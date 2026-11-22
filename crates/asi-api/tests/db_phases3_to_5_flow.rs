#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::IpAddr;

use asi_api::app::{build_router, AppState};
use asi_api::bootstrap::bootstrap_initial_admin;
use asi_api::config::ApiConfig;
use asi_api::run_migrations;
use asi_common::assets::{
    AssetGroupDto, AuditLogDto, CreateWorkerTokenResponse, IgnoredTargetDto, ScanPolicyDto,
};
use asi_common::auth::LoginResponse;
use asi_common::diff::{DiffEventKind, DiffSeverity};
use asi_common::inventory::{
    DashboardStatsDto, DiffEventDto, HostDetailDto, HostSummaryDto, ServiceClusterDto,
};
use asi_common::io::{ExportDiffsEnvelope, ExportHostsEnvelope, ExportServicesEnvelope};
use asi_common::notification::{NotificationChannelDto, NotificationDeliveryDto};
use asi_common::pagination::PaginatedResponse;
use asi_common::scans::{PreflightResponse, ScanRunDto, ScanRunStatus};
use asi_common::signatures::SyncSignaturesResponse;
use asi_common::worker::{
    ChunkLeaseResponse, ChunkResultsResponse, ControlDirective, HeartbeatResponse,
    Stage1PortFinding, Stage2ServiceFinding, Stage3WebObservation, WorkerCapabilities,
    WorkerRegisterResponse, WorkerSignaturesResponse,
};
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

async fn api_json_request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    bearer: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    let body_stream = if let Some(json_val) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(json_val.to_string())
    } else {
        Body::empty()
    };

    let resp = app
        .clone()
        .oneshot(builder.body(body_stream).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

#[tokio::test]
#[ignore = "Requires live PostgreSQL instance (DATABASE_URL)"]
async fn live_db_phases3_to_5_scan_diff_instability_clusters_audit_and_kill_switch() {
    dotenvy::dotenv().ok();
    let mut config = ApiConfig::from_env().unwrap();
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://asi:asi_dev_password_change_me@127.0.0.1:5432/asi".to_string()
    });
    config.bootstrap_admin_password = Some("ChangeMeNow_Admin123!".to_string());
    config.cookie_secure = false;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .unwrap();

    run_migrations(&pool).await.unwrap();
    bootstrap_initial_admin(&pool, &config).await.unwrap();

    let state = AppState::from_config(Some(pool.clone()), &config).unwrap();
    let app = build_router(state, "http://localhost:5173");

    // 1. Login as Admin
    let login_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": config.bootstrap_admin_username,
                        "password": "ChangeMeNow_Admin123!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_resp.status(), StatusCode::OK);
    let login_bytes = login_resp.into_body().collect().await.unwrap().to_bytes();
    let token = serde_json::from_slice::<LoginResponse>(&login_bytes)
        .unwrap()
        .access_token;

    // 2. Create Policy (zero cooldown for instant sequential scans, tarpit threshold = 5)
    let policy_name = format!("e2e-policy-{}", Uuid::new_v4());
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/policies",
        &token,
        Some(serde_json::json!({
            "name": policy_name,
            "port_spec": "80,443",
            "discovery_tool": "naabu",
            "rate_pps": 500,
            "per_ip_cooldown_ms": 0,
            "subnet_concurrency": 4,
            "kill_grace_seconds": 1,
            "inactivity_threshold": 3,
            "tarpit_port_threshold": 5,
            "enable_nuclei": false
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let policy: ScanPolicyDto = serde_json::from_slice(&bytes).unwrap();

    // 3. Create Asset Group and add CIDR + exclusion targets
    let group_name = format!("e2e-mock-lab-{}", Uuid::new_v4());
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/asset-groups",
        &token,
        Some(serde_json::json!({
            "name": group_name,
            "description": "Phases 3-5 E2E verification",
            "policy_id": policy.id,
            "sampling_enabled": false
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let group: AssetGroupDto = serde_json::from_slice(&bytes).unwrap();

    let (st, _) = api_json_request(
        &app,
        Method::POST,
        &format!("/api/v1/asset-groups/{}/targets", group.id),
        &token,
        Some(serde_json::json!({
            "targets": [
                { "target_type": "cidr", "value": "172.28.0.8/29", "notes": "Range .8-.15" },
                { "target_type": "exclude_cidr", "value": "172.28.0.12/32", "notes": "Excluded host" }
            ]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // 4. Create Worker Token & Register Worker
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/workers/tokens",
        &token,
        Some(serde_json::json!({
            "name": format!("e2e-worker-{}", Uuid::new_v4()),
            "segment_tag": "mock-lab",
            "max_concurrency": 2
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let worker_cred: CreateWorkerTokenResponse = serde_json::from_slice(&bytes).unwrap();
    let worker_id = worker_cred.worker.id;
    let worker_token = worker_cred.token;

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/internal/v1/worker/register",
        &worker_token,
        Some(serde_json::json!({
            "name": worker_cred.worker.name,
            "segment_tag": "mock-lab",
            "max_concurrency": 2,
            "capabilities": WorkerCapabilities {
                naabu_version: None,
                masscan_version: None,
                nmap_version: None,
                nuclei_version: None,
                os_arch: "linux-x86_64".to_string()
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let reg: WorkerRegisterResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reg.worker_id, worker_id);

    // 5. Sync Built-in Signatures & Fetch via Worker Protocol
    let (st, bytes) =
        api_json_request(&app, Method::POST, "/api/v1/signatures/sync", &token, None).await;
    assert_eq!(st, StatusCode::OK);
    let sync_res: SyncSignaturesResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(sync_res.synced_count >= 1);

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        "/internal/v1/worker/signatures",
        &worker_token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let worker_sigs: WorkerSignaturesResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(!worker_sigs.yaml_rules.is_empty());
    assert!(!worker_sigs.version_hash.is_empty());

    // 6. Create Group-Scoped Notification Channel (encrypted secret)
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/notifications/channels",
        &token,
        Some(serde_json::json!({
            "name": format!("e2e-webhook-{}", Uuid::new_v4()),
            "channel_type": "webhook_json",
            "asset_group_id": group.id,
            "notify_on_confirmed": true,
            "notify_on_variance": true,
            "config_public": { "url": "http://127.0.0.1:1/hook" },
            "secret": "e2e-hmac-secret-key"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let channel: NotificationChannelDto = serde_json::from_slice(&bytes).unwrap();
    assert!(channel.has_secret);

    // 7. Preflight + Scan #1 (Baseline) + Late Ignored Target Filtering at Lease Time
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/scans/preflight",
        &token,
        Some(serde_json::json!({
            "asset_group_id": group.id,
            "window_minutes": 30
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let preflight: PreflightResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(preflight.total_targets, 7);

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/scans",
        &token,
        Some(serde_json::json!({
            "asset_group_id": group.id,
            "trigger_type": "manual",
            "time_slot": "06_12"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let scan1: ScanRunDto = serde_json::from_slice(&bytes).unwrap();

    // Add 172.28.0.13 to ignored_targets AFTER scan1 was queued to test lease-time defense-in-depth
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/ignored-targets",
        &token,
        Some(serde_json::json!({
            "asset_group_id": group.id,
            "target_type": "ip",
            "value": "172.28.0.13",
            "reason": "Added after scan enqueue to verify lease re-filtering"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let ignored_target: IgnoredTargetDto = serde_json::from_slice(&bytes).unwrap();

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/internal/v1/worker/chunks/lease",
        &worker_token,
        Some(serde_json::json!({ "worker_id": worker_id, "max_chunks": 1 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let lease1: ChunkLeaseResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(lease1.scan_run_id, scan1.id);
    assert!(!lease1
        .targets
        .iter()
        .any(|t| t.ip_addr == "172.28.0.12".parse::<IpAddr>().unwrap()
            || t.ip_addr == "172.28.0.13".parse::<IpAddr>().unwrap()));

    // Concurrent lease must return 204 (ip_locks + SKIP LOCKED)
    let (st_dup, _) = api_json_request(
        &app,
        Method::POST,
        "/internal/v1/worker/chunks/lease",
        &worker_token,
        Some(serde_json::json!({ "worker_id": worker_id, "max_chunks": 1 })),
    )
    .await;
    assert_eq!(st_dup, StatusCode::NO_CONTENT);

    // Heartbeat returns Continue
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        &format!("/internal/v1/worker/chunks/{}/heartbeat", lease1.chunk_id),
        &worker_token,
        Some(serde_json::json!({
            "worker_id": worker_id,
            "attempt_no": lease1.attempt_no,
            "stage_label": "stage2"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let hb1: HeartbeatResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(hb1.directive, ControlDirective::Continue);

    let ip_10: IpAddr = "172.28.0.10".parse().unwrap();
    let ip_11: IpAddr = "172.28.0.11".parse().unwrap();
    let ip_14: IpAddr = "172.28.0.14".parse().unwrap();
    let ip_15: IpAddr = "172.28.0.15".parse().unwrap();

    let mut stage1_scan1 = vec![
        Stage1PortFinding {
            ip_addr: ip_10,
            port: 80,
            protocol: "tcp".to_string(),
        },
        Stage1PortFinding {
            ip_addr: ip_11,
            port: 80,
            protocol: "tcp".to_string(),
        },
        Stage1PortFinding {
            ip_addr: ip_14,
            port: 80,
            protocol: "tcp".to_string(),
        },
    ];
    for p in 80..=85_u16 {
        stage1_scan1.push(Stage1PortFinding {
            ip_addr: ip_15,
            port: p,
            protocol: "tcp".to_string(),
        });
    }

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        &format!("/internal/v1/worker/chunks/{}/results", lease1.chunk_id),
        &worker_token,
        Some(serde_json::json!({
            "worker_id": worker_id,
            "attempt_no": lease1.attempt_no,
            "duration_ms": 420,
            "probable_tarpit_ips": [ip_15],
            "stage1_ports": stage1_scan1,
            "stage2_services": [
                Stage2ServiceFinding {
                    ip_addr: ip_10,
                    port: 80,
                    protocol: "tcp".to_string(),
                    service_name: Some("http".to_string()),
                    product: Some("nginx".to_string()),
                    version: Some("1.27".to_string()),
                    extra_info: None,
                    tunnel: None,
                    is_web_candidate: true,
                    rdns_hostnames: Vec::new(),
                    tls_sha256: None,
                    tls_subject_cn: None,
                    tls_issuer_cn: None,
                    tls_san_dns: Vec::new(),
                    tls_not_before: None,
                    tls_not_after: None,
                    tls_is_self_signed: None,
                },
                Stage2ServiceFinding {
                    ip_addr: ip_11,
                    port: 80,
                    protocol: "tcp".to_string(),
                    service_name: Some("http".to_string()),
                    product: Some("nginx".to_string()),
                    version: Some("1.27".to_string()),
                    extra_info: None,
                    tunnel: None,
                    is_web_candidate: true,
                    rdns_hostnames: Vec::new(),
                    tls_sha256: None,
                    tls_subject_cn: None,
                    tls_issuer_cn: None,
                    tls_san_dns: Vec::new(),
                    tls_not_before: None,
                    tls_not_after: None,
                    tls_is_self_signed: None,
                }
            ],
            "stage3_observations": [
                Stage3WebObservation {
                    ip_addr: ip_10,
                    port: 80,
                    vhost: "172.28.0.10".to_string(),
                    scheme: "http".to_string(),
                    http_status: Some(200),
                    final_url: Some("http://172.28.0.10/".to_string()),
                    redirect_target: None,
                    title: Some("AGH Faculty Portal".to_string()),
                    headers_filtered: HashMap::from([("server".to_string(), "nginx/1.27".to_string())]),
                    cookies_meta: Vec::new(),
                    favicon_mmh3: Some(424242),
                    matched_technologies: vec!["Nginx".to_string()],
                    detected_paths: Vec::new(),
                },
                Stage3WebObservation {
                    ip_addr: ip_11,
                    port: 80,
                    vhost: "172.28.0.11".to_string(),
                    scheme: "http".to_string(),
                    http_status: Some(200),
                    final_url: Some("http://172.28.0.11/".to_string()),
                    redirect_target: None,
                    title: Some("AGH Portal Clone".to_string()),
                    headers_filtered: HashMap::from([("server".to_string(), "nginx/1.27".to_string())]),
                    cookies_meta: Vec::new(),
                    favicon_mmh3: Some(424242),
                    matched_technologies: vec!["Nginx".to_string()],
                    detected_paths: Vec::new(),
                }
            ]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let res1: ChunkResultsResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(res1.accepted);
    assert!(res1.scan_completed);

    // 8. Verify Hosts Inventory, Set Analytical Metadata & Tarpit Override
    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!("/api/v1/hosts?asset_group_id={}", group.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let hosts_page: PaginatedResponse<HostSummaryDto> = serde_json::from_slice(&bytes).unwrap();
    let host_10 = hosts_page
        .items
        .iter()
        .find(|h| h.ip_addr == ip_10)
        .unwrap();
    let host_14 = hosts_page
        .items
        .iter()
        .find(|h| h.ip_addr == ip_14)
        .unwrap();
    let host_15 = hosts_page
        .items
        .iter()
        .find(|h| h.ip_addr == ip_15)
        .unwrap();
    assert!(host_15.is_probable_tarpit);

    let (st, _) = api_json_request(
        &app,
        Method::PATCH,
        &format!("/api/v1/hosts/{}", host_10.id),
        &token,
        Some(serde_json::json!({
            "manual_tags": ["critical", "prod"],
            "notes": "Preserved across rescans",
            "owner_hint": "AGH SOC"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = api_json_request(
        &app,
        Method::POST,
        &format!("/api/v1/hosts/{}/tarpit-override", host_15.id),
        &token,
        Some(serde_json::json!({
            "force_sv": true,
            "reason": "Inspect tarpit service fingerprints"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // 9. Scan #2 (12_18): /admin appears on .10, .14 drops offline (miss #1), force_sv_ips populated
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/scans",
        &token,
        Some(serde_json::json!({
            "asset_group_id": group.id,
            "trigger_type": "manual",
            "time_slot": "12_18"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let scan2: ScanRunDto = serde_json::from_slice(&bytes).unwrap();

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/internal/v1/worker/chunks/lease",
        &worker_token,
        Some(serde_json::json!({ "worker_id": worker_id, "max_chunks": 1 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let lease2: ChunkLeaseResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(lease2.scan_run_id, scan2.id);
    assert!(lease2.policy.force_sv_ips.contains(&ip_15));

    let (st, _) = api_json_request(
        &app,
        Method::POST,
        &format!("/internal/v1/worker/chunks/{}/results", lease2.chunk_id),
        &worker_token,
        Some(serde_json::json!({
            "worker_id": worker_id,
            "attempt_no": lease2.attempt_no,
            "duration_ms": 380,
            "probable_tarpit_ips": [],
            "stage1_ports": [
                Stage1PortFinding { ip_addr: ip_10, port: 80, protocol: "tcp".to_string() },
                Stage1PortFinding { ip_addr: ip_11, port: 80, protocol: "tcp".to_string() },
                Stage1PortFinding { ip_addr: ip_15, port: 80, protocol: "tcp".to_string() }
            ],
            "stage2_services": [],
            "stage3_observations": [
                Stage3WebObservation {
                    ip_addr: ip_10,
                    port: 80,
                    vhost: "172.28.0.10".to_string(),
                    scheme: "http".to_string(),
                    http_status: Some(200),
                    final_url: Some("http://172.28.0.10/".to_string()),
                    redirect_target: None,
                    title: Some("AGH Faculty Portal".to_string()),
                    headers_filtered: HashMap::from([("server".to_string(), "nginx/1.27".to_string())]),
                    cookies_meta: Vec::new(),
                    favicon_mmh3: Some(424242),
                    matched_technologies: vec!["Nginx".to_string(), "Admin Panel".to_string()],
                    detected_paths: vec!["/admin".to_string()],
                },
                Stage3WebObservation {
                    ip_addr: ip_11,
                    port: 80,
                    vhost: "172.28.0.11".to_string(),
                    scheme: "http".to_string(),
                    http_status: Some(200),
                    final_url: Some("http://172.28.0.11/".to_string()),
                    redirect_target: None,
                    title: Some("AGH Portal Clone".to_string()),
                    headers_filtered: HashMap::from([("server".to_string(), "nginx/1.27".to_string())]),
                    cookies_meta: Vec::new(),
                    favicon_mmh3: Some(424242),
                    matched_technologies: vec!["Nginx".to_string()],
                    detected_paths: Vec::new(),
                }
            ]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Assert Scan-First Truth preserved manual analytical fields on .10
    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{}", host_10.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let detail_10: HostDetailDto = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(detail_10.host.manual_tags, vec!["critical", "prod"]);
    assert_eq!(
        detail_10.host.notes.as_deref(),
        Some("Preserved across rescans")
    );
    assert_eq!(detail_10.host.owner_hint.as_deref(), Some("AGH SOC"));

    // Assert High ConfirmedChange diff, scan_engine audit_log, queued notification, and acknowledge
    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!(
            "/api/v1/diffs?asset_group_id={}&host_id={}&event_kind=confirmed_change",
            group.id, host_10.id
        ),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let diffs_page: PaginatedResponse<DiffEventDto> = serde_json::from_slice(&bytes).unwrap();
    let admin_diff = diffs_page
        .items
        .iter()
        .find(|d| {
            d.severity == DiffSeverity::High
                && d.bullet_items
                    .iter()
                    .any(|b| b.key == "admin_panel_detected")
        })
        .unwrap();

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!("/api/v1/audit-logs?resource_type=host&actor_id={worker_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let audit_page: PaginatedResponse<AuditLogDto> = serde_json::from_slice(&bytes).unwrap();
    assert!(audit_page.items.iter().any(|a| {
        a.actor_type == "scan_engine"
            && a.action == "host.diff_detected"
            && a.resource_id == Some(host_10.id)
    }));

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        "/api/v1/notifications/deliveries",
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let deliveries_page: PaginatedResponse<NotificationDeliveryDto> =
        serde_json::from_slice(&bytes).unwrap();
    assert!(deliveries_page
        .items
        .iter()
        .any(|d| d.channel_id == channel.id && d.diff_event_id == admin_diff.id));

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        &format!("/api/v1/diffs/{}/acknowledge", admin_diff.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let acked: DiffEventDto = serde_json::from_slice(&bytes).unwrap();
    assert!(acked.acknowledged_at.is_some());

    // 10. Scan #3 (18_24): .14 returns online (up -> down -> up = 2 transitions -> is_unstable + active_variance)
    let (st, _) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/scans",
        &token,
        Some(serde_json::json!({
            "asset_group_id": group.id,
            "trigger_type": "sampling",
            "time_slot": "18_24"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/internal/v1/worker/chunks/lease",
        &worker_token,
        Some(serde_json::json!({ "worker_id": worker_id, "max_chunks": 1 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let lease3: ChunkLeaseResponse = serde_json::from_slice(&bytes).unwrap();

    let (st, _) = api_json_request(
        &app,
        Method::POST,
        &format!("/internal/v1/worker/chunks/{}/results", lease3.chunk_id),
        &worker_token,
        Some(serde_json::json!({
            "worker_id": worker_id,
            "attempt_no": lease3.attempt_no,
            "duration_ms": 350,
            "probable_tarpit_ips": [],
            "stage1_ports": [
                Stage1PortFinding { ip_addr: ip_10, port: 80, protocol: "tcp".to_string() },
                Stage1PortFinding { ip_addr: ip_11, port: 80, protocol: "tcp".to_string() },
                Stage1PortFinding { ip_addr: ip_14, port: 80, protocol: "tcp".to_string() }
            ],
            "stage2_services": [],
            "stage3_observations": []
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{}", host_14.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let detail_14: HostDetailDto = serde_json::from_slice(&bytes).unwrap();
    assert!(detail_14.host.is_unstable);

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!(
            "/api/v1/diffs?asset_group_id={}&host_id={}&event_kind=active_variance",
            group.id, host_14.id
        ),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let variance_page: PaginatedResponse<DiffEventDto> = serde_json::from_slice(&bytes).unwrap();
    assert!(!variance_page.items.is_empty());
    assert_eq!(
        variance_page.items[0].event_kind,
        DiffEventKind::ActiveVariance
    );

    // 11. Shadow IT Clusters, Dashboard Summary, and JSON Exports
    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!(
            "/api/v1/clusters?asset_group_id={}&kind=favicon&min_members=2",
            group.id
        ),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let clusters: Vec<ServiceClusterDto> = serde_json::from_slice(&bytes).unwrap();
    assert!(clusters
        .iter()
        .any(|c| c.cluster_key == "favicon:424242" && c.member_count >= 2));

    let (st, bytes) =
        api_json_request(&app, Method::GET, "/api/v1/dashboard/summary", &token, None).await;
    assert_eq!(st, StatusCode::OK);
    let summary: DashboardStatsDto = serde_json::from_slice(&bytes).unwrap();
    assert!(summary.total_hosts >= 4);
    assert!(summary.confirmed_changes_24h >= 1);

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!("/api/v1/export/hosts?asset_group_id={}", group.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let exp_hosts: ExportHostsEnvelope = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(exp_hosts.schema_version, "1.0");
    assert!(!exp_hosts.items.is_empty());

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!("/api/v1/export/diffs?asset_group_id={}", group.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let exp_diffs: ExportDiffsEnvelope = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(exp_diffs.schema_version, "1.0");
    assert!(!exp_diffs.items.is_empty());

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!("/api/v1/export/services?asset_group_id={}", group.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let exp_svcs: ExportServicesEnvelope = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(exp_svcs.schema_version, "1.0");
    assert!(!exp_svcs.items.is_empty());

    // 12. Scan #4: Hard Kill Switch -> heartbeat KillNow -> release -> Stopped
    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/api/v1/scans",
        &token,
        Some(serde_json::json!({
            "asset_group_id": group.id,
            "trigger_type": "manual",
            "time_slot": "00_06"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let scan4: ScanRunDto = serde_json::from_slice(&bytes).unwrap();

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        "/internal/v1/worker/chunks/lease",
        &worker_token,
        Some(serde_json::json!({ "worker_id": worker_id, "max_chunks": 1 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let lease4: ChunkLeaseResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(lease4.scan_run_id, scan4.id);

    let (st, _) = api_json_request(
        &app,
        Method::POST,
        &format!("/api/v1/scans/{}/stop", scan4.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, bytes) = api_json_request(
        &app,
        Method::POST,
        &format!("/internal/v1/worker/chunks/{}/heartbeat", lease4.chunk_id),
        &worker_token,
        Some(serde_json::json!({
            "worker_id": worker_id,
            "attempt_no": lease4.attempt_no,
            "stage_label": "stage1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let hb4: HeartbeatResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(hb4.directive, ControlDirective::KillNow);

    let (st, _) = api_json_request(
        &app,
        Method::POST,
        &format!("/internal/v1/worker/chunks/{}/release", lease4.chunk_id),
        &worker_token,
        Some(serde_json::json!({
            "worker_id": worker_id,
            "attempt_no": lease4.attempt_no,
            "reason": "killed_in_e2e_test"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, bytes) = api_json_request(
        &app,
        Method::GET,
        &format!("/api/v1/scans/{}", scan4.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let stopped_scan: ScanRunDto = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stopped_scan.status, ScanRunStatus::Stopped);

    // 13. Clean teardown
    let (st, _) = api_json_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/notifications/channels/{}", channel.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, _) = api_json_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/ignored-targets/{}", ignored_target.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, _) = api_json_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/asset-groups/{}", group.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let (st, _) = api_json_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/policies/{}", policy.id),
        &token,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);

    let _ = sqlx::query("DELETE FROM worker_nodes WHERE id = $1")
        .bind(worker_id)
        .execute(&pool)
        .await;
}
