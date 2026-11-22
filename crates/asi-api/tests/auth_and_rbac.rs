#![allow(clippy::unwrap_used, clippy::expect_used)]

use asi_api::app::{build_router, AppState};
use asi_common::auth::AuthUser;
use asi_common::error::ProblemDetails;
use asi_common::rbac::Role;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

fn issue_token_for(state: &AppState, role: Role) -> String {
    let user = AuthUser {
        id: Uuid::new_v4(),
        username: format!("{:?}", role).to_ascii_lowercase(),
        email: "user@agh.local".to_string(),
        role,
        preferred_locale: "pl".to_string(),
        permissions: role.permissions().to_vec(),
    };
    state.jwt.issue_access_token(&user).unwrap()
}

async fn send(
    app: axum::Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    json_body: Option<serde_json::Value>,
) -> (StatusCode, ProblemDetails) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    let body = match json_body {
        Some(val) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(val.to_string())
        }
        None => Body::empty(),
    };

    let response = app.oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let problem: ProblemDetails = serde_json::from_slice(&bytes).unwrap();
    (status, problem)
}

#[tokio::test]
async fn protected_routes_reject_unauthenticated_requests_with_401() {
    let state = AppState::default();
    let app = build_router(state, "http://localhost:5173");

    for (method, path) in [
        (Method::GET, "/api/v1/auth/me"),
        (Method::GET, "/api/v1/users"),
        (Method::GET, "/api/v1/asset-groups"),
        (Method::GET, "/api/v1/policies"),
        (Method::GET, "/api/v1/ignored-targets"),
        (Method::GET, "/api/v1/workers"),
        (Method::GET, "/api/v1/export/targets"),
    ] {
        let (status, problem) = send(app.clone(), method, path, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "failed for {path}");
        assert_eq!(problem.error_code, "UNAUTHORIZED");
    }
}

#[tokio::test]
async fn rbac_enforces_403_before_database_access_for_forbidden_roles() {
    let state = AppState::default();
    let app = build_router(state.clone(), "http://localhost:5173");

    let readonly = issue_token_for(&state, Role::ReadOnly);
    let readwrite = issue_token_for(&state, Role::ReadWrite);
    let rwd = issue_token_for(&state, Role::ReadWriteDelete);

    // ReadOnly cannot create asset groups, policies, or ignore targets
    let (status, problem) = send(
        app.clone(),
        Method::POST,
        "/api/v1/asset-groups",
        Some(&readonly),
        Some(serde_json::json!({
            "name": "grp",
            "policy_id": Uuid::new_v4()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem.error_code, "FORBIDDEN");

    // ReadWrite cannot manage asset groups, ignored targets, or import JSON
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/ignored-targets",
        Some(&readwrite),
        Some(serde_json::json!({
            "target_type": "ip",
            "value": "10.0.0.1",
            "reason": "test"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/import/targets",
        Some(&readwrite),
        Some(serde_json::json!({
            "schema_version": "1.0",
            "asset_group_id": Uuid::new_v4(),
            "items": []
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ReadWriteDelete cannot manage users, audit logs, or worker tokens
    let (status, _) = send(app.clone(), Method::GET, "/api/v1/users", Some(&rwd), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(
        app.clone(),
        Method::GET,
        "/api/v1/audit-logs",
        Some(&rwd),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(
        app,
        Method::POST,
        "/api/v1/workers/tokens",
        Some(&rwd),
        Some(serde_json::json!({ "name": "worker-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn allowed_roles_pass_rbac_and_reach_db_readiness_check() {
    let state = AppState::default();
    let app = build_router(state.clone(), "http://localhost:5173");

    let readonly = issue_token_for(&state, Role::ReadOnly);
    let rwd = issue_token_for(&state, Role::ReadWriteDelete);
    let admin = issue_token_for(&state, Role::Admin);

    // ReadOnly can reach export endpoints (returns 503 because test has no DB pool, NOT 403)
    let (status, _) = send(
        app.clone(),
        Method::GET,
        "/api/v1/export/targets",
        Some(&readonly),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // ReadWriteDelete can reach asset-group creation
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/asset-groups",
        Some(&rwd),
        Some(serde_json::json!({
            "name": "lab-group",
            "policy_id": Uuid::new_v4()
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Admin can reach users and worker tokens
    let (status, _) = send(app, Method::GET, "/api/v1/users", Some(&admin), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn openapi_exposes_phase2_paths_and_no_csv_endpoints() {
    let app = build_router(AppState::default(), "http://localhost:5173");
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let raw = String::from_utf8(body.to_vec()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();

    for expected in [
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/users",
        "/api/v1/audit-logs",
        "/api/v1/policies",
        "/api/v1/asset-groups",
        "/api/v1/ignored-targets",
        "/api/v1/workers/tokens",
        "/api/v1/import/targets",
        "/api/v1/export/targets",
        "/api/v1/export/policies",
        "/api/v1/export/ignored-targets",
    ] {
        assert!(
            doc["paths"][expected].is_object(),
            "missing OpenAPI path {expected}"
        );
    }

    for scan_path in [
        "/api/v1/scans/preflight",
        "/api/v1/scans",
        "/api/v1/scans/{id}",
        "/api/v1/scans/{id}/chunks",
        "/api/v1/scans/{id}/pause",
        "/api/v1/scans/{id}/resume",
        "/api/v1/scans/{id}/stop",
    ] {
        assert!(
            doc["paths"][scan_path].is_object(),
            "missing OpenAPI Phase 3 path {scan_path}"
        );
    }

    for phase4_path in [
        "/api/v1/hosts",
        "/api/v1/hosts/{id}",
        "/api/v1/hosts/{id}/tarpit-override",
        "/api/v1/diffs",
        "/api/v1/diffs/{id}",
        "/api/v1/diffs/{id}/acknowledge",
        "/api/v1/export/hosts",
        "/api/v1/export/diffs",
    ] {
        assert!(
            doc["paths"][phase4_path].is_object(),
            "missing OpenAPI Phase 4 path {phase4_path}"
        );
    }

    for phase5_path in [
        "/api/v1/dashboard/summary",
        "/api/v1/services",
        "/api/v1/clusters",
        "/api/v1/export/services",
        "/api/v1/signatures",
        "/api/v1/signatures/{id}",
        "/api/v1/signatures/validate",
        "/api/v1/signatures/sync",
        "/api/v1/import/signatures",
        "/api/v1/notifications/channels",
        "/api/v1/notifications/channels/{id}",
        "/api/v1/notifications/channels/{id}/test",
        "/api/v1/notifications/deliveries",
    ] {
        assert!(
            doc["paths"][phase5_path].is_object(),
            "missing OpenAPI Phase 5 path {phase5_path}"
        );
    }

    for expected in [
        "/api/v1/scans/quick",
        "/api/v1/notifications/channels/{id}/trigger",
        "/api/v1/import/targets-flexible",
        "/api/v1/import/scan-results",
        "/api/v1/export/targets.csv",
        "/api/v1/export/hosts.csv",
        "/api/v1/export/services.csv",
        "/api/v1/export/diffs.csv",
        "/api/v1/integrations/defectdojo/preview/diff/{diff_event_id}",
        "/api/v1/integrations/defectdojo/override/diff/{diff_event_id}",
        "/api/v1/integrations/defectdojo/preview/host/{host_id}",
        "/api/v1/integrations/defectdojo/override/host/{host_id}",
        "/api/v1/integrations/defectdojo/push-host/{host_id}",
        "/api/v1/integrations/defectdojo/host-link/{host_id}",
    ] {
        assert!(
            raw.contains(expected),
            "OpenAPI spec should expose path {expected}"
        );
    }
    assert!(raw.to_ascii_lowercase().contains("text/csv"));
}

#[tokio::test]
async fn phase5_signatures_and_notifications_rbac_isolation() {
    let state = AppState::default();
    let app = build_router(state.clone(), "http://localhost:5173");

    let readonly = issue_token_for(&state, Role::ReadOnly);
    let readwrite = issue_token_for(&state, Role::ReadWrite);
    let rwd = issue_token_for(&state, Role::ReadWriteDelete);
    let admin = issue_token_for(&state, Role::Admin);

    let sample_yaml = "id: custom-test\ninfo:\n  name: Custom\nhttp:\n  - method: GET\n    matchers:\n      - type: status\n        status: [200]\n";

    // ReadOnly can query dashboard summary -> reaches DB 503
    let (status, _) = send(
        app.clone(),
        Method::GET,
        "/api/v1/dashboard/summary",
        Some(&readonly),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // ReadWrite cannot manage custom signatures -> 403
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/signatures",
        Some(&readwrite),
        Some(serde_json::json!({ "yaml_content": sample_yaml })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ReadWriteDelete can create custom signatures (reaches DB 503), but cannot sync built-ins (Admin-only)
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/signatures",
        Some(&rwd),
        Some(serde_json::json!({ "yaml_content": sample_yaml })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/signatures/sync",
        Some(&rwd),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ReadWriteDelete cannot create notification channels (Admin-only)
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/notifications/channels",
        Some(&rwd),
        Some(serde_json::json!({
            "name": "soc-webhook",
            "channel_type": "webhook_json",
            "config_public": { "url": "https://soc.agh.local/hook" }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin passes RBAC on signatures/sync and notifications/channels
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/signatures/sync",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, _) = send(
        app,
        Method::POST,
        "/api/v1/notifications/channels",
        Some(&admin),
        Some(serde_json::json!({
            "name": "soc-webhook",
            "channel_type": "webhook_json",
            "config_public": { "url": "https://soc.agh.local/hook" }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn phase3_scan_rbac_and_worker_internal_auth() {
    let state = AppState::default();
    let app = build_router(state.clone(), "http://localhost:5173");

    let readonly = issue_token_for(&state, Role::ReadOnly);
    let readwrite = issue_token_for(&state, Role::ReadWrite);

    // ReadOnly cannot start or stop scans (403 Forbidden)
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/scans",
        Some(&readonly),
        Some(serde_json::json!({ "asset_group_id": Uuid::new_v4() })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(
        app.clone(),
        Method::POST,
        &format!("/api/v1/scans/{}/stop", Uuid::new_v4()),
        Some(&readonly),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ReadWrite passes RBAC on POST /api/v1/scans (reaches 503 DB check in unit harness)
    let (status, _) = send(
        app.clone(),
        Method::POST,
        "/api/v1/scans",
        Some(&readwrite),
        Some(serde_json::json!({ "asset_group_id": Uuid::new_v4() })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Internal worker endpoint rejects missing worker bearer token with 401
    let (status, problem) = send(
        app,
        Method::POST,
        "/internal/v1/worker/chunks/lease",
        None,
        Some(serde_json::json!({ "worker_id": Uuid::new_v4(), "max_chunks": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(problem.error_code, "UNAUTHORIZED");
}

#[tokio::test]
async fn phase4_hosts_and_diffs_rbac_isolation() {
    let state = AppState::default();
    let app = build_router(state.clone(), "http://localhost:5173");

    for path in ["/api/v1/hosts", "/api/v1/diffs", "/api/v1/events/stream"] {
        let (status, problem) = send(app.clone(), Method::GET, path, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "failed for {path}");
        assert_eq!(problem.error_code, "UNAUTHORIZED");
    }

    let readonly = issue_token_for(&state, Role::ReadOnly);
    let readwrite = issue_token_for(&state, Role::ReadWrite);
    let rwd = issue_token_for(&state, Role::ReadWriteDelete);
    let admin = issue_token_for(&state, Role::Admin);
    let host_id = Uuid::new_v4();
    let diff_id = Uuid::new_v4();

    // ReadOnly cannot edit host analytical metadata, acknowledge diffs, or override tarpit
    let (status, _) = send(
        app.clone(),
        Method::PATCH,
        &format!("/api/v1/hosts/{host_id}"),
        Some(&readonly),
        Some(serde_json::json!({ "owner_hint": "csirt" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(
        app.clone(),
        Method::POST,
        &format!("/api/v1/diffs/{diff_id}/acknowledge"),
        Some(&readonly),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(
        app.clone(),
        Method::POST,
        &format!("/api/v1/hosts/{host_id}/tarpit-override"),
        Some(&readonly),
        Some(serde_json::json!({ "force_sv": true })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ReadWrite can edit host metadata & acknowledge diffs, but cannot override tarpit
    let (status, _) = send(
        app.clone(),
        Method::PATCH,
        &format!("/api/v1/hosts/{host_id}"),
        Some(&readwrite),
        Some(serde_json::json!({ "owner_hint": "netops" })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, _) = send(
        app.clone(),
        Method::POST,
        &format!("/api/v1/diffs/{diff_id}/acknowledge"),
        Some(&readwrite),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, _) = send(
        app.clone(),
        Method::POST,
        &format!("/api/v1/hosts/{host_id}/tarpit-override"),
        Some(&readwrite),
        Some(serde_json::json!({ "force_sv": true })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ReadWriteDelete also cannot override tarpit (Admin-only)
    let (status, _) = send(
        app.clone(),
        Method::POST,
        &format!("/api/v1/hosts/{host_id}/tarpit-override"),
        Some(&rwd),
        Some(serde_json::json!({ "force_sv": true })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin passes RBAC for tarpit override
    let (status, _) = send(
        app,
        Method::POST,
        &format!("/api/v1/hosts/{host_id}/tarpit-override"),
        Some(&admin),
        Some(serde_json::json!({ "force_sv": true })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}
