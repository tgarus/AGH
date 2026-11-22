use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::Infallible;
use std::net::IpAddr;
use std::time::Duration;

use asi_common::diff::{filter_noise_headers, TimeSlot};
use asi_common::error::DomainError;
use asi_common::events::HostAnomalyType;
use asi_common::inventory::{HostStatus, PortState};
use asi_common::signatures::builtin_default_signatures_yaml;
use asi_common::worker::{
    ChunkLeaseRequest, ChunkLeaseResponse, ChunkReleaseRequest, ChunkResultsResponse,
    ChunkResultsSubmission, ChunkTarget, ControlDirective, DiscoveryTool, HeartbeatRequest,
    HeartbeatResponse, PolicySnapshot, Stage1PortFinding, Stage2ServiceFinding,
    Stage3WebObservation, WebCookieMeta, WorkerRegisterRequest, WorkerRegisterResponse,
    WorkerSignaturesResponse,
};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Timelike, Utc};
use futures_util::stream::Stream;
use ipnetwork::IpNetwork;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgConnection};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::diff_engine::evaluator::{
    evaluate_host_diff, CurrentHostObservation, CurrentPortObservation, DiffEventDraft,
    PreviousHostState, PreviousPortState, TlsSnapshot, WebSnapshot,
};
use crate::diff_engine::instability::{
    assess_instability, compute_open_ports_hash, AvailabilitySample,
};
use crate::error::AppError;
use crate::orchestrator::slicer::{estimate_eta_seconds, update_ema_ms};
use crate::routes::common::{map_db_err, require_db};
use crate::security::worker_extractor::AuthenticatedWorker;

const LEASE_TTL_SECONDS: i64 = 60;
const HEARTBEAT_INTERVAL_SECONDS: u64 = 15;

#[derive(FromRow)]
struct CandidateChunkRow {
    id: Uuid,
    scan_run_id: Uuid,
    asset_group_id: Uuid,
    subnet_bucket: String,
    targets: serde_json::Value,
    policy_snapshot: serde_json::Value,
    include_all_ignored: bool,
    overridden_ignored_values: Vec<String>,
}

#[derive(FromRow)]
struct IgnoredTargetRow {
    target_type: String,
    value: String,
}

#[derive(FromRow)]
struct LockedChunkRow {
    scan_run_id: Uuid,
    targets: serde_json::Value,
    status: String,
    attempt_no: i32,
    leased_by_worker_id: Option<Uuid>,
}

#[derive(FromRow)]
struct ScanRunMetaRow {
    asset_group_id: Uuid,
    status: String,
    total_chunks: i32,
    completed_chunks: i32,
    ema_chunk_ms: Option<f64>,
    policy_snapshot: serde_json::Value,
    time_slot: Option<String>,
}

#[derive(FromRow)]
struct PrevHostRow {
    id: Uuid,
    status: String,
    consecutive_misses: i32,
    is_unstable: bool,
    is_probable_tarpit: bool,
    last_seen_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct PrevPortRow {
    id: Uuid,
    port: i32,
    protocol: String,
    state: String,
    consecutive_misses: i32,
    service_name: Option<String>,
    product: Option<String>,
    version: Option<String>,
    tunnel: Option<String>,
}

#[derive(FromRow)]
struct PrevTlsRow {
    host_port_id: Uuid,
    sha256_fingerprint: String,
    subject_cn: Option<String>,
    issuer_cn: Option<String>,
    san_dns: Vec<String>,
    not_after: Option<DateTime<Utc>>,
    is_self_signed: bool,
}

#[derive(FromRow)]
struct PrevWebRow {
    host_port_id: Uuid,
    vhost: String,
    scheme: String,
    http_status: Option<i32>,
    redirect_target: Option<String>,
    title: Option<String>,
    headers_filtered: serde_json::Value,
    cookies_meta: serde_json::Value,
    favicon_mmh3: Option<i64>,
    matched_technologies: serde_json::Value,
    detected_paths: Vec<String>,
}

#[derive(FromRow)]
struct PrevSampleRow {
    time_slot: String,
    is_alive: bool,
    open_ports_hash: String,
}

async fn load_previous_host_state_and_samples(
    conn: &mut PgConnection,
    asset_group_id: Uuid,
    ip_net: IpNetwork,
    request_id: Option<Uuid>,
    instance: &str,
) -> Result<(PreviousHostState, Vec<AvailabilitySample>), AppError> {
    let host_row: Option<PrevHostRow> = sqlx::query_as(
        r#"
        SELECT id, status, consecutive_misses, is_unstable, is_probable_tarpit, last_seen_at
        FROM hosts
        WHERE asset_group_id = $1 AND ip_addr = $2
        FOR UPDATE
        "#,
    )
    .bind(asset_group_id)
    .bind(ip_net)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|err| map_db_err(err, "previous host lookup failed", request_id, instance))?;

    let Some(h) = host_row else {
        return Ok((
            PreviousHostState {
                exists: false,
                status: HostStatus::MissingPending,
                consecutive_misses: 0,
                is_unstable: false,
                is_probable_tarpit: false,
                last_seen_at_present: false,
                ports: BTreeMap::new(),
            },
            Vec::new(),
        ));
    };

    let port_rows: Vec<PrevPortRow> = sqlx::query_as(
        r#"
        SELECT id, port, protocol, state, consecutive_misses, service_name, product, version, tunnel
        FROM host_ports
        WHERE host_id = $1
        "#,
    )
    .bind(h.id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|err| map_db_err(err, "previous ports lookup failed", request_id, instance))?;

    let port_id_list: Vec<Uuid> = port_rows.iter().map(|p| p.id).collect();
    let mut tls_by_port: HashMap<Uuid, TlsSnapshot> = HashMap::new();
    let mut webs_by_port: HashMap<Uuid, BTreeMap<(String, String), WebSnapshot>> = HashMap::new();

    if !port_id_list.is_empty() {
        let tls_rows: Vec<PrevTlsRow> = sqlx::query_as(
            r#"
            SELECT host_port_id, sha256_fingerprint, subject_cn, issuer_cn, san_dns, not_after, is_self_signed
            FROM tls_certificates
            WHERE host_port_id = ANY($1)
            "#,
        )
        .bind(&port_id_list)
        .fetch_all(&mut *conn)
        .await
        .map_err(|err| map_db_err(err, "previous tls lookup failed", request_id, instance))?;

        for row in tls_rows {
            tls_by_port.insert(
                row.host_port_id,
                TlsSnapshot {
                    sha256_fingerprint: row.sha256_fingerprint,
                    subject_cn: row.subject_cn,
                    issuer_cn: row.issuer_cn,
                    san_dns: row.san_dns.into_iter().collect(),
                    not_after: row.not_after,
                    is_self_signed: row.is_self_signed,
                },
            );
        }

        let web_rows: Vec<PrevWebRow> = sqlx::query_as(
            r#"
            SELECT host_port_id, vhost, scheme, http_status, redirect_target, title,
                   headers_filtered, cookies_meta, favicon_mmh3, matched_technologies, detected_paths
            FROM web_observations
            WHERE host_port_id = ANY($1)
            "#,
        )
        .bind(&port_id_list)
        .fetch_all(&mut *conn)
        .await
        .map_err(|err| map_db_err(err, "previous web lookup failed", request_id, instance))?;

        for row in web_rows {
            let raw_headers: HashMap<String, String> =
                serde_json::from_value(row.headers_filtered).unwrap_or_default();
            let cookies_vec: Vec<WebCookieMeta> =
                serde_json::from_value(row.cookies_meta).unwrap_or_default();
            let cookies_meta = cookies_vec
                .into_iter()
                .map(|c| (c.name, (c.http_only, c.secure, c.same_site)))
                .collect();
            let techs: Vec<String> =
                serde_json::from_value(row.matched_technologies).unwrap_or_default();

            webs_by_port.entry(row.host_port_id).or_default().insert(
                (row.vhost, row.scheme),
                WebSnapshot {
                    http_status: row.http_status.and_then(|s| u16::try_from(s).ok()),
                    redirect_target: row.redirect_target,
                    title: row.title,
                    headers_filtered: filter_noise_headers(&raw_headers),
                    cookies_meta,
                    favicon_mmh3: row.favicon_mmh3,
                    matched_technologies: techs.into_iter().collect(),
                    detected_paths: row.detected_paths.into_iter().collect(),
                },
            );
        }
    }

    let mut ports = BTreeMap::new();
    for p in port_rows {
        let Some(port_u16) = u16::try_from(p.port).ok() else {
            continue;
        };
        let state = PortState::from_db_str(&p.state).unwrap_or(PortState::Active);
        ports.insert(
            (port_u16, p.protocol),
            PreviousPortState {
                state,
                consecutive_misses: u32::try_from(p.consecutive_misses.max(0)).unwrap_or(0),
                service_name: p.service_name,
                product: p.product,
                version: p.version,
                tunnel: p.tunnel,
                tls: tls_by_port.remove(&p.id),
                webs: webs_by_port.remove(&p.id).unwrap_or_default(),
            },
        );
    }

    let mut sample_rows: Vec<PrevSampleRow> = sqlx::query_as(
        r#"
        SELECT time_slot, is_alive, open_ports_hash
        FROM host_availability_samples
        WHERE host_id = $1
        ORDER BY sampled_at DESC
        LIMIT 39
        "#,
    )
    .bind(h.id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|err| map_db_err(err, "previous samples lookup failed", request_id, instance))?;

    sample_rows.reverse();
    let samples = sample_rows
        .into_iter()
        .filter_map(|row| {
            TimeSlot::from_db_str(&row.time_slot).map(|time_slot| AvailabilitySample {
                time_slot,
                is_alive: row.is_alive,
                open_ports_hash: row.open_ports_hash,
            })
        })
        .collect();

    let status = HostStatus::from_db_str(&h.status).unwrap_or(HostStatus::MissingPending);

    Ok((
        PreviousHostState {
            exists: true,
            status,
            consecutive_misses: u32::try_from(h.consecutive_misses.max(0)).unwrap_or(0),
            is_unstable: h.is_unstable,
            is_probable_tarpit: h.is_probable_tarpit,
            last_seen_at_present: h.last_seen_at.is_some(),
            ports,
        },
        samples,
    ))
}

fn build_current_host_observation(
    ip: IpAddr,
    is_tarpit: bool,
    stage1_ports: &[&Stage1PortFinding],
    stage2_services: &[Stage2ServiceFinding],
    stage3_observations: &[Stage3WebObservation],
) -> CurrentHostObservation {
    let is_alive = !stage1_ports.is_empty() || is_tarpit;
    let mut open_ports: BTreeMap<(u16, String), CurrentPortObservation> = BTreeMap::new();

    for p in stage1_ports {
        open_ports
            .entry((p.port, p.protocol.clone()))
            .or_insert_with(|| CurrentPortObservation {
                service_name: None,
                product: None,
                version: None,
                tunnel: None,
                tls: None,
                webs: BTreeMap::new(),
            });
    }

    for svc in stage2_services.iter().filter(|s| s.ip_addr == ip) {
        let entry = open_ports
            .entry((svc.port, svc.protocol.clone()))
            .or_insert_with(|| CurrentPortObservation {
                service_name: None,
                product: None,
                version: None,
                tunnel: None,
                tls: None,
                webs: BTreeMap::new(),
            });
        entry.service_name = svc.service_name.clone();
        entry.product = svc.product.clone();
        entry.version = svc.version.clone();
        entry.tunnel = svc.tunnel.clone();
        entry.tls = svc.tls_sha256.as_ref().map(|sha| TlsSnapshot {
            sha256_fingerprint: sha.clone(),
            subject_cn: svc.tls_subject_cn.clone(),
            issuer_cn: svc.tls_issuer_cn.clone(),
            san_dns: svc.tls_san_dns.iter().cloned().collect(),
            not_after: svc.tls_not_after,
            is_self_signed: svc.tls_is_self_signed.unwrap_or(false),
        });
    }

    for obs in stage3_observations.iter().filter(|o| o.ip_addr == ip) {
        let entry = open_ports
            .entry((obs.port, "tcp".to_string()))
            .or_insert_with(|| CurrentPortObservation {
                service_name: None,
                product: None,
                version: None,
                tunnel: None,
                tls: None,
                webs: BTreeMap::new(),
            });
        let cookies_meta = obs
            .cookies_meta
            .iter()
            .map(|c| (c.name.clone(), (c.http_only, c.secure, c.same_site.clone())))
            .collect();
        entry.webs.insert(
            (obs.vhost.clone(), obs.scheme.clone()),
            WebSnapshot {
                http_status: obs.http_status,
                redirect_target: obs.redirect_target.clone(),
                title: obs.title.clone(),
                headers_filtered: filter_noise_headers(&obs.headers_filtered),
                cookies_meta,
                favicon_mmh3: obs.favicon_mmh3,
                matched_technologies: obs.matched_technologies.iter().cloned().collect(),
                detected_paths: obs.detected_paths.iter().cloned().collect(),
            },
        );
    }

    CurrentHostObservation {
        is_alive,
        is_probable_tarpit: is_tarpit,
        open_ports,
    }
}

pub async fn worker_register(
    worker: AuthenticatedWorker,
    State(state): State<AppState>,
    Json(payload): Json<WorkerRegisterRequest>,
) -> Result<Json<WorkerRegisterResponse>, AppError> {
    let instance = "/internal/v1/worker/register";
    let pool = require_db(&state, worker.request_id, instance)?;

    let caps_json = serde_json::to_value(&payload.capabilities).map_err(|err| {
        AppError::new(
            DomainError::Internal(format!("failed to serialize capabilities: {err}")),
            worker.request_id,
            Some(instance.to_string()),
        )
    })?;
    let max_concurrency = i32::try_from(payload.max_concurrency.max(1)).unwrap_or(1);
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE worker_nodes
        SET status = 'online',
            capabilities = $1,
            max_concurrency = $2,
            segment_tag = COALESCE($3, segment_tag),
            last_heartbeat_at = $4
        WHERE id = $5
        "#,
    )
    .bind(&caps_json)
    .bind(max_concurrency)
    .bind(payload.segment_tag)
    .bind(now)
    .bind(worker.worker_id)
    .execute(pool)
    .await
    .map_err(|err| map_db_err(err, "worker register failed", worker.request_id, instance))?;

    let event_id = Uuid::new_v4();
    state.events.emit_ui(
        "worker.status",
        event_id,
        serde_json::json!({
            "event_id": event_id,
            "occurred_at": now,
            "worker_id": worker.worker_id,
            "name": worker.name,
            "status": "online",
            "active_chunks": 0
        }),
    );

    Ok(Json(WorkerRegisterResponse {
        worker_id: worker.worker_id,
        registered_at: now,
        heartbeat_interval_seconds: HEARTBEAT_INTERVAL_SECONDS,
    }))
}

pub async fn worker_signatures(
    worker: AuthenticatedWorker,
    State(state): State<AppState>,
) -> Result<Json<WorkerSignaturesResponse>, AppError> {
    let instance = "/internal/v1/worker/signatures";
    let pool = require_db(&state, worker.request_id, instance)?;

    let mut rules: Vec<String> = sqlx::query_scalar(
        "SELECT yaml_content FROM signature_rules WHERE is_enabled = TRUE ORDER BY template_id ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "signatures fetch failed", worker.request_id, instance))?;

    if rules.is_empty() {
        rules = builtin_default_signatures_yaml();
    }

    let mut hasher = Sha256::new();
    for r in &rules {
        hasher.update(r.as_bytes());
        hasher.update(b"\n---\n");
    }
    let version_hash = hex::encode(hasher.finalize());

    Ok(Json(WorkerSignaturesResponse {
        version_hash,
        yaml_rules: rules,
    }))
}

fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn filter_leased_targets(
    targets: Vec<ChunkTarget>,
    exclude_cidrs: &[String],
    ignored_domains: &BTreeSet<String>,
) -> Vec<ChunkTarget> {
    let excluded_nets: Vec<IpNetwork> = exclude_cidrs
        .iter()
        .filter_map(|raw| {
            let trimmed = raw.trim();
            trimmed
                .parse::<IpNetwork>()
                .ok()
                .or_else(|| trimmed.parse::<IpAddr>().ok().map(IpNetwork::from))
        })
        .collect();

    targets
        .into_iter()
        .filter(|t| !excluded_nets.iter().any(|net| net.contains(t.ip_addr)))
        .map(|mut t| {
            t.vhosts
                .retain(|vh| !ignored_domains.contains(&normalize_domain(vh)));
            t
        })
        .collect()
}

pub async fn lease_chunk(
    worker: AuthenticatedWorker,
    State(state): State<AppState>,
    Json(_payload): Json<ChunkLeaseRequest>,
) -> Result<Response, AppError> {
    let instance = "/internal/v1/worker/chunks/lease";
    let pool = require_db(&state, worker.request_id, instance)?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "lease tx failed", worker.request_id, instance))?;

    // 1. Reclaim expired IP locks & expired chunk leases atomically
    sqlx::query("DELETE FROM ip_locks WHERE locked_until < NOW() AND cooldown_until < NOW()")
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "ip_locks cleanup failed", worker.request_id, instance))?;

    sqlx::query(
        r#"
        UPDATE scan_chunks sc
        SET status = 'pending',
            leased_by_worker_id = NULL,
            lease_expires_at = NULL,
            error_message = 'lease_expired_requeued'
        FROM scan_runs sr
        WHERE sc.scan_run_id = sr.id
          AND sc.status = 'leased'
          AND sc.lease_expires_at < NOW()
          AND sr.status IN ('queued', 'running')
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "lease reclaim failed", worker.request_id, instance))?;

    // 2. Fetch candidate pending chunks using FOR UPDATE SKIP LOCKED (enforcing worker visibility scope)
    let candidates: Vec<CandidateChunkRow> = sqlx::query_as(
        r#"
        SELECT sc.id, sc.scan_run_id, sr.asset_group_id, sc.subnet_bucket, sc.targets,
               sr.policy_snapshot, sr.include_all_ignored, sr.overridden_ignored_values
        FROM scan_chunks sc
        INNER JOIN scan_runs sr ON sr.id = sc.scan_run_id
        INNER JOIN worker_nodes wn ON wn.id = $1
        WHERE sc.status = 'pending'
          AND sr.status IN ('queued', 'running')
          AND (
              wn.visibility_scope = 'all'
              OR sr.asset_group_id = ANY(wn.allowed_asset_group_ids)
              OR EXISTS (
                  SELECT 1 FROM asset_group_members agm
                  WHERE agm.asset_group_id = sr.asset_group_id
                    AND agm.user_id = ANY(wn.allowed_user_ids)
              )
          )
        ORDER BY sr.started_at ASC, sc.sequence_no ASC
        FOR UPDATE OF sc SKIP LOCKED
        LIMIT 20
        "#,
    )
    .bind(worker.worker_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "chunk lease query failed", worker.request_id, instance))?;

    for candidate in candidates {
        let targets: Vec<ChunkTarget> =
            serde_json::from_value(candidate.targets.clone()).map_err(|err| {
                AppError::new(
                    DomainError::Internal(format!("corrupt chunk targets JSON: {err}")),
                    worker.request_id,
                    Some(instance.to_string()),
                )
            })?;

        let policy: PolicySnapshot = serde_json::from_value(candidate.policy_snapshot.clone())
            .map_err(|err| {
                AppError::new(
                    DomainError::Internal(format!("corrupt policy snapshot JSON: {err}")),
                    worker.request_id,
                    Some(instance.to_string()),
                )
            })?;

        let mut excluded_cidrs: Vec<String> = sqlx::query_scalar(
            "SELECT value FROM asset_group_targets WHERE asset_group_id = $1 AND target_type = 'exclude_cidr'",
        )
        .bind(candidate.asset_group_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "exclude query failed", worker.request_id, instance))?;

        let ignored_rows: Vec<IgnoredTargetRow> = sqlx::query_as(
            "SELECT target_type, value FROM ignored_targets WHERE asset_group_id IS NULL OR asset_group_id = $1",
        )
        .bind(candidate.asset_group_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "ignored query failed", worker.request_id, instance))?;

        let mut ignored_domains = BTreeSet::new();
        if !candidate.include_all_ignored {
            for row in ignored_rows {
                if candidate.overridden_ignored_values.contains(&row.value) {
                    continue;
                }
                if row.target_type == "domain" {
                    let norm = normalize_domain(&row.value);
                    if !norm.is_empty() {
                        ignored_domains.insert(norm);
                    }
                } else {
                    excluded_cidrs.push(row.value);
                }
            }
        }

        let targets = filter_leased_targets(targets, &excluded_cidrs, &ignored_domains);
        if targets.is_empty() {
            sqlx::query(
                r#"
                UPDATE scan_chunks
                SET status = 'completed',
                    targets = '[]'::jsonb,
                    duration_ms = 0,
                    completed_at = NOW(),
                    error_message = 'all_targets_excluded_at_lease'
                WHERE id = $1
                "#,
            )
            .bind(candidate.id)
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(
                    err,
                    "empty chunk completion failed",
                    worker.request_id,
                    instance,
                )
            })?;

            sqlx::query(
                "UPDATE scan_runs SET completed_chunks = completed_chunks + 1 WHERE id = $1",
            )
            .bind(candidate.scan_run_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(
                    err,
                    "scan run increment failed",
                    worker.request_id,
                    instance,
                )
            })?;

            let remaining: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND status IN ('pending', 'leased')",
            )
            .bind(candidate.scan_run_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(
                    err,
                    "remaining chunk check failed",
                    worker.request_id,
                    instance,
                )
            })?;

            if remaining == 0 {
                sqlx::query(
                    "UPDATE scan_runs SET status = 'completed', finished_at = NOW() WHERE id = $1 AND status IN ('queued', 'running')",
                )
                .bind(candidate.scan_run_id)
                .execute(&mut *tx)
                .await
                .map_err(|err| {
                    map_db_err(err, "scan run finalize failed", worker.request_id, instance)
                })?;
            }
            continue;
        }

        let filtered_targets_json = serde_json::to_value(&targets).map_err(|err| {
            AppError::new(
                DomainError::Internal(format!("failed to serialize filtered chunk targets: {err}")),
                worker.request_id,
                Some(instance.to_string()),
            )
        })?;

        let active_leased_in_bucket: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND subnet_bucket = $2 AND status = 'leased'",
        )
        .bind(candidate.scan_run_id)
        .bind(&candidate.subnet_bucket)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "subnet concurrency check failed", worker.request_id, instance))?;

        if active_leased_in_bucket >= i64::from(policy.subnet_concurrency.max(1)) {
            continue;
        }

        let ip_nets: Vec<IpNetwork> = targets.iter().map(|t| IpNetwork::from(t.ip_addr)).collect();

        let conflict_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM ip_locks
                WHERE ip_addr = ANY($1)
                  AND (locked_until > NOW() OR cooldown_until > NOW())
            )
            "#,
        )
        .bind(&ip_nets)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "ip_locks check failed", worker.request_id, instance))?;

        if conflict_exists {
            continue;
        }

        let now = Utc::now();
        let lease_expires_at = now + chrono::Duration::seconds(LEASE_TTL_SECONDS);
        let cooldown_ms = i64::try_from(policy.per_ip_cooldown_ms).unwrap_or(250);
        let cooldown_until = lease_expires_at + chrono::Duration::milliseconds(cooldown_ms);

        for ip_net in &ip_nets {
            sqlx::query(
                r#"
                INSERT INTO ip_locks (ip_addr, locked_by_chunk_id, locked_by_worker_id, locked_until, cooldown_until)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (ip_addr) DO UPDATE
                SET locked_by_chunk_id = EXCLUDED.locked_by_chunk_id,
                    locked_by_worker_id = EXCLUDED.locked_by_worker_id,
                    locked_until = EXCLUDED.locked_until,
                    cooldown_until = EXCLUDED.cooldown_until
                "#,
            )
            .bind(*ip_net)
            .bind(candidate.id)
            .bind(worker.worker_id)
            .bind(lease_expires_at)
            .bind(cooldown_until)
            .execute(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "ip_lock acquire failed", worker.request_id, instance))?;
        }

        let next_attempt: i32 = sqlx::query_scalar(
            r#"
            UPDATE scan_chunks
            SET status = 'leased',
                attempt_no = attempt_no + 1,
                leased_by_worker_id = $1,
                lease_expires_at = $2,
                last_heartbeat_at = $3,
                targets = $4
            WHERE id = $5
            RETURNING attempt_no
            "#,
        )
        .bind(worker.worker_id)
        .bind(lease_expires_at)
        .bind(now)
        .bind(&filtered_targets_json)
        .bind(candidate.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "chunk lease update failed",
                worker.request_id,
                instance,
            )
        })?;

        let transitioned_running: Option<Uuid> = sqlx::query_scalar(
            "UPDATE scan_runs SET status = 'running' WHERE id = $1 AND status = 'queued' RETURNING id",
        )
        .bind(candidate.scan_run_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "scan run transition failed", worker.request_id, instance))?;

        sqlx::query(
            "UPDATE worker_nodes SET status = 'online', last_heartbeat_at = NOW() WHERE id = $1",
        )
        .bind(worker.worker_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "worker heartbeat failed", worker.request_id, instance))?;

        tx.commit()
            .await
            .map_err(|err| map_db_err(err, "commit failed", worker.request_id, instance))?;

        if transitioned_running.is_some() {
            let ev_id = Uuid::new_v4();
            state.events.emit_ui(
                "scan.status_changed",
                ev_id,
                serde_json::json!({
                    "event_id": ev_id,
                    "occurred_at": Utc::now(),
                    "scan_run_id": candidate.scan_run_id,
                    "previous_status": "queued",
                    "current_status": "running",
                    "reason": null
                }),
            );
        }

        let resp = ChunkLeaseResponse {
            chunk_id: candidate.id,
            scan_run_id: candidate.scan_run_id,
            attempt_no: u32::try_from(next_attempt.max(1)).unwrap_or(1),
            targets,
            excluded_cidrs,
            policy,
            lease_expires_at,
        };
        return Ok((StatusCode::OK, Json(resp)).into_response());
    }

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", worker.request_id, instance))?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn chunk_heartbeat(
    worker: AuthenticatedWorker,
    State(state): State<AppState>,
    Path(chunk_id): Path<Uuid>,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, AppError> {
    let instance = format!("/internal/v1/worker/chunks/{chunk_id}/heartbeat");
    let pool = require_db(&state, worker.request_id, &instance)?;

    let now = Utc::now();
    let new_expiry = now + chrono::Duration::seconds(LEASE_TTL_SECONDS);

    let run_status: Option<String> = sqlx::query_scalar(
        r#"
        UPDATE scan_chunks sc
        SET lease_expires_at = $1,
            last_heartbeat_at = $2
        FROM scan_runs sr
        WHERE sc.id = $3
          AND sc.scan_run_id = sr.id
          AND sc.status = 'leased'
          AND sc.leased_by_worker_id = $4
          AND sc.attempt_no = $5
        RETURNING sr.status
        "#,
    )
    .bind(new_expiry)
    .bind(now)
    .bind(chunk_id)
    .bind(worker.worker_id)
    .bind(i32::try_from(payload.attempt_no).unwrap_or(0))
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "heartbeat update failed", worker.request_id, &instance))?;

    let Some(run_status) = run_status else {
        return Err(AppError::new(
            DomainError::Conflict("Chunk lease is no longer held by this worker.".to_string()),
            worker.request_id,
            Some(instance),
        ));
    };

    let _ = sqlx::query("UPDATE ip_locks SET locked_until = $1 WHERE locked_by_chunk_id = $2")
        .bind(new_expiry)
        .bind(chunk_id)
        .execute(pool)
        .await;

    let _ = sqlx::query(
        "UPDATE worker_nodes SET status = 'online', last_heartbeat_at = NOW() WHERE id = $1",
    )
    .bind(worker.worker_id)
    .execute(pool)
    .await;

    let directive = match run_status.as_str() {
        "stopping" | "stopped" => ControlDirective::KillNow,
        "pausing" | "paused" => ControlDirective::GracefulStop,
        _ => ControlDirective::Continue,
    };

    Ok(Json(HeartbeatResponse {
        directive,
        lease_expires_at: new_expiry,
    }))
}

pub async fn worker_control_stream(
    _worker: AuthenticatedWorker,
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe_worker_control();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(ctrl_ev) => match serde_json::to_string(&ctrl_ev) {
            Ok(data) => Some(Ok(Event::default().event("control").data(data))),
            Err(_) => None,
        },
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

pub async fn submit_chunk_results(
    worker: AuthenticatedWorker,
    State(state): State<AppState>,
    Path(chunk_id): Path<Uuid>,
    Json(payload): Json<ChunkResultsSubmission>,
) -> Result<Json<ChunkResultsResponse>, AppError> {
    let instance = format!("/internal/v1/worker/chunks/{chunk_id}/results");
    let pool = require_db(&state, worker.request_id, &instance)?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "results tx failed", worker.request_id, &instance))?;

    let chunk: Option<LockedChunkRow> = sqlx::query_as(
        r#"
        SELECT scan_run_id, targets, status, attempt_no, leased_by_worker_id
        FROM scan_chunks
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(chunk_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "chunk lock failed", worker.request_id, &instance))?;

    let Some(chunk) = chunk else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Chunk {chunk_id} not found.")),
            worker.request_id,
            Some(instance),
        ));
    };

    let attempt_i32 = i32::try_from(payload.attempt_no).unwrap_or(0);
    if chunk.status == "completed" && chunk.attempt_no == attempt_i32 {
        let run_status: String = sqlx::query_scalar("SELECT status FROM scan_runs WHERE id = $1")
            .bind(chunk.scan_run_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(err, "run status check failed", worker.request_id, &instance)
            })?;
        tx.commit()
            .await
            .map_err(|err| map_db_err(err, "commit failed", worker.request_id, &instance))?;
        return Ok(Json(ChunkResultsResponse {
            accepted: true,
            scan_completed: run_status == "completed",
        }));
    }

    if chunk.status != "leased"
        || chunk.leased_by_worker_id != Some(worker.worker_id)
        || chunk.attempt_no != attempt_i32
    {
        return Err(AppError::new(
            DomainError::Conflict("Chunk lease mismatch or expired.".to_string()),
            worker.request_id,
            Some(instance),
        ));
    }

    let run_meta: ScanRunMetaRow = sqlx::query_as(
        r#"
        SELECT asset_group_id, status, total_chunks, completed_chunks, ema_chunk_ms,
               policy_snapshot, time_slot
        FROM scan_runs
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(chunk.scan_run_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "scan run lock failed", worker.request_id, &instance))?;

    let policy_snap: PolicySnapshot = serde_json::from_value(run_meta.policy_snapshot.clone())
        .unwrap_or_else(|_| PolicySnapshot {
            port_spec: "top-1000".to_string(),
            discovery_tool: DiscoveryTool::Naabu,
            rate_pps: 500,
            per_ip_cooldown_ms: 250,
            subnet_concurrency: 4,
            kill_grace_seconds: 3,
            inactivity_threshold: 3,
            tarpit_port_threshold: 200,
            enable_nuclei: false,
            force_sv_ips: Vec::new(),
        });
    let inactivity_threshold = policy_snap.inactivity_threshold.max(1);

    let completed_prior_runs: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM scan_runs
        WHERE asset_group_id = $1 AND id <> $2 AND status = 'completed'
        "#,
    )
    .bind(run_meta.asset_group_id)
    .bind(chunk.scan_run_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "baseline check failed", worker.request_id, &instance))?;
    let is_initial_baseline = completed_prior_runs == 0;

    let chunk_targets: Vec<ChunkTarget> =
        serde_json::from_value(chunk.targets.clone()).unwrap_or_default();

    let tarpit_set: BTreeSet<IpAddr> = payload.probable_tarpit_ips.iter().copied().collect();
    let mut ports_by_ip: HashMap<IpAddr, Vec<&Stage1PortFinding>> = HashMap::new();
    for p in &payload.stage1_ports {
        ports_by_ip.entry(p.ip_addr).or_default().push(p);
    }

    let mut host_ids: HashMap<IpAddr, Uuid> = HashMap::new();
    let mut port_ids: HashMap<(IpAddr, u16, String), Uuid> = HashMap::new();
    let mut anomaly_events: Vec<(Uuid, IpAddr, HostAnomalyType, Option<u32>)> = Vec::new();
    let mut emitted_diffs: Vec<(Uuid, Uuid, IpAddr, DiffEventDraft)> = Vec::new();
    let now = Utc::now();
    let effective_slot = run_meta
        .time_slot
        .as_deref()
        .and_then(TimeSlot::from_db_str)
        .unwrap_or_else(|| TimeSlot::from_utc_hour(now.hour()));

    // Scan-First Truth + Diff Engine + Instability Analysis
    for target in &chunk_targets {
        let ip = target.ip_addr;
        let ip_net = IpNetwork::from(ip);
        let stage1_for_ip = ports_by_ip.get(&ip).map(Vec::as_slice).unwrap_or(&[]);
        let is_tarpit = tarpit_set.contains(&ip);

        let (prev_state, mut samples) = load_previous_host_state_and_samples(
            &mut tx,
            run_meta.asset_group_id,
            ip_net,
            worker.request_id,
            &instance,
        )
        .await?;

        let curr_obs = build_current_host_observation(
            ip,
            is_tarpit,
            stage1_for_ip,
            &payload.stage2_services,
            &payload.stage3_observations,
        );

        let port_keys: Vec<(u16, &str)> = curr_obs
            .open_ports
            .keys()
            .map(|(p, proto)| (*p, proto.as_str()))
            .collect();
        let open_ports_hash = compute_open_ports_hash(curr_obs.is_alive, &port_keys);
        samples.push(AvailabilitySample {
            time_slot: effective_slot,
            is_alive: curr_obs.is_alive,
            open_ports_hash: open_ports_hash.clone(),
        });

        let instability = assess_instability(prev_state.is_unstable, &samples);
        let eval = evaluate_host_diff(
            &prev_state,
            &curr_obs,
            &instability,
            inactivity_threshold,
            is_initial_baseline,
        );

        let mut auto_tags: BTreeSet<String> = BTreeSet::new();
        if is_tarpit {
            auto_tags.insert("probable-tarpit".to_string());
        }
        if instability.is_unstable {
            auto_tags.insert("unstable".to_string());
        }
        for obs in payload
            .stage3_observations
            .iter()
            .filter(|o| o.ip_addr == ip)
        {
            if obs
                .detected_paths
                .iter()
                .any(|p| p == "/admin" || p == "/login")
            {
                auto_tags.insert("admin-panel".to_string());
            }
            if obs
                .matched_technologies
                .iter()
                .any(|t| t.to_ascii_lowercase().contains("staging"))
            {
                auto_tags.insert("staging".to_string());
            }
        }
        let auto_tags_vec: Vec<String> = auto_tags.into_iter().collect();

        let host_id: Uuid = if curr_obs.is_alive {
            sqlx::query_scalar(
                r#"
                INSERT INTO hosts (
                    asset_group_id, ip_addr, status, consecutive_misses,
                    is_unstable, is_probable_tarpit, availability_profile, auto_tags,
                    first_seen_at, last_seen_at, last_scanned_at
                )
                VALUES ($1, $2, $3, 0, $4, $5, $6, $7, $8, $8, $8)
                ON CONFLICT (asset_group_id, ip_addr) DO UPDATE
                SET status = CASE WHEN hosts.status = 'ignored' THEN 'ignored' ELSE EXCLUDED.status END,
                    consecutive_misses = 0,
                    is_unstable = EXCLUDED.is_unstable,
                    is_probable_tarpit = EXCLUDED.is_probable_tarpit,
                    availability_profile = EXCLUDED.availability_profile,
                    auto_tags = EXCLUDED.auto_tags,
                    last_seen_at = EXCLUDED.last_seen_at,
                    last_scanned_at = EXCLUDED.last_scanned_at
                RETURNING id
                "#,
            )
            .bind(run_meta.asset_group_id)
            .bind(ip_net)
            .bind(eval.next_host_status.as_db_str())
            .bind(instability.is_unstable)
            .bind(is_tarpit)
            .bind(&instability.availability_profile)
            .bind(&auto_tags_vec)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "host upsert failed", worker.request_id, &instance))?
        } else {
            sqlx::query_scalar(
                r#"
                INSERT INTO hosts (
                    asset_group_id, ip_addr, status, consecutive_misses,
                    is_unstable, is_probable_tarpit, availability_profile, auto_tags,
                    first_seen_at, last_scanned_at
                )
                VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7, $8, $8)
                ON CONFLICT (asset_group_id, ip_addr) DO UPDATE
                SET consecutive_misses = EXCLUDED.consecutive_misses,
                    status = CASE WHEN hosts.status = 'ignored' THEN 'ignored' ELSE EXCLUDED.status END,
                    is_unstable = EXCLUDED.is_unstable,
                    availability_profile = EXCLUDED.availability_profile,
                    auto_tags = CASE
                        WHEN $5 THEN array_append(array_remove(hosts.auto_tags, 'unstable'), 'unstable')
                        ELSE array_remove(hosts.auto_tags, 'unstable')
                    END,
                    last_scanned_at = EXCLUDED.last_scanned_at
                RETURNING id
                "#,
            )
            .bind(run_meta.asset_group_id)
            .bind(ip_net)
            .bind(eval.next_host_status.as_db_str())
            .bind(i32::try_from(eval.next_host_misses).unwrap_or(i32::MAX))
            .bind(instability.is_unstable)
            .bind(&instability.availability_profile)
            .bind(&auto_tags_vec)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(err, "host miss upsert failed", worker.request_id, &instance)
            })?
        };

        host_ids.insert(ip, host_id);

        sqlx::query(
            r#"
            INSERT INTO host_availability_samples (
                host_id, scan_run_id, time_slot, is_alive, open_ports_hash, sampled_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(host_id)
        .bind(chunk.scan_run_id)
        .bind(effective_slot.as_db_str())
        .bind(curr_obs.is_alive)
        .bind(&open_ports_hash)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "availability sample insert failed",
                worker.request_id,
                &instance,
            )
        })?;

        for tr in &eval.missing_port_transitions {
            sqlx::query(
                r#"
                UPDATE host_ports
                SET state = $1,
                    consecutive_misses = $2
                WHERE host_id = $3 AND port = $4 AND protocol = $5
                "#,
            )
            .bind(tr.next_state.as_db_str())
            .bind(i32::try_from(tr.next_misses).unwrap_or(i32::MAX))
            .bind(host_id)
            .bind(i32::from(tr.port))
            .bind(&tr.protocol)
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(
                    err,
                    "missing port transition update failed",
                    worker.request_id,
                    &instance,
                )
            })?;
        }

        for draft in eval.diffs {
            let bullets_json = serde_json::to_value(&draft.bullet_items).unwrap_or_default();
            let diff_id: Uuid = sqlx::query_scalar(
                r#"
                INSERT INTO diff_events (
                    host_id, scan_run_id, event_kind, severity, bullet_items,
                    previous_snapshot, current_snapshot, detected_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id
                "#,
            )
            .bind(host_id)
            .bind(chunk.scan_run_id)
            .bind(draft.event_kind.as_db_str())
            .bind(draft.severity.as_db_str())
            .bind(bullets_json)
            .bind(&draft.previous_snapshot)
            .bind(&draft.current_snapshot)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(
                    err,
                    "diff_event insert failed",
                    worker.request_id,
                    &instance,
                )
            })?;
            crate::notifications::worker::enqueue_notifications_for_diff(
                &mut tx,
                run_meta.asset_group_id,
                diff_id,
                draft.event_kind,
            )
            .await
            .map_err(|err| {
                map_db_err(
                    err,
                    "notification enqueue failed",
                    worker.request_id,
                    &instance,
                )
            })?;
            // Faza 6: enqueue do outbox DefectDojo (no-op gdy integracja wylaczona)
            let _ = crate::integrations::push::enqueue_dd_for_diff(
                &mut tx,
                run_meta.asset_group_id,
                diff_id,
                draft.event_kind,
            )
            .await;
            insert_audit_log(
                &mut *tx,
                AuditRecord {
                    actor_type: "scan_engine",
                    actor_id: Some(worker.worker_id),
                    action: "host.diff_detected",
                    resource_type: "host",
                    resource_id: Some(host_id),
                    before_state: Some(draft.previous_snapshot.clone()),
                    after_state: Some(draft.current_snapshot.clone()),
                    source_ip: None,
                    request_id: worker.request_id,
                },
            )
            .await
            .map_err(|err| {
                map_db_err(
                    err,
                    "scan_engine audit log failed",
                    worker.request_id,
                    &instance,
                )
            })?;
            emitted_diffs.push((diff_id, host_id, ip, draft));
        }

        let port_count = u32::try_from(curr_obs.open_ports.len()).unwrap_or(u32::MAX);
        if is_tarpit {
            anomaly_events.push((
                host_id,
                ip,
                HostAnomalyType::ProbableTarpit,
                Some(port_count),
            ));
        }
        if instability.newly_marked_unstable {
            anomaly_events.push((host_id, ip, HostAnomalyType::Unstable, Some(port_count)));
        }

        for vh in &target.vhosts {
            sqlx::query(
                r#"
                INSERT INTO host_hostnames (host_id, hostname, source, first_seen_at, last_seen_at)
                VALUES ($1, $2, 'user_input', $3, $3)
                ON CONFLICT (host_id, hostname) DO UPDATE
                SET last_seen_at = EXCLUDED.last_seen_at
                "#,
            )
            .bind(host_id)
            .bind(vh)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(err, "hostname upsert failed", worker.request_id, &instance)
            })?;
        }
    }

    // Upsert Stage 1 discovered ports (zero truncation)
    for finding in &payload.stage1_ports {
        let Some(&host_id) = host_ids.get(&finding.ip_addr) else {
            continue;
        };
        let port_i32 = i32::from(finding.port);
        let port_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO host_ports (host_id, port, protocol, state, consecutive_misses, first_seen_at, last_seen_at)
            VALUES ($1, $2, $3, 'active', 0, $4, $4)
            ON CONFLICT (host_id, port, protocol) DO UPDATE
            SET state = 'active',
                consecutive_misses = 0,
                last_seen_at = EXCLUDED.last_seen_at
            RETURNING id
            "#,
        )
        .bind(host_id)
        .bind(port_i32)
        .bind(&finding.protocol)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "host_port upsert failed", worker.request_id, &instance))?;

        port_ids.insert(
            (finding.ip_addr, finding.port, finding.protocol.clone()),
            port_id,
        );
    }

    // Enrich Stage 2 service, TLS certificate & rDNS/SAN hostnames
    for svc in &payload.stage2_services {
        let Some(&host_id) = host_ids.get(&svc.ip_addr) else {
            continue;
        };
        let port_i32 = i32::from(svc.port);
        let port_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO host_ports (
                host_id, port, protocol, state, consecutive_misses,
                service_name, product, version, extra_info, is_web_candidate, tunnel,
                first_seen_at, last_seen_at
            )
            VALUES ($1, $2, $3, 'active', 0, $4, $5, $6, $7, $8, $9, $10, $10)
            ON CONFLICT (host_id, port, protocol) DO UPDATE
            SET state = 'active',
                consecutive_misses = 0,
                service_name = EXCLUDED.service_name,
                product = EXCLUDED.product,
                version = EXCLUDED.version,
                extra_info = EXCLUDED.extra_info,
                is_web_candidate = EXCLUDED.is_web_candidate,
                tunnel = EXCLUDED.tunnel,
                last_seen_at = EXCLUDED.last_seen_at
            RETURNING id
            "#,
        )
        .bind(host_id)
        .bind(port_i32)
        .bind(&svc.protocol)
        .bind(&svc.service_name)
        .bind(&svc.product)
        .bind(&svc.version)
        .bind(&svc.extra_info)
        .bind(svc.is_web_candidate)
        .bind(&svc.tunnel)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "stage2 port update failed",
                worker.request_id,
                &instance,
            )
        })?;

        port_ids.insert((svc.ip_addr, svc.port, svc.protocol.clone()), port_id);

        for rdns in &svc.rdns_hostnames {
            sqlx::query(
                r#"
                INSERT INTO host_hostnames (host_id, hostname, source, first_seen_at, last_seen_at)
                VALUES ($1, $2, 'rdns', $3, $3)
                ON CONFLICT (host_id, hostname) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
                "#,
            )
            .bind(host_id)
            .bind(rdns)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "rdns upsert failed", worker.request_id, &instance))?;
        }

        for san in &svc.tls_san_dns {
            sqlx::query(
                r#"
                INSERT INTO host_hostnames (host_id, hostname, source, first_seen_at, last_seen_at)
                VALUES ($1, $2, 'tls_san', $3, $3)
                ON CONFLICT (host_id, hostname) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
                "#,
            )
            .bind(host_id)
            .bind(san)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(err, "tls_san upsert failed", worker.request_id, &instance)
            })?;
        }

        if let Some(sha256) = &svc.tls_sha256 {
            sqlx::query(
                r#"
                INSERT INTO tls_certificates (
                    host_port_id, sha256_fingerprint, subject_cn, issuer_cn, san_dns,
                    not_before, not_after, is_self_signed, observed_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (host_port_id) DO UPDATE
                SET sha256_fingerprint = EXCLUDED.sha256_fingerprint,
                    subject_cn = EXCLUDED.subject_cn,
                    issuer_cn = EXCLUDED.issuer_cn,
                    san_dns = EXCLUDED.san_dns,
                    not_before = EXCLUDED.not_before,
                    not_after = EXCLUDED.not_after,
                    is_self_signed = EXCLUDED.is_self_signed,
                    observed_at = EXCLUDED.observed_at
                "#,
            )
            .bind(port_id)
            .bind(sha256)
            .bind(&svc.tls_subject_cn)
            .bind(&svc.tls_issuer_cn)
            .bind(&svc.tls_san_dns)
            .bind(svc.tls_not_before)
            .bind(svc.tls_not_after)
            .bind(svc.tls_is_self_signed.unwrap_or(false))
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(err, "tls cert upsert failed", worker.request_id, &instance)
            })?;
        }
    }

    // Upsert Stage 3 web observations
    for obs in &payload.stage3_observations {
        let Some(&port_id) = port_ids.get(&(obs.ip_addr, obs.port, "tcp".to_string())) else {
            continue;
        };
        let headers_json = serde_json::to_value(&obs.headers_filtered).unwrap_or_default();
        let cookies_json = serde_json::to_value(&obs.cookies_meta).unwrap_or_default();
        let tech_json = serde_json::to_value(&obs.matched_technologies).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT INTO web_observations (
                host_port_id, vhost, scheme, http_status, final_url, redirect_target, title,
                headers_filtered, cookies_meta, favicon_mmh3, matched_technologies,
                detected_paths, last_observed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (host_port_id, vhost, scheme) DO UPDATE
            SET http_status = EXCLUDED.http_status,
                final_url = EXCLUDED.final_url,
                redirect_target = EXCLUDED.redirect_target,
                title = EXCLUDED.title,
                headers_filtered = EXCLUDED.headers_filtered,
                cookies_meta = EXCLUDED.cookies_meta,
                favicon_mmh3 = EXCLUDED.favicon_mmh3,
                matched_technologies = EXCLUDED.matched_technologies,
                detected_paths = EXCLUDED.detected_paths,
                last_observed_at = EXCLUDED.last_observed_at
            "#,
        )
        .bind(port_id)
        .bind(&obs.vhost)
        .bind(&obs.scheme)
        .bind(obs.http_status.map(i32::from))
        .bind(&obs.final_url)
        .bind(&obs.redirect_target)
        .bind(&obs.title)
        .bind(headers_json)
        .bind(cookies_json)
        .bind(obs.favicon_mmh3)
        .bind(tech_json)
        .bind(&obs.detected_paths)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "web observation upsert failed",
                worker.request_id,
                &instance,
            )
        })?;
    }

    // Release active IP locks and apply per-IP cooldown starting from chunk completion
    let release_cooldown_ms = i64::try_from(policy_snap.per_ip_cooldown_ms).unwrap_or(250);
    let release_cooldown_until = now + chrono::Duration::milliseconds(release_cooldown_ms);
    sqlx::query(
        "UPDATE ip_locks SET locked_until = $1, cooldown_until = $2 WHERE locked_by_chunk_id = $3",
    )
    .bind(now)
    .bind(release_cooldown_until)
    .bind(chunk_id)
    .execute(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "ip_lock release failed", worker.request_id, &instance))?;

    let duration_i32 = i32::try_from(payload.duration_ms).unwrap_or(i32::MAX);
    sqlx::query(
        r#"
        UPDATE scan_chunks
        SET status = 'completed',
            duration_ms = $1,
            completed_at = $2
        WHERE id = $3
        "#,
    )
    .bind(duration_i32)
    .bind(now)
    .bind(chunk_id)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "chunk completion update failed",
            worker.request_id,
            &instance,
        )
    })?;

    let next_completed = run_meta.completed_chunks.saturating_add(1);
    let next_ema = update_ema_ms(run_meta.ema_chunk_ms, payload.duration_ms);

    let remaining_active_or_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND status IN ('pending', 'leased')",
    )
    .bind(chunk.scan_run_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "remaining chunk check failed", worker.request_id, &instance))?;

    let remaining_u32 = u32::try_from(remaining_active_or_pending.max(0)).unwrap_or(0);
    let eta_seconds = estimate_eta_seconds(remaining_u32, next_ema);
    let est_finish: Option<DateTime<Utc>> = if remaining_u32 > 0 {
        Some(now + chrono::Duration::seconds(i64::try_from(eta_seconds).unwrap_or(i64::MAX)))
    } else {
        None
    };

    let next_run_status = if remaining_active_or_pending == 0 {
        match run_meta.status.as_str() {
            "stopping" => "stopped",
            "pausing" => "paused",
            _ => "completed",
        }
    } else {
        match run_meta.status.as_str() {
            "pausing" => {
                let leased_left: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND status = 'leased'",
                )
                .bind(chunk.scan_run_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(1);
                if leased_left == 0 {
                    "paused"
                } else {
                    "pausing"
                }
            }
            "stopping" => {
                let leased_left: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND status = 'leased'",
                )
                .bind(chunk.scan_run_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(1);
                if leased_left == 0 {
                    "stopped"
                } else {
                    "stopping"
                }
            }
            _ => "running",
        }
    };

    let is_terminal = matches!(next_run_status, "completed" | "stopped");

    // Faza 6: gdy run dobiegł końca (completed) — enqueue pushu całego runa do DefectDojo
    if next_run_status == "completed" {
        let _ = crate::integrations::push::enqueue_dd_for_run(
            &mut tx,
            run_meta.asset_group_id,
            chunk.scan_run_id,
        )
        .await;
    }

    sqlx::query(
        r#"
        UPDATE scan_runs
        SET completed_chunks = $1,
            ema_chunk_ms = $2,
            estimated_finish_at = $3,
            status = $4,
            finished_at = CASE WHEN $5 THEN $6 ELSE finished_at END
        WHERE id = $7
        "#,
    )
    .bind(next_completed)
    .bind(next_ema)
    .bind(est_finish)
    .bind(next_run_status)
    .bind(is_terminal)
    .bind(now)
    .bind(chunk.scan_run_id)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "scan run progress update failed",
            worker.request_id,
            &instance,
        )
    })?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", worker.request_id, &instance))?;

    // Emit live telemetry events
    let total_chunks_u32 = u32::try_from(run_meta.total_chunks.max(1)).unwrap_or(1);
    let completed_u32 = u32::try_from(next_completed.max(0)).unwrap_or(0);
    let percent =
        ((f64::from(completed_u32) / f64::from(total_chunks_u32)) * 100.0).min(100.0) as f32;

    let prog_ev_id = Uuid::new_v4();
    state.events.emit_ui(
        "scan.progress",
        prog_ev_id,
        serde_json::json!({
            "event_id": prog_ev_id,
            "occurred_at": now,
            "scan_run_id": chunk.scan_run_id,
            "completed_chunks": completed_u32,
            "total_chunks": total_chunks_u32,
            "percent": percent,
            "ema_chunk_ms": next_ema,
            "eta_seconds": eta_seconds,
            "estimated_finish_at": est_finish,
        }),
    );

    for (host_id, ip_addr, anomaly_type, open_port_count) in anomaly_events {
        let ev_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "event_id": ev_id,
            "occurred_at": now,
            "host_id": host_id,
            "ip_addr": ip_addr,
            "anomaly_type": anomaly_type,
            "open_port_count": open_port_count,
        });
        state.events.emit_ui("host.anomaly", ev_id, payload.clone());
        if let Err(err) = crate::notifications::worker::enqueue_webhook_event(
            pool,
            Some(run_meta.asset_group_id),
            "host.anomaly_detected",
            payload,
        )
        .await
        {
            tracing::warn!(
                error = %err,
                host_id = %host_id,
                "failed to enqueue host.anomaly_detected webhook"
            );
        }
    }

    for (diff_event_id, host_id, ip_addr, draft) in emitted_diffs {
        let ev_id = Uuid::new_v4();
        state.events.emit_ui(
            "diff.detected",
            ev_id,
            serde_json::json!({
                "event_id": ev_id,
                "occurred_at": now,
                "diff_event_id": diff_event_id,
                "host_id": host_id,
                "ip_addr": ip_addr,
                "event_kind": draft.event_kind,
                "severity": draft.severity,
                "bullet_items": draft.bullet_items,
            }),
        );
    }

    if next_run_status != run_meta.status {
        let ev_id = Uuid::new_v4();
        state.events.emit_ui(
            "scan.status_changed",
            ev_id,
            serde_json::json!({
                "event_id": ev_id,
                "occurred_at": now,
                "scan_run_id": chunk.scan_run_id,
                "previous_status": run_meta.status,
                "current_status": next_run_status,
                "reason": null,
            }),
        );
        if next_run_status == "completed" {
            if let Err(err) = crate::notifications::worker::enqueue_webhook_event(
                pool,
                Some(run_meta.asset_group_id),
                "scan.completed",
                serde_json::json!({
                    "event": "scan.completed",
                    "scan_run_id": chunk.scan_run_id,
                    "asset_group_id": run_meta.asset_group_id,
                    "previous_status": run_meta.status,
                    "current_status": next_run_status,
                    "completed_at": now,
                }),
            )
            .await
            {
                tracing::warn!(
                    error = %err,
                    scan_run_id = %chunk.scan_run_id,
                    "failed to enqueue scan.completed webhook"
                );
            }
        }
    }

    Ok(Json(ChunkResultsResponse {
        accepted: true,
        scan_completed: next_run_status == "completed",
    }))
}

pub async fn release_chunk(
    worker: AuthenticatedWorker,
    State(state): State<AppState>,
    Path(chunk_id): Path<Uuid>,
    Json(payload): Json<ChunkReleaseRequest>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/internal/v1/worker/chunks/{chunk_id}/release");
    let pool = require_db(&state, worker.request_id, &instance)?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "release tx failed", worker.request_id, &instance))?;

    let chunk: Option<LockedChunkRow> = sqlx::query_as(
        r#"
        SELECT scan_run_id, targets, status, attempt_no, leased_by_worker_id
        FROM scan_chunks
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(chunk_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "chunk lookup failed", worker.request_id, &instance))?;

    let Some(chunk) = chunk else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Chunk {chunk_id} not found.")),
            worker.request_id,
            Some(instance),
        ));
    };

    if chunk.status != "leased" || chunk.leased_by_worker_id != Some(worker.worker_id) {
        tx.commit()
            .await
            .map_err(|err| map_db_err(err, "commit failed", worker.request_id, &instance))?;
        return Ok(StatusCode::NO_CONTENT);
    }

    let run_status: String =
        sqlx::query_scalar("SELECT status FROM scan_runs WHERE id = $1 FOR UPDATE")
            .bind(chunk.scan_run_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(err, "run status fetch failed", worker.request_id, &instance)
            })?;

    let next_chunk_status = if matches!(run_status.as_str(), "stopping" | "stopped") {
        "cancelled"
    } else {
        "pending"
    };

    sqlx::query(
        r#"
        UPDATE scan_chunks
        SET status = $1,
            leased_by_worker_id = NULL,
            lease_expires_at = NULL,
            error_message = $2
        WHERE id = $3
        "#,
    )
    .bind(next_chunk_status)
    .bind(&payload.reason)
    .bind(chunk_id)
    .execute(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "chunk release failed", worker.request_id, &instance))?;

    sqlx::query("DELETE FROM ip_locks WHERE locked_by_chunk_id = $1")
        .bind(chunk_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "ip_lock delete failed", worker.request_id, &instance))?;

    let leased_remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND status = 'leased'",
    )
    .bind(chunk.scan_run_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "leased count failed", worker.request_id, &instance))?;

    let mut transitioned_to: Option<&'static str> = None;
    if leased_remaining == 0 {
        if run_status == "pausing" {
            sqlx::query("UPDATE scan_runs SET status = 'paused' WHERE id = $1")
                .bind(chunk.scan_run_id)
                .execute(&mut *tx)
                .await
                .map_err(|err| {
                    map_db_err(err, "pause finalize failed", worker.request_id, &instance)
                })?;
            transitioned_to = Some("paused");
        } else if run_status == "stopping" {
            sqlx::query(
                "UPDATE scan_runs SET status = 'stopped', finished_at = NOW() WHERE id = $1",
            )
            .bind(chunk.scan_run_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "stop finalize failed", worker.request_id, &instance))?;
            transitioned_to = Some("stopped");
        }
    }

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", worker.request_id, &instance))?;

    if let Some(new_st) = transitioned_to {
        let ev_id = Uuid::new_v4();
        state.events.emit_ui(
            "scan.status_changed",
            ev_id,
            serde_json::json!({
                "event_id": ev_id,
                "occurred_at": Utc::now(),
                "scan_run_id": chunk.scan_run_id,
                "previous_status": run_status,
                "current_status": new_st,
                "reason": payload.reason,
            }),
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_leased_targets_removes_excluded_ips_and_ignored_domains() {
        let targets = vec![
            ChunkTarget {
                ip_addr: "172.28.0.10".parse().unwrap(),
                vhosts: vec!["ok.lab.local".to_string(), "Ignored.Lab.Local.".to_string()],
            },
            ChunkTarget {
                ip_addr: "172.28.0.12".parse().unwrap(),
                vhosts: vec!["excluded.lab.local".to_string()],
            },
            ChunkTarget {
                ip_addr: "172.28.0.13".parse().unwrap(),
                vhosts: vec![],
            },
        ];

        let exclude_cidrs = vec!["172.28.0.12/31".to_string()];
        let ignored_domains = BTreeSet::from(["ignored.lab.local".to_string()]);

        let filtered = filter_leased_targets(targets, &exclude_cidrs, &ignored_domains);
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered[0].ip_addr,
            "172.28.0.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(filtered[0].vhosts, vec!["ok.lab.local"]);
    }
}
