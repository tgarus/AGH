use anyhow::Result;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::routing::{delete, get, patch, post};
use axum::Router;
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use crate::config::{ApiConfig, SignatureSyncConfig};
use crate::routes::asset_groups::{
    add_group_targets, create_asset_group, delete_asset_group, delete_group_target,
    get_asset_group, list_asset_groups, list_group_targets, update_asset_group,
};
use crate::routes::auth::{login, logout, me, refresh};
use crate::routes::diffs::{acknowledge_diff, get_diff, list_diffs};
use crate::routes::events::ui_events_stream;
use crate::routes::health::{healthz, openapi_json, readyz};
use crate::routes::hosts::{get_host, list_hosts, set_tarpit_override, update_host_metadata};
use crate::routes::ignored_targets::{
    create_ignored_target, delete_ignored_target, list_ignored_targets,
};
use crate::routes::integrations::{
    get_dd_link, get_defectdojo_config, list_dd_outbox, push_diff_to_defectdojo, sync_defectdojo,
    test_defectdojo_connection, update_defectdojo_config,
};
use crate::routes::io::{
    export_diffs_json, export_hosts_json, export_ignored_targets_json, export_policies_json,
    export_services_json, export_targets_json, import_targets_json,
};
use crate::routes::notifications::{
    create_notification_channel, delete_notification_channel, list_notification_channels,
    list_notification_deliveries, test_notification_channel, update_notification_channel,
};
use crate::routes::policies::{create_policy, delete_policy, list_policies, update_policy};
use crate::routes::scans::{
    get_scan, list_scan_chunks, list_scans, pause_scan, preflight_scan, resume_scan, start_scan,
    stop_scan,
};
use crate::routes::services::{dashboard_summary, list_clusters, list_services};
use crate::routes::signatures::{
    create_signature, delete_signature, get_signature, import_signatures_json, list_signatures,
    sync_signatures, update_signature, validate_signature,
};
use crate::routes::users::{create_user, delete_user, list_audit_logs, list_users, update_user};
use crate::routes::worker_internal::{
    chunk_heartbeat, lease_chunk, release_chunk, submit_chunk_results, worker_control_stream,
    worker_register, worker_signatures,
};
use crate::routes::workers::{create_worker_token, list_workers, revoke_worker};
use crate::security::crypto::SecretBox;
use crate::security::jwt::JwtManager;
use crate::security::rate_limit::LoginRateLimiter;
use crate::sse::EventHub;

#[derive(Clone)]
pub struct AppState {
    pub db: Option<PgPool>,
    pub jwt: JwtManager,
    pub secret_box: SecretBox,
    pub login_limiter: LoginRateLimiter,
    pub events: EventHub,
    pub cookie_secure: bool,
    pub sig_sync: SignatureSyncConfig,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            db: None,
            jwt: JwtManager::new("dev-only-change-me-at-least-32-bytes-long-secret"),
            secret_box: SecretBox::dev_default(),
            login_limiter: LoginRateLimiter::default(),
            events: EventHub::new(),
            cookie_secure: false,
            sig_sync: SignatureSyncConfig::default(),
        }
    }
}

impl AppState {
    pub fn from_config(db: Option<PgPool>, config: &ApiConfig) -> Result<Self> {
        let secret_box = SecretBox::from_hex_key(&config.master_key)?;
        Ok(Self {
            db,
            jwt: JwtManager::new(&config.jwt_secret),
            secret_box,
            login_limiter: LoginRateLimiter::default(),
            events: EventHub::new(),
            cookie_secure: config.cookie_secure,
            sig_sync: config.sig_sync.clone(),
        })
    }

    #[must_use]
    pub fn with_jwt_secret(mut self, secret: &str) -> Self {
        self.jwt = JwtManager::new(secret);
        self
    }
}

pub fn build_router(state: AppState, cors_origin: &str) -> Router {
    let x_request_id = HeaderName::from_static("x-request-id");

    let cors = match cors_origin.parse::<HeaderValue>() {
        Ok(origin) => CorsLayer::new()
            .allow_origin(origin)
            .allow_credentials(true)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PATCH,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                x_request_id.clone(),
                HeaderName::from_static("last-event-id"),
            ]),
        Err(err) => {
            tracing::warn!(origin = %cors_origin, error = %err, "invalid ASI_CORS_ORIGIN, falling back to restrictive CORS");
            CorsLayer::new()
        }
    };

    Router::new()
        // System & OpenAPI
        .route("/api/v1/healthz", get(healthz))
        .route("/api/v1/readyz", get(readyz))
        .route("/api/v1/openapi.json", get(openapi_json))
        // Auth
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        // Users & Audit Logs
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/:id", patch(update_user).delete(delete_user))
        .route("/api/v1/audit-logs", get(list_audit_logs))
        // Scan Policies
        .route("/api/v1/policies", get(list_policies).post(create_policy))
        .route(
            "/api/v1/policies/:id",
            patch(update_policy).delete(delete_policy),
        )
        // Asset Groups & Targets
        .route(
            "/api/v1/asset-groups",
            get(list_asset_groups).post(create_asset_group),
        )
        .route(
            "/api/v1/asset-groups/:id",
            get(get_asset_group)
                .patch(update_asset_group)
                .delete(delete_asset_group),
        )
        .route(
            "/api/v1/asset-groups/:id/targets",
            get(list_group_targets).post(add_group_targets),
        )
        .route(
            "/api/v1/asset-groups/:id/targets/:target_id",
            delete(delete_group_target),
        )
        // Ignored Targets
        .route(
            "/api/v1/ignored-targets",
            get(list_ignored_targets).post(create_ignored_target),
        )
        .route("/api/v1/ignored-targets/:id", delete(delete_ignored_target))
        // Scans & Live SSE
        .route("/api/v1/scans/preflight", post(preflight_scan))
        .route("/api/v1/scans", get(list_scans).post(start_scan))
        .route("/api/v1/scans/:id", get(get_scan))
        .route("/api/v1/scans/:id/chunks", get(list_scan_chunks))
        .route("/api/v1/scans/:id/pause", post(pause_scan))
        .route("/api/v1/scans/:id/resume", post(resume_scan))
        .route("/api/v1/scans/:id/stop", post(stop_scan))
        .route("/api/v1/events/stream", get(ui_events_stream))
        // Inventory Hosts, Services, Clusters & Diff Engine
        .route("/api/v1/dashboard/summary", get(dashboard_summary))
        .route("/api/v1/hosts", get(list_hosts))
        .route(
            "/api/v1/hosts/:id",
            get(get_host).patch(update_host_metadata),
        )
        .route(
            "/api/v1/hosts/:id/tarpit-override",
            post(set_tarpit_override),
        )
        .route("/api/v1/services", get(list_services))
        .route("/api/v1/clusters", get(list_clusters))
        .route("/api/v1/diffs", get(list_diffs))
        .route("/api/v1/diffs/:id", get(get_diff))
        .route("/api/v1/diffs/:id/acknowledge", post(acknowledge_diff))
        // FingerprintHub v4 Signatures
        .route(
            "/api/v1/signatures",
            get(list_signatures).post(create_signature),
        )
        .route("/api/v1/signatures/validate", post(validate_signature))
        .route("/api/v1/signatures/sync", post(sync_signatures))
        .route(
            "/api/v1/signatures/:id",
            get(get_signature)
                .patch(update_signature)
                .delete(delete_signature),
        )
        // Notification Channels & Retry Deliveries
        .route(
            "/api/v1/notifications/channels",
            get(list_notification_channels).post(create_notification_channel),
        )
        .route(
            "/api/v1/notifications/channels/:id",
            patch(update_notification_channel).delete(delete_notification_channel),
        )
        .route(
            "/api/v1/notifications/channels/:id/test",
            post(test_notification_channel),
        )
        .route(
            "/api/v1/notifications/deliveries",
            get(list_notification_deliveries),
        )
        // Workers
        .route("/api/v1/workers", get(list_workers))
        .route("/api/v1/workers/tokens", post(create_worker_token))
        .route("/api/v1/workers/:id/revoke", post(revoke_worker))
        // JSON Import / Export
        .route("/api/v1/import/targets", post(import_targets_json))
        .route("/api/v1/import/signatures", post(import_signatures_json))
        .route(
            "/api/v1/integrations/defectdojo",
            get(get_defectdojo_config).put(update_defectdojo_config),
        )
        .route(
            "/api/v1/integrations/defectdojo/test-connection",
            post(test_defectdojo_connection),
        )
        .route(
            "/api/v1/integrations/defectdojo/sync",
            post(sync_defectdojo),
        )
        .route(
            "/api/v1/integrations/defectdojo/outbox",
            get(list_dd_outbox),
        )
        .route(
            "/api/v1/integrations/defectdojo/link/:diff_event_id",
            get(get_dd_link),
        )
        .route(
            "/api/v1/integrations/defectdojo/push/:diff_event_id",
            post(push_diff_to_defectdojo),
        )
        .route("/api/v1/export/targets", get(export_targets_json))
        .route("/api/v1/export/policies", get(export_policies_json))
        .route(
            "/api/v1/export/ignored-targets",
            get(export_ignored_targets_json),
        )
        .route("/api/v1/export/hosts", get(export_hosts_json))
        .route("/api/v1/export/diffs", get(export_diffs_json))
        .route("/api/v1/export/services", get(export_services_json))
        // Internal Worker Protocol (HTTPS API)
        .route("/internal/v1/worker/register", post(worker_register))
        .route("/internal/v1/worker/signatures", get(worker_signatures))
        .route("/internal/v1/worker/chunks/lease", post(lease_chunk))
        .route(
            "/internal/v1/worker/chunks/:id/heartbeat",
            post(chunk_heartbeat),
        )
        .route(
            "/internal/v1/worker/control/stream",
            get(worker_control_stream),
        )
        .route(
            "/internal/v1/worker/chunks/:id/results",
            post(submit_chunk_results),
        )
        .route(
            "/internal/v1/worker/chunks/:id/release",
            post(release_chunk),
        )
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        .layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid))
}
