#![allow(clippy::unwrap_used, clippy::expect_used)]

use asi_api::app::{build_router, AppState};
use asi_api::bootstrap::bootstrap_initial_admin;
use asi_api::config::ApiConfig;
use asi_api::run_migrations;
use asi_common::assets::{AssetGroupDto, CreateWorkerTokenResponse, ScanPolicyDto};
use asi_common::auth::LoginResponse;
use asi_common::io::{ExportTargetsEnvelope, ImportTargetsJsonResponse};
use asi_common::pagination::PaginatedResponse;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

#[tokio::test]
#[ignore = "Requires live PostgreSQL instance (DATABASE_URL)"]
async fn live_db_phase2_auth_rotation_crud_and_json_io() {
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

    // 1. Login as bootstrapped Admin
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
    let set_cookie_1 = login_resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cookie_pair_1 = set_cookie_1.split(';').next().unwrap().to_string();
    let login_body = login_resp.into_body().collect().await.unwrap().to_bytes();
    let login_data: LoginResponse = serde_json::from_slice(&login_body).unwrap();
    let token = login_data.access_token;

    // 2. Rotate refresh token
    let refresh_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(header::COOKIE, &cookie_pair_1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_resp.status(), StatusCode::OK);
    let set_cookie_2 = refresh_resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cookie_pair_2 = set_cookie_2.split(';').next().unwrap().to_string();

    // 3. Reusing cookie_pair_1 triggers family revocation -> 401 and invalidates cookie_pair_2
    let reuse_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(header::COOKIE, &cookie_pair_1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reuse_resp.status(), StatusCode::UNAUTHORIZED);

    let after_revoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(header::COOKIE, &cookie_pair_2)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(after_revoke.status(), StatusCode::UNAUTHORIZED);

    // 4. Fetch default policy, create asset group, JSON dry-run & import, JSON export, worker token
    let policies_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(policies_resp.status(), StatusCode::OK);
    let policies_bytes = policies_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let policies: PaginatedResponse<ScanPolicyDto> =
        serde_json::from_slice(&policies_bytes).unwrap();
    let default_policy = &policies.items[0];

    let group_name = format!("mock-lab-{}", uuid::Uuid::new_v4());
    let group_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/asset-groups")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": group_name,
                        "description": "Integration test mock-lab group",
                        "policy_id": default_policy.id
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(group_resp.status(), StatusCode::CREATED);
    let group: AssetGroupDto =
        serde_json::from_slice(&group_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();

    let import_payload = serde_json::json!({
        "schema_version": "1.0",
        "asset_group_id": group.id,
        "dry_run": false,
        "items": [
            { "target_type": "cidr", "value": "172.28.0.0/24", "notes": "Docker Mock-Lab" },
            { "target_type": "domain", "value": "app1.lab.local", "notes": "Vhost 1" }
        ]
    });
    let import_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/import/targets")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(import_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(import_resp.status(), StatusCode::OK);
    let import_summary: ImportTargetsJsonResponse =
        serde_json::from_slice(&import_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(import_summary.inserted_count, 2);

    let export_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/export/targets?asset_group_id={}",
                    group.id
                ))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export_resp.status(), StatusCode::OK);
    let exported: ExportTargetsEnvelope =
        serde_json::from_slice(&export_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(exported.schema_version, "1.0");
    assert_eq!(exported.items.len(), 2);

    let worker_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/workers/tokens")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": format!("worker-{}", uuid::Uuid::new_v4()),
                        "segment_tag": "mock-lab"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(worker_resp.status(), StatusCode::CREATED);
    let worker_data: CreateWorkerTokenResponse =
        serde_json::from_slice(&worker_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(worker_data.token.starts_with("asiw_"));

    // Clean up test asset group & worker
    let _ = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/asset-groups/{}", group.id))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let _ = sqlx::query("DELETE FROM worker_nodes WHERE id = $1")
        .bind(worker_data.worker.id)
        .execute(&pool)
        .await;
}
