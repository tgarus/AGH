#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Faza 6: testy integracji DefectDojo.
//! 1) `dd_client_*` — klient DD przeciwko lokalnemu mockowi HTTP (bez bazy).
//! 2) `live_db_dd_*` — pełny flow przez API na żywej bazie (#[ignore], DATABASE_URL).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use asi_api::app::{build_router, AppState};
use asi_api::bootstrap::bootstrap_initial_admin;
use asi_api::config::ApiConfig;
use asi_api::integrations::defectdojo::DdClient;
use asi_api::run_migrations;
use asi_common::defectdojo::DdFindingUpsert;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, Method, Request, StatusCode};
use axum::routing::{get, patch};
use axum::{Json, Router};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const MOCK_API_KEY: &str = "dd-secret-key";

// ---------------------------------------------------------------------------
// Mock DefectDojo API v2
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockDd {
    next_product: i32,
    next_engagement: i32,
    next_test: i32,
    next_finding: i32,
    products: Vec<Value>,
    engagements: Vec<Value>,
    tests: Vec<Value>,
    findings: Vec<Value>,
}

type SharedMock = Arc<Mutex<MockDd>>;

fn check_auth(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(format!("Token {MOCK_API_KEY}").as_str())
}

fn unauthorized() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"detail": "Invalid token"})),
    )
}

async fn products_get(
    headers: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    State(st): State<SharedMock>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let lock = st.lock().unwrap();
    let name = q.get("name").cloned();
    let results: Vec<Value> = lock
        .products
        .iter()
        .filter(|p| name.as_ref().map(|n| p["name"] == *n).unwrap_or(true))
        .cloned()
        .collect();
    let count = results.len() as i64;
    Ok(Json(json!({"count": count, "results": results})))
}

async fn products_post(
    headers: axum::http::HeaderMap,
    State(st): State<SharedMock>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let mut lock = st.lock().unwrap();
    lock.next_product += 1;
    let p = json!({"id": lock.next_product, "name": body["name"], "description": body.get("description")});
    lock.products.push(p.clone());
    Ok(Json(p))
}

async fn product_types_get(
    headers: axum::http::HeaderMap,
    State(_st): State<SharedMock>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    Ok(Json(
        json!({"count": 1, "results": [{"id": 1, "name": "Application"}]}),
    ))
}

async fn test_types_get(
    headers: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    State(st): State<SharedMock>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let lock = st.lock().unwrap();
    let name = q.get("name").cloned();
    let results: Vec<Value> =
        if name.as_deref() == Some(asi_api::integrations::defectdojo::DD_TEST_TYPE_NAME) {
            vec![json!({"id": 77, "name": asi_api::integrations::defectdojo::DD_TEST_TYPE_NAME})]
        } else {
            Vec::new()
        };
    let _ = &lock;
    Ok(Json(json!({"count": results.len(), "results": results})))
}

async fn test_types_post(
    headers: axum::http::HeaderMap,
    State(_st): State<SharedMock>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    Ok(Json(json!({"id": 77, "name": body["name"]})))
}

async fn engagements_get(
    headers: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    State(_st): State<SharedMock>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let name = q.get("name").cloned().unwrap_or_default();
    let results = vec![json!({"id": 500, "name": name, "product": 1, "status": "In Progress"})];
    Ok(Json(json!({"count": results.len(), "results": results})))
}

async fn engagements_post(
    headers: axum::http::HeaderMap,
    State(st): State<SharedMock>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let mut lock = st.lock().unwrap();
    lock.next_engagement += 1;
    let e = json!({"id": lock.next_engagement, "name": body["name"], "product": body["product"], "status": body["status"]});
    lock.engagements.push(e.clone());
    Ok(Json(e))
}

async fn engagements_patch(
    headers: axum::http::HeaderMap,
    Path(id): Path<i32>,
    State(st): State<SharedMock>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let mut lock = st.lock().unwrap();
    for e in lock.engagements.iter_mut() {
        if e["id"] == id {
            if let Some(s) = body.get("status") {
                e["status"] = s.clone();
            }
        }
    }
    Ok(Json(json!({"id": id, "status": body.get("status")})))
}

async fn tests_get(
    headers: axum::http::HeaderMap,
    Query(_q): Query<HashMap<String, String>>,
    State(_st): State<SharedMock>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    Ok(Json(json!({"count": 0, "results": []})))
}

async fn tests_post(
    headers: axum::http::HeaderMap,
    State(st): State<SharedMock>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let mut lock = st.lock().unwrap();
    lock.next_test += 1;
    let t = json!({"id": lock.next_test, "title": body["title"], "test_type": body["test_type"], "engagement": body["engagement"]});
    lock.tests.push(t.clone());
    Ok(Json(t))
}

async fn findings_get(
    headers: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    State(st): State<SharedMock>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let lock = st.lock().unwrap();
    let results: Vec<Value>;
    if let Some(unique) = q.get("unique_id_from_tool") {
        results = lock
            .findings
            .iter()
            .filter(|f| f["unique_id_from_tool"] == *unique)
            .cloned()
            .collect();
    } else if let Some(ids) = q.get("id__in") {
        let wanted: Vec<i64> = ids.split(',').filter_map(|s| s.parse().ok()).collect();
        results = lock
            .findings
            .iter()
            .filter(|f| wanted.contains(&f["id"].as_i64().unwrap_or(-1)))
            .cloned()
            .collect();
    } else {
        results = lock.findings.clone();
    }
    let count = results.len() as i64;
    Ok(Json(json!({"count": count, "results": results})))
}

async fn findings_post(
    headers: axum::http::HeaderMap,
    State(st): State<SharedMock>,
    Json(mut body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let mut lock = st.lock().unwrap();
    lock.next_finding += 1;
    body["id"] = json!(lock.next_finding);
    // symulacja triazu w DD: nowe findingi sa "active", pull zmienia status na "mitigated"
    body["status"] = json!("active");
    lock.findings.push(body.clone());
    Ok(Json(body))
}

async fn findings_patch(
    headers: axum::http::HeaderMap,
    Path(id): Path<i32>,
    State(st): State<SharedMock>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !check_auth(&headers) {
        return Err(unauthorized());
    }
    let mut lock = st.lock().unwrap();
    let mut out = json!({"id": id});
    for f in lock.findings.iter_mut() {
        if f["id"] == id {
            for (k, v) in body.as_object().unwrap() {
                f[k.clone()] = v.clone();
            }
            out = f.clone();
        }
    }
    Ok(Json(out))
}

async fn spawn_mock_dd() -> (String, SharedMock) {
    let state: SharedMock = Arc::new(Mutex::new(MockDd::default()));
    let st = state.clone();
    let app = Router::new()
        .route("/api/v2/products/", get(products_get).post(products_post))
        .route("/api/v2/product_types/", get(product_types_get))
        .route(
            "/api/v2/test_types/",
            get(test_types_get).post(test_types_post),
        )
        .route(
            "/api/v2/engagements/",
            get(engagements_get).post(engagements_post),
        )
        .route("/api/v2/engagements/:id/", patch(engagements_patch))
        .route("/api/v2/tests/", get(tests_get).post(tests_post))
        .route("/api/v2/findings/", get(findings_get).post(findings_post))
        .route("/api/v2/findings/:id/", patch(findings_patch))
        .with_state(st);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

// ---------------------------------------------------------------------------
// 1) Klient DD vs mock (bez bazy)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dd_client_upsert_is_idempotent_and_pull_reads_status() {
    let (url, state) = spawn_mock_dd().await;
    let client = DdClient::new(&url, MOCK_API_KEY).unwrap();

    let count = client.ping().await.unwrap();
    assert_eq!(count, 0);

    let pid = client.ensure_product("Kampus", "test group").await.unwrap();
    assert_eq!(pid, 1);
    // drugi raz — GET znajduje istniejacy produkt, bez POST
    let pid2 = client.ensure_product("Kampus", "test group").await.unwrap();
    assert_eq!(pid2, 1);
    assert_eq!(state.lock().unwrap().products.len(), 1);

    let ttid = client.ensure_test_type().await.unwrap();
    assert_eq!(ttid, 77);
    let eid = client
        .ensure_engagement(pid, "run1", Utc::now(), None)
        .await
        .unwrap();
    let test_id = client
        .ensure_test(eid, ttid, "run1", Utc::now(), None)
        .await
        .unwrap();
    assert!(test_id >= 1);

    let payload = DdFindingUpsert {
        title: "ASI zmiana [Medium] 10.0.0.5: + service 443/tcp".to_string(),
        description: "Zmiany:\n- + service 443/tcp".to_string(),
        severity: "Medium".to_string(),
        date: "2026-11-21".to_string(),
        test: test_id,
        found_by: vec![test_id],
        numerical_severity: "S2".to_string(),
        unique_id_from_tool: "diff-1".to_string(),
        component_name: Some("https".to_string()),
        references: Some("asi://diffs/diff-1".to_string()),
        tags: vec!["asi".to_string(), "confirmed_change".to_string()],
        active: true,
        verified: false,
        ..Default::default()
    };
    let f1 = client.upsert_finding(&payload).await.unwrap();
    let f2 = client.upsert_finding(&payload).await.unwrap(); // PATCH zamiast POST
    assert_eq!(f1, f2);
    assert_eq!(state.lock().unwrap().findings.len(), 1);

    // symulacja triazu w DD: pull widzi zmieniony status
    {
        let mut lock = state.lock().unwrap();
        lock.findings[0]["status"] = json!("mitigated");
        lock.findings[0]["tags"] = json!([{"name": "triaged"}, {"name": "asi"}]);
    }
    let pulled = client.findings_by_ids(&[f1]).await.unwrap();
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].status.as_deref(), Some("mitigated"));
    assert_eq!(pulled[0].tags.len(), 2);

    client.close_engagement(eid).await.unwrap();

    // zly klucz -> 401
    let bad = DdClient::new(&url, "wrong-key").unwrap();
    assert!(bad.ping().await.is_err());
}

// ---------------------------------------------------------------------------
// 2) Pelny flow przez API na żywej bazie
// ---------------------------------------------------------------------------

async fn api_json(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    let req_body = if let Some(v) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(v.to_string())
    } else {
        Body::empty()
    };
    let resp = app
        .clone()
        .oneshot(builder.body(req_body).unwrap())
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
async fn live_db_dd_config_push_pull_and_rbac() {
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

    let (dd_url, _mock) = spawn_mock_dd().await;
    let state = AppState::from_config(Some(pool.clone()), &config).unwrap();
    let app = build_router(state.clone(), "http://localhost:5173");

    // login admin
    let (status, body) = api_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        "",
        Some(json!({
            "username": "admin", "password": "ChangeMeNow_Admin123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let login: Value = serde_json::from_slice(&body).unwrap();
    let admin_token = login["access_token"].as_str().unwrap().to_string();

    // 1. PUT konfiguracji (enabled, scope=all_diffs, auto_push)
    let (status, body) = api_json(
        &app,
        Method::PUT,
        "/api/v1/integrations/defectdojo",
        &admin_token,
        Some(json!({
            "base_url": dd_url,
            "asi_public_url": "http://asi.local",
            "api_key": MOCK_API_KEY,
            "finding_scope": "all_diffs",
            "auto_push": true,
            "pull_interval_minutes": 1,
            "enabled": true
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PUT config: {}",
        String::from_utf8_lossy(&body)
    );
    let cfg: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(cfg["enabled"], true);
    assert_eq!(cfg["has_api_key"], true);
    assert_eq!(cfg["finding_scope"], "all_diffs");
    assert!(cfg["base_url"]
        .as_str()
        .unwrap()
        .starts_with("http://127.0.0.1"));

    // 2. test-connection przeciwko mockowi
    let (status, body) = api_json(
        &app,
        Method::POST,
        "/api/v1/integrations/defectdojo/test-connection",
        &admin_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let pong: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(pong["ok"], true, "test-connection: {pong}");

    // 3. seed: policy + asset_group + host + scan_run + diff_event (unikalna nazwa per bieg)
    let suffix = &Uuid::new_v4().to_string()[..8];
    let group_name = format!("DD-Test-{suffix}");
    let group_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO asset_groups (name, description, policy_id)
           SELECT $1, 'test', id FROM scan_policies ORDER BY created_at LIMIT 1
           RETURNING id"#,
    )
    .bind(&group_name)
    .fetch_one(&pool)
    .await
    .unwrap();
    let host_id: Uuid = sqlx::query_scalar(
        "INSERT INTO hosts (asset_group_id, ip_addr, status) VALUES ($1, '10.9.9.9', 'active') RETURNING id",
    )
    .bind(group_id).fetch_one(&pool).await.unwrap();
    let run_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO scan_runs (asset_group_id, policy_snapshot, trigger_type, status, total_targets, total_chunks, started_at)
           VALUES ($1, '{}'::jsonb, 'manual', 'completed', 1, 1, NOW()) RETURNING id"#,
    )
    .bind(group_id).fetch_one(&pool).await.unwrap();
    let diff_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO diff_events (host_id, scan_run_id, event_kind, severity, bullet_items, detected_at)
           VALUES ($1, $2, 'confirmed_change', 'high', '[{"op":"+","key":"service 443/tcp","params":{"service":"https"}}]'::jsonb, NOW())
           RETURNING id"#,
    )
    .bind(host_id).bind(run_id).fetch_one(&pool).await.unwrap();

    // 4. reczny push diffa -> finding #1 w mocku
    let (status, body) = api_json(
        &app,
        Method::POST,
        &format!("/api/v1/integrations/defectdojo/push/{diff_id}"),
        &admin_token,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "push: {}",
        String::from_utf8_lossy(&body)
    );
    let pushed: Value = serde_json::from_slice(&body).unwrap();
    assert!(pushed["note"].as_str().unwrap().contains("finding #1"));

    // 5. link widoczny z dd_finding_id
    let (status, body) = api_json(
        &app,
        Method::GET,
        &format!("/api/v1/integrations/defectdojo/link/{diff_id}"),
        &admin_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let link: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(link["dd_finding_id"], 1);
    assert_eq!(link["dd_product_id"], 1);
    assert_eq!(link["dd_finding_status"], "active");
    let tags = link["dd_tags"].as_array().unwrap();
    assert!(
        tags.iter().any(|t| t == "confirmed_change"),
        "tags: {tags:?}"
    );
    assert!(tags.iter().any(|t| t == "asi"), "tags: {tags:?}");

    // 6. pull statusow z DD (mock zwraca "mitigated")
    {
        let mut lock = _mock.lock().unwrap();
        lock.findings[0]["status"] = json!("mitigated");
    }
    let cfg_loaded = asi_api::integrations::push::load_config(&pool, &state.secret_box)
        .await
        .unwrap()
        .unwrap();
    let client = DdClient::new(&cfg_loaded.base_url, &cfg_loaded.api_key).unwrap();
    let updated = asi_api::integrations::push::pull_dd_statuses(&pool, &client, &state.events)
        .await
        .unwrap();
    assert!(updated >= 1);
    let (status, body) = api_json(
        &app,
        Method::GET,
        &format!("/api/v1/integrations/defectdojo/link/{diff_id}"),
        &admin_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let link: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(link["dd_finding_status"], "mitigated");

    // 7. outbox: enqueue_dd_for_diff dla active_variance przy scope=all_diffs
    let mut tx = pool.begin().await.unwrap();
    asi_api::integrations::push::enqueue_dd_for_diff(
        &mut tx,
        group_id,
        diff_id,
        asi_common::diff::DiffEventKind::ActiveVariance,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dd_outbox WHERE diff_event_id = $1 AND kind='diff_event'",
    )
    .bind(diff_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending, 1);

    // 8. RBAC: user ReadOnly nie moze PUT config ani sync
    let reader_name = format!("reader-{suffix}");
    let (status, _) = api_json(&app, Method::POST, "/api/v1/users", &admin_token, Some(json!({
        "username": reader_name, "email": format!("{reader_name}@example.com"), "password": "ReaderPass123!", "role": "ReadOnly"
    }))).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = api_json(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        "",
        Some(json!({
            "username": reader_name, "password": "ReaderPass123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let reader_token = serde_json::from_slice::<Value>(&body).unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = api_json(
        &app,
        Method::PUT,
        "/api/v1/integrations/defectdojo",
        &reader_token,
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = api_json(
        &app,
        Method::POST,
        "/api/v1/integrations/defectdojo/sync",
        &reader_token,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // ale odczyt configu i linku jest OK dla ReadOnly
    let (status, _) = api_json(
        &app,
        Method::GET,
        "/api/v1/integrations/defectdojo",
        &reader_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 9. sync manualny enqueue'uje outbox
    let (status, body) = api_json(
        &app,
        Method::POST,
        "/api/v1/integrations/defectdojo/sync",
        &admin_token,
        Some(json!({"asset_group_id": group_id})),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let sync: Value = serde_json::from_slice(&body).unwrap();
    assert!(sync["enqueued"].as_i64().unwrap() >= 1);
}
