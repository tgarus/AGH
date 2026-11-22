#![allow(clippy::unwrap_used, clippy::expect_used)]

use asi_api::app::{build_router, AppState};
use asi_common::error::ProblemDetails;
use asi_common::health::HealthResponse;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn healthz_returns_200_json() {
    let app = build_router(AppState::default(), "http://localhost:5173");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: HealthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.status, "ok");
    assert_eq!(parsed.service, "asi-api");
}

#[tokio::test]
async fn readyz_returns_503_rfc9457_without_db_pool() {
    let app = build_router(AppState::default(), "http://localhost:5173");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/problem+json"
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let problem: ProblemDetails = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem.status, 503);
    assert_eq!(problem.error_code, "SERVICE_UNAVAILABLE");
    assert!(problem.request_id.is_some());
}

#[tokio::test]
async fn openapi_endpoint_contains_health_paths_and_schemas() {
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
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(doc["paths"]["/api/v1/healthz"].is_object());
    assert!(doc["paths"]["/api/v1/readyz"].is_object());
    assert!(doc["components"]["schemas"]["ProblemDetails"].is_object());
    assert!(doc["components"]["schemas"]["Role"].is_object());
}
