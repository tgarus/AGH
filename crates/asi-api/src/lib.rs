pub mod app;
pub mod audit;
pub mod bootstrap;
pub mod config;
pub mod diff_engine;
pub mod error;
pub mod integrations;
pub mod notifications;
pub mod openapi;
pub mod orchestrator;
pub mod routes;
pub mod security;
pub mod signatures_repo;
pub mod sse;

use sqlx::PgPool;
use utoipa::OpenApi;

use crate::openapi::ApiDoc;

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}

pub fn export_openapi_json() -> Result<String, serde_json::Error> {
    ApiDoc::openapi().to_pretty_json()
}
