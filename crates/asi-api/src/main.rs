use std::path::PathBuf;

use anyhow::{Context, Result};
use asi_api::app::{build_router, AppState};
use asi_api::bootstrap::bootstrap_initial_admin;
use asi_api::config::{ApiConfig, LogFormat};
use asi_api::{export_openapi_json, run_migrations};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();

    if let Some(pos) = args.iter().position(|a| a == "--export-openapi") {
        let out_path = args
            .get(pos + 1)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("docs/openapi.json"));
        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create directory {}", parent.display()))?;
            }
        }
        let json = export_openapi_json().context("failed to serialize OpenAPI document")?;
        std::fs::write(&out_path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", out_path.display()))?;
        println!("Exported OpenAPI schema to {}", out_path.display());
        return Ok(());
    }

    let migrate_only = args.iter().any(|a| a == "--migrate-only");
    let config = ApiConfig::from_env()?;
    init_tracing(config.log_format);

    tracing::info!(?config, "starting asi-api");

    let db_url = config
        .database_url
        .as_deref()
        .context("DATABASE_URL must be set when starting asi-api")?;

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(db_url)
        .await
        .context("failed to connect to PostgreSQL")?;

    if config.auto_migrate || migrate_only {
        run_migrations(&pool)
            .await
            .context("failed to apply SQLx database migrations")?;
        tracing::info!("database migrations verified");
    }

    bootstrap_initial_admin(&pool, &config).await?;

    if migrate_only {
        return Ok(());
    }

    let state = AppState::from_config(Some(pool), &config)?;
    let _scheduler = asi_api::orchestrator::scheduler::spawn_scheduler(state.clone());
    let _notifier = asi_api::notifications::worker::spawn_notification_worker(state.clone());
    let (_dd_outbox, _dd_pull) = asi_api::integrations::worker::spawn_dd_workers(state.clone());

    // Opcjonalny sync sygnatur FingerprintHub z repo przy starcie (nie blokuje startu;
    // przy braku sieci zostają wbudowane — patrz ASI_FINGERPRINTHUB_SYNC_ON_STARTUP).
    if config.sig_sync.sync_on_startup {
        if let Some(pool) = state.db.clone() {
            let sig_cfg = config.sig_sync.clone();
            tokio::spawn(async move {
                match asi_api::routes::signatures::run_signature_sync(
                    &pool, &sig_cfg, None, None, None,
                )
                .await
                {
                    Ok(stats) => {
                        tracing::info!(
                            builtin = stats.builtin_count,
                            repo = stats.repo_count,
                            skipped = stats.skipped_count,
                            source = %stats.source,
                            "startup FingerprintHub sync done"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(error = ?err, "startup FingerprintHub sync failed");
                    }
                }
            });
        }
    }

    let router = build_router(state, &config.cors_origin);

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;

    tracing::info!(addr = %config.bind_addr, "asi-api listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("asi-api server exited unexpectedly")?;

    Ok(())
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to listen for Ctrl+C");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}
