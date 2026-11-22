use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use asi_common::signatures::builtin_default_signatures_yaml;
use asi_common::worker::{
    ChunkLeaseRequest, ChunkReleaseRequest, ControlDirective, HeartbeatRequest, WorkerControlEvent,
    WorkerRegisterRequest,
};
use asi_worker::capabilities::detect_capabilities;
use asi_worker::client::WorkerApiClient;
use asi_worker::config::{WorkerConfig, WorkerLogFormat};
use asi_worker::pipeline::run_chunk_pipeline;
use asi_worker::pipeline::stage3::{compile_templates, CompiledTemplate};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

type ActiveMap = Arc<Mutex<HashMap<Uuid, (Uuid, CancellationToken)>>>;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--check-capabilities") {
        let caps = detect_capabilities().await;
        let json = serde_json::to_string_pretty(&caps)?;
        println!("{json}");
        return Ok(());
    }

    let config = WorkerConfig::from_env();
    init_tracing(config.log_format);

    let caps = detect_capabilities().await;
    tracing::info!(?config, capabilities = ?caps, "starting asi-worker");

    if config.worker_token.is_none() {
        tracing::warn!("ASI_WORKER_TOKEN is not set; worker supervisor cannot lease chunks yet");
    }

    let client = WorkerApiClient::new(config.api_url.clone(), config.worker_token.clone())?;
    let shutdown = CancellationToken::new();
    let signal_token = shutdown.clone();
    tokio::spawn(async move {
        wait_for_shutdown(signal_token).await;
    });

    // Retry registration until shutdown
    let reg = loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let req = WorkerRegisterRequest {
            name: config.worker_name.clone(),
            segment_tag: config.segment_tag.clone(),
            max_concurrency: config.max_concurrency,
            capabilities: caps.clone(),
        };
        match client.register(&req).await {
            Ok(resp) => {
                tracing::info!(worker_id = %resp.worker_id, "registered worker with asi-api");
                break resp;
            }
            Err(err) => {
                tracing::warn!(error = %err, "worker registration failed; retrying in 5s");
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    () = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    };

    let initial_templates: Arc<Vec<CompiledTemplate>> = match client.fetch_signatures().await {
        Ok(sig_resp) => {
            let compiled = compile_templates(&sig_resp.yaml_rules);
            tracing::info!(count = compiled.len(), hash = %sig_resp.version_hash, "loaded FingerprintHub v4 signatures");
            Arc::new(compiled)
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to fetch signatures from api; falling back to builtins");
            Arc::new(compile_templates(&builtin_default_signatures_yaml()))
        }
    };
    let compiled_templates = Arc::new(std::sync::RwLock::new(initial_templates));

    let active_chunks: ActiveMap = Arc::new(Mutex::new(HashMap::new()));
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<WorkerControlEvent>(64);

    let ctrl_client = client.clone();
    let ctrl_shutdown = shutdown.clone();
    tokio::spawn(async move {
        ctrl_client
            .stream_control_events(ctrl_tx, ctrl_shutdown)
            .await;
    });

    let ctrl_active = Arc::clone(&active_chunks);
    let reload_client = client.clone();
    let reload_templates = Arc::clone(&compiled_templates);
    tokio::spawn(async move {
        while let Some(ev) = ctrl_rx.recv().await {
            if ev.action == "reload_signatures" {
                match reload_client.fetch_signatures().await {
                    Ok(sig_resp) => {
                        let next = Arc::new(compile_templates(&sig_resp.yaml_rules));
                        let count = next.len();
                        if let Ok(mut guard) = reload_templates.write() {
                            *guard = next;
                        }
                        tracing::info!(count, hash = %sig_resp.version_hash, "hot-reloaded FingerprintHub v4 signatures");
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to hot-reload signatures from api");
                    }
                }
                continue;
            }
            if let Ok(guard) = ctrl_active.lock() {
                for (&chunk_id, &(scan_run_id, ref token)) in guard.iter() {
                    let matches_run = ev.scan_run_id.is_some_and(|id| id == scan_run_id);
                    let matches_chunk = ev.chunk_id.is_some_and(|id| id == chunk_id);
                    if matches_run || matches_chunk {
                        tracing::info!(action = %ev.action, %scan_run_id, %chunk_id, "triggering Hard Kill Switch from SSE");
                        token.cancel();
                    }
                }
            }
        }
    });

    let hb_interval = Duration::from_secs(reg.heartbeat_interval_seconds.max(5));

    while !shutdown.is_cancelled() {
        let lease_req = ChunkLeaseRequest {
            worker_id: reg.worker_id,
            max_chunks: 1,
        };

        let lease = match client.lease_chunk(&lease_req).await {
            Ok(Some(lease)) => lease,
            Ok(None) => {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(3)) => continue,
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "chunk lease failed; retrying in 5s");
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(5)) => continue,
                }
            }
        };

        let chunk_id = lease.chunk_id;
        let scan_run_id = lease.scan_run_id;
        let attempt_no = lease.attempt_no;
        let chunk_cancel = shutdown.child_token();

        if let Ok(mut guard) = active_chunks.lock() {
            guard.insert(chunk_id, (scan_run_id, chunk_cancel.clone()));
        }

        // Background heartbeat loop for this leased chunk
        let hb_client = client.clone();
        let hb_cancel = chunk_cancel.clone();
        let hb_worker_id = reg.worker_id;
        let hb_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = hb_cancel.cancelled() => break,
                    () = tokio::time::sleep(hb_interval) => {}
                }
                let req = HeartbeatRequest {
                    worker_id: hb_worker_id,
                    attempt_no,
                    stage_label: "running".to_string(),
                };
                match hb_client.heartbeat(chunk_id, &req).await {
                    Ok(resp) => {
                        if !matches!(resp.directive, ControlDirective::Continue) {
                            tracing::info!(directive = ?resp.directive, %chunk_id, "heartbeat directive stopping chunk");
                            hb_cancel.cancel();
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, %chunk_id, "heartbeat failed");
                    }
                }
            }
        });

        let current_templates = compiled_templates
            .read()
            .map(|g| Arc::clone(&*g))
            .unwrap_or_else(|_| Arc::new(Vec::new()));

        let pipeline_res = run_chunk_pipeline(
            reg.worker_id,
            &lease,
            &caps,
            &current_templates,
            config.allow_local_mock_lab,
            chunk_cancel.clone(),
        )
        .await;

        let was_cancelled = chunk_cancel.is_cancelled() || shutdown.is_cancelled();
        chunk_cancel.cancel();
        let _ = hb_handle.await;

        if let Ok(mut guard) = active_chunks.lock() {
            guard.remove(&chunk_id);
        }

        match pipeline_res {
            Ok(submission) if !was_cancelled => {
                if let Err(err) = client.submit_results(chunk_id, &submission).await {
                    tracing::error!(error = %err, %chunk_id, "failed to submit chunk results");
                }
            }
            Ok(_) => {
                let release_req = ChunkReleaseRequest {
                    worker_id: reg.worker_id,
                    attempt_no,
                    reason: "cancelled_by_control_signal".to_string(),
                };
                let _ = client.release_chunk(chunk_id, &release_req).await;
            }
            Err(err) => {
                let release_req = ChunkReleaseRequest {
                    worker_id: reg.worker_id,
                    attempt_no,
                    reason: err.to_string(),
                };
                let _ = client.release_chunk(chunk_id, &release_req).await;
            }
        }
    }

    tracing::info!("asi-worker stopped cleanly");
    Ok(())
}

fn init_tracing(format: WorkerLogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        WorkerLogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        WorkerLogFormat::Pretty => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }
}

async fn wait_for_shutdown(token: CancellationToken) {
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
    token.cancel();
}
