pub mod favicon;
pub mod stage1;
pub mod stage2;
pub mod stage3;

use std::time::{Duration, Instant};

use anyhow::Result;
use asi_common::worker::{ChunkLeaseResponse, ChunkResultsSubmission, WorkerCapabilities};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::guard::TargetGuard;
use crate::pipeline::stage1::run_stage1;
use crate::pipeline::stage2::run_stage2;
use crate::pipeline::stage3::{run_stage3, CompiledTemplate};

pub async fn run_chunk_pipeline(
    worker_id: Uuid,
    lease: &ChunkLeaseResponse,
    caps: &WorkerCapabilities,
    compiled_templates: &[CompiledTemplate],
    allow_local_mock_lab: bool,
    cancel: CancellationToken,
) -> Result<ChunkResultsSubmission> {
    let started = Instant::now();
    let guard = TargetGuard::new(&lease.excluded_cidrs, allow_local_mock_lab);
    let safe_targets = guard.filter_targets(&lease.targets);

    let stage1 = run_stage1(
        &safe_targets,
        &lease.policy,
        caps,
        allow_local_mock_lab,
        cancel.clone(),
    )
    .await?;

    if lease.policy.per_ip_cooldown_ms > 0 && !cancel.is_cancelled() {
        tokio::select! {
            () = cancel.cancelled() => {}
            () = tokio::time::sleep(Duration::from_millis(lease.policy.per_ip_cooldown_ms.min(2000))) => {}
        }
    }

    let stage2_services = run_stage2(
        &safe_targets,
        &stage1.ports,
        &stage1.probable_tarpit_ips,
        &lease.policy,
        caps,
        cancel.clone(),
    )
    .await;

    let stage3_observations = run_stage3(
        &safe_targets,
        &stage2_services,
        compiled_templates,
        &lease.policy,
        caps,
        cancel.clone(),
    )
    .await;

    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    Ok(ChunkResultsSubmission {
        worker_id,
        attempt_no: lease.attempt_no,
        duration_ms,
        probable_tarpit_ips: stage1.probable_tarpit_ips,
        stage1_ports: stage1.ports,
        stage2_services,
        stage3_observations,
    })
}
