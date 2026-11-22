use std::process::Stdio;
use std::time::Duration;

use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub cancelled: bool,
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("failed to spawn command '{program}': {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("process execution I/O error: {0}")]
    Io(#[from] std::io::Error),
}

async fn read_pipe<R: AsyncReadExt + Unpin>(mut pipe: R) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = pipe.read_to_end(&mut buf).await;
    buf
}

/// Runs an external scanner binary inside its own OS process group and enforces the
/// Hard Kill Switch (SIGTERM -> grace period -> SIGKILL) when `cancel` is triggered.
pub async fn run_cancellable_command(
    program: &str,
    args: &[&str],
    cancel: CancellationToken,
    grace: Duration,
) -> Result<ProcessOutput, ProcessError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    {
        #[allow(unsafe_code)]
        // SAFETY: setsid() is async-signal-safe and isolates the spawned scanner
        // into its own process group so Hard Kill Switch can terminate the full tree.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn().map_err(|source| ProcessError::Spawn {
        program: program.to_string(),
        source,
    })?;

    let child_pid = child.id();

    let stdout_task = child
        .stdout
        .take()
        .map(|pipe| tokio::spawn(read_pipe(pipe)));
    let stderr_task = child
        .stderr
        .take()
        .map(|pipe| tokio::spawn(read_pipe(pipe)));

    let (exit_code, cancelled) = tokio::select! {
        wait_res = child.wait() => {
            let status = wait_res?;
            (status.code(), false)
        }
        () = cancel.cancelled() => {
            terminate_process_group(&mut child, child_pid, grace).await;
            (None, true)
        }
    };

    let stdout_bytes = match stdout_task {
        Some(handle) => handle.await.unwrap_or_default(),
        None => Vec::new(),
    };
    let stderr_bytes = match stderr_task {
        Some(handle) => handle.await.unwrap_or_default(),
        None => Vec::new(),
    };

    Ok(ProcessOutput {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        cancelled,
    })
}

async fn terminate_process_group(
    child: &mut tokio::process::Child,
    child_pid: Option<u32>,
    grace: Duration,
) {
    #[cfg(unix)]
    if let Some(pgid) = child_pid.and_then(|pid| libc::pid_t::try_from(pid).ok()) {
        #[allow(unsafe_code)]
        // SAFETY: pgid equals the child PID created via setsid() in pre_exec.
        unsafe {
            let _ = libc::killpg(pgid, libc::SIGTERM);
        }

        if tokio::time::timeout(grace, child.wait()).await.is_ok() {
            return;
        }

        #[allow(unsafe_code)]
        // SAFETY: grace period elapsed; SIGKILL guarantees immediate termination of process group.
        unsafe {
            let _ = libc::killpg(pgid, libc::SIGKILL);
        }
        let _ = child.wait().await;
    }

    #[cfg(not(unix))]
    {
        let _ = child_pid;
        let _ = tokio::time::timeout(grace, child.wait()).await;
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_kill_switch_terminates_long_running_process_within_grace() {
        let cancel = CancellationToken::new();
        let child_cancel = cancel.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            child_cancel.cancel();
        });

        let started = Instant::now();
        let output = run_cancellable_command("sleep", &["30"], cancel, Duration::from_millis(200))
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert!(output.cancelled);
        assert_eq!(output.exit_code, None);
        assert!(
            elapsed < Duration::from_secs(2),
            "expected cancellation within <2s, took {elapsed:?}"
        );
    }
}
