use std::time::Duration;

use asi_common::worker::WorkerCapabilities;
use tokio::process::Command;

async fn probe_version(program: &str, args: &[&str]) -> Option<String> {
    let fut = Command::new(program).args(args).output();
    let output = tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .ok()?
        .ok()?;

    let combined = if !output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stdout).to_string()
    } else {
        String::from_utf8_lossy(&output.stderr).to_string()
    };

    combined
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToString::to_string)
}

pub async fn detect_capabilities() -> WorkerCapabilities {
    let (naabu_version, masscan_version, nmap_version, nuclei_version) = tokio::join!(
        probe_version("naabu", &["-version"]),
        probe_version("masscan", &["--version"]),
        probe_version("nmap", &["--version"]),
        probe_version("nuclei", &["-version"]),
    );

    WorkerCapabilities {
        naabu_version,
        masscan_version,
        nmap_version,
        nuclei_version,
        os_arch: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    }
}
