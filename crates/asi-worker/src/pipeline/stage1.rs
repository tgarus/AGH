use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use asi_common::validation::expand_port_spec;
use asi_common::worker::{
    ChunkTarget, DiscoveryTool, PolicySnapshot, Stage1PortFinding, WorkerCapabilities,
};
use futures_util::stream::{self, StreamExt};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::process::run_cancellable_command;

#[derive(Debug, Clone)]
pub struct Stage1Outcome {
    pub ports: Vec<Stage1PortFinding>,
    pub probable_tarpit_ips: Vec<IpAddr>,
}

#[derive(Deserialize)]
struct NaabuLine {
    ip: Option<String>,
    host: Option<String>,
    port: u16,
    protocol: Option<String>,
}

#[derive(Deserialize)]
struct MasscanRecord {
    ip: String,
    ports: Vec<MasscanPortEntry>,
}

#[derive(Deserialize)]
struct MasscanPortEntry {
    port: u16,
    proto: Option<String>,
    status: Option<String>,
}

#[must_use]
pub fn parse_naabu_json_lines(stdout: &str) -> Vec<Stage1PortFinding> {
    let mut seen = BTreeSet::new();
    let mut results = Vec::new();
    for line in stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Ok(parsed) = serde_json::from_str::<NaabuLine>(line) else {
            continue;
        };
        let Some(ip_str) = parsed.ip.or(parsed.host) else {
            continue;
        };
        let Ok(ip_addr) = ip_str.parse::<IpAddr>() else {
            continue;
        };
        let protocol = parsed
            .protocol
            .unwrap_or_else(|| "tcp".to_string())
            .to_ascii_lowercase();
        if seen.insert((ip_addr, parsed.port, protocol.clone())) {
            results.push(Stage1PortFinding {
                ip_addr,
                port: parsed.port,
                protocol,
            });
        }
    }
    results
}

#[must_use]
pub fn parse_masscan_json(stdout: &str) -> Vec<Stage1PortFinding> {
    let cleaned = stdout.trim().replace(",\n]", "\n]").replace(",]", "]");
    let Ok(records) = serde_json::from_str::<Vec<MasscanRecord>>(&cleaned) else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut results = Vec::new();
    for rec in records {
        let Ok(ip_addr) = rec.ip.parse::<IpAddr>() else {
            continue;
        };
        for p in rec.ports {
            if p.status.as_deref().unwrap_or("open") != "open" {
                continue;
            }
            let protocol = p
                .proto
                .unwrap_or_else(|| "tcp".to_string())
                .to_ascii_lowercase();
            if seen.insert((ip_addr, p.port, protocol.clone())) {
                results.push(Stage1PortFinding {
                    ip_addr,
                    port: p.port,
                    protocol,
                });
            }
        }
    }
    results
}

/// Applies the Tarpit Guard threshold WITHOUT silently truncating discovered ports.
#[must_use]
pub fn apply_tarpit_guard(
    findings: Vec<Stage1PortFinding>,
    tarpit_threshold: u32,
) -> Stage1Outcome {
    let mut counts: HashMap<IpAddr, u32> = HashMap::new();
    for f in &findings {
        let entry = counts.entry(f.ip_addr).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    let mut probable_tarpit_ips: Vec<IpAddr> = counts
        .into_iter()
        .filter_map(|(ip, cnt)| (cnt > tarpit_threshold).then_some(ip))
        .collect();
    probable_tarpit_ips.sort();

    Stage1Outcome {
        ports: findings,
        probable_tarpit_ips,
    }
}

pub async fn run_stage1(
    targets: &[ChunkTarget],
    policy: &PolicySnapshot,
    caps: &WorkerCapabilities,
    allow_local_mock_lab: bool,
    cancel: CancellationToken,
) -> Result<Stage1Outcome> {
    if targets.is_empty() {
        return Ok(Stage1Outcome {
            ports: Vec::new(),
            probable_tarpit_ips: Vec::new(),
        });
    }

    let grace = Duration::from_secs(policy.kill_grace_seconds.clamp(1, 10));
    let findings = match policy.discovery_tool {
        DiscoveryTool::Naabu if caps.naabu_version.is_some() => {
            run_naabu(targets, policy, grace, cancel.clone()).await?
        }
        DiscoveryTool::Masscan if caps.masscan_version.is_some() => {
            run_masscan(targets, policy, grace, cancel.clone()).await?
        }
        _ if caps.naabu_version.is_some() => {
            run_naabu(targets, policy, grace, cancel.clone()).await?
        }
        _ if allow_local_mock_lab => {
            tracing::warn!(
                "naabu/masscan binary not found; using rate-limited Tokio TCP connect fallback for Mock-Lab"
            );
            run_tcp_connect_fallback(targets, policy, cancel.clone()).await?
        }
        _ => {
            bail!(
                "No Stage 1 discovery binary (naabu/masscan) found on PATH and ASI_ALLOW_LOCAL_MOCK_LAB is false."
            );
        }
    };

    Ok(apply_tarpit_guard(findings, policy.tarpit_port_threshold))
}

async fn write_targets_temp_file(targets: &[ChunkTarget]) -> Result<std::path::PathBuf> {
    let path = std::env::temp_dir().join(format!("asi-stage1-{}.txt", Uuid::new_v4()));
    let content: String = targets
        .iter()
        .map(|t| t.ip_addr.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    tokio::fs::write(&path, content)
        .await
        .with_context(|| format!("failed to write temp targets file {}", path.display()))?;
    Ok(path)
}

async fn run_naabu(
    targets: &[ChunkTarget],
    policy: &PolicySnapshot,
    grace: Duration,
    cancel: CancellationToken,
) -> Result<Vec<Stage1PortFinding>> {
    let target_file = write_targets_temp_file(targets).await?;
    let target_path_str = target_file.to_string_lossy().to_string();
    let rate_str = policy.rate_pps.max(1).to_string();

    let mut args = vec![
        "-list",
        target_path_str.as_str(),
        "-silent",
        "-json",
        "-rate",
        rate_str.as_str(),
    ];

    let spec = policy.port_spec.trim().to_ascii_lowercase();
    if spec == "top-100" {
        args.extend(["-top-ports", "100"]);
    } else if spec == "top-1000" {
        args.extend(["-top-ports", "1000"]);
    } else {
        args.extend(["-p", spec.as_str()]);
    }

    let output = run_cancellable_command("naabu", &args, cancel, grace).await;
    let _ = tokio::fs::remove_file(&target_file).await;
    let output = output?;
    if output.cancelled {
        bail!("Stage 1 naabu cancelled by Hard Kill Switch");
    }
    Ok(parse_naabu_json_lines(&output.stdout))
}

async fn run_masscan(
    targets: &[ChunkTarget],
    policy: &PolicySnapshot,
    grace: Duration,
    cancel: CancellationToken,
) -> Result<Vec<Stage1PortFinding>> {
    let target_file = write_targets_temp_file(targets).await?;
    let target_path_str = target_file.to_string_lossy().to_string();
    let rate_str = policy.rate_pps.max(1).to_string();
    let port_spec = if matches!(policy.port_spec.as_str(), "top-100" | "top-1000") {
        "1-1024".to_string()
    } else {
        policy.port_spec.clone()
    };

    let args = [
        "-iL",
        target_path_str.as_str(),
        "-p",
        port_spec.as_str(),
        "--rate",
        rate_str.as_str(),
        "-oJ",
        "-",
    ];

    let output = run_cancellable_command("masscan", &args, cancel, grace).await;
    let _ = tokio::fs::remove_file(&target_file).await;
    let output = output?;
    if output.cancelled {
        bail!("Stage 1 masscan cancelled by Hard Kill Switch");
    }
    Ok(parse_masscan_json(&output.stdout))
}

async fn run_tcp_connect_fallback(
    targets: &[ChunkTarget],
    policy: &PolicySnapshot,
    cancel: CancellationToken,
) -> Result<Vec<Stage1PortFinding>> {
    let ports = expand_port_spec(&policy.port_spec)
        .map_err(|msg| anyhow::anyhow!("invalid port_spec in policy: {msg}"))?;

    let mut pairs = Vec::new();
    for target in targets {
        for &port in &ports {
            pairs.push((target.ip_addr, port));
        }
    }

    let concurrency = usize::try_from(policy.rate_pps.clamp(1, 64)).unwrap_or(32);
    let results = stream::iter(pairs)
        .map(|(ip_addr, port)| {
            let token = cancel.clone();
            async move {
                if token.is_cancelled() {
                    return None;
                }
                let addr = SocketAddr::new(ip_addr, port);
                let conn = tokio::select! {
                    () = token.cancelled() => return None,
                    res = tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(addr)) => res,
                };
                match conn {
                    Ok(Ok(_stream)) => Some(Stage1PortFinding {
                        ip_addr,
                        port,
                        protocol: "tcp".to_string(),
                    }),
                    _ => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    if cancel.is_cancelled() {
        bail!("Stage 1 fallback cancelled by Hard Kill Switch");
    }

    Ok(results.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_naabu_ndjson() {
        let raw = r#"
{"host":"172.28.0.10","ip":"172.28.0.10","port":80,"protocol":"tcp"}
{"host":"172.28.0.11","ip":"172.28.0.11","port":8888}
"#;
        let parsed = parse_naabu_json_lines(raw);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].port, 8888);
        assert_eq!(parsed[1].protocol, "tcp");
    }

    #[test]
    fn parses_masscan_json() {
        let raw = r#"[
{"ip": "172.28.0.10", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]},
]"#;
        let parsed = parse_masscan_json(raw);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].port, 443);
    }

    #[test]
    fn tarpit_guard_preserves_all_ports_while_flagging_host() {
        let tarpit_ip: IpAddr = "172.28.0.15".parse().unwrap();
        let findings: Vec<Stage1PortFinding> = (10001..=10220)
            .map(|port| Stage1PortFinding {
                ip_addr: tarpit_ip,
                port,
                protocol: "tcp".to_string(),
            })
            .collect();

        let outcome = apply_tarpit_guard(findings, 200);
        // Zero silent port truncation: all 220 ports preserved
        assert_eq!(outcome.ports.len(), 220);
        assert_eq!(outcome.probable_tarpit_ips, vec![tarpit_ip]);
    }
}
