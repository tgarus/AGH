use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use asi_common::assets::{IgnoredTargetType, TargetType};
use asi_common::scans::PreflightResponse;
use asi_common::validation::estimate_port_count;
use asi_common::worker::ChunkTarget;
use ipnetwork::IpNetwork;
use uuid::Uuid;

const TARGET_CHUNK_SECONDS: u32 = 45;
const MIN_CHUNK_SIZE: u32 = 4;
const MAX_CHUNK_SIZE: u32 = 64;
const MAX_EXPANDED_HOSTS_PER_SCAN: usize = 131_072;
const CHUNK_OVERHEAD_SECONDS: f64 = 2.5;
const EMA_ALPHA: f64 = 0.25;

#[derive(Debug, Clone)]
pub struct TargetEntry {
    pub target_type: TargetType,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct IgnoredEntry {
    pub target_type: IgnoredTargetType,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct PlannedChunk {
    pub sequence_no: i32,
    pub subnet_bucket: String,
    pub targets: Vec<ChunkTarget>,
}

#[derive(Debug, Clone)]
pub struct SlicePlan {
    pub total_targets: u32,
    pub chunk_size: u32,
    pub estimated_ports: u32,
    pub chunks: Vec<PlannedChunk>,
    pub excluded_cidrs: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn slice_targets(
    targets: &[TargetEntry],
    ignored: &[IgnoredEntry],
    port_spec: &str,
    rate_pps: u32,
) -> Result<SlicePlan, String> {
    slice_targets_with_resolver(targets, ignored, port_spec, rate_pps, resolve_domain_std)
}

fn resolve_domain_std(domain: &str) -> Vec<IpAddr> {
    let host_port = format!("{domain}:80");
    match host_port.to_socket_addrs() {
        Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

pub fn slice_targets_with_resolver<F>(
    targets: &[TargetEntry],
    ignored: &[IgnoredEntry],
    port_spec: &str,
    rate_pps: u32,
    mut resolver: F,
) -> Result<SlicePlan, String>
where
    F: FnMut(&str) -> Vec<IpAddr>,
{
    let mut exclude_nets = Vec::<IpNetwork>::new();
    let mut excluded_cidrs = Vec::<String>::new();
    let mut ignored_ips = BTreeSet::<IpAddr>::new();
    let mut ignored_domains = BTreeSet::<String>::new();

    for entry in targets {
        if entry.target_type == TargetType::ExcludeCidr {
            if let Ok(net) = entry.value.parse::<IpNetwork>() {
                exclude_nets.push(net);
                excluded_cidrs.push(entry.value.clone());
            }
        }
    }

    for entry in ignored {
        match entry.target_type {
            IgnoredTargetType::Ip => {
                if let Ok(ip) = entry.value.parse::<IpAddr>() {
                    ignored_ips.insert(ip);
                }
            }
            IgnoredTargetType::Cidr => {
                if let Ok(net) = entry.value.parse::<IpNetwork>() {
                    exclude_nets.push(net);
                    excluded_cidrs.push(entry.value.clone());
                }
            }
            IgnoredTargetType::Domain => {
                ignored_domains.insert(entry.value.to_ascii_lowercase());
            }
        }
    }

    let mut warnings = Vec::new();
    let mut ip_vhosts: BTreeMap<IpAddr, BTreeSet<String>> = BTreeMap::new();

    for entry in targets {
        match entry.target_type {
            TargetType::ExcludeCidr => {}
            TargetType::Ip => {
                if let Ok(ip) = entry.value.parse::<IpAddr>() {
                    ip_vhosts.entry(ip).or_default();
                }
            }
            TargetType::Cidr => {
                let net: IpNetwork = entry
                    .value
                    .parse()
                    .map_err(|_| format!("Invalid CIDR '{}'", entry.value))?;
                match net {
                    IpNetwork::V4(v4) => {
                        let count = v4.size() as usize;
                        if ip_vhosts.len().saturating_add(count) > MAX_EXPANDED_HOSTS_PER_SCAN {
                            return Err(format!(
                                "Target expansion exceeds safety limit of {MAX_EXPANDED_HOSTS_PER_SCAN} IPs."
                            ));
                        }
                        for ip in v4.iter() {
                            // For /24 and larger networks, omit network and broadcast addresses.
                            // Smaller ranges (/25../32) often slice a /24 and hold real hosts on boundaries.
                            if v4.prefix() <= 24 && (ip == v4.network() || ip == v4.broadcast()) {
                                continue;
                            }
                            ip_vhosts.entry(IpAddr::V4(ip)).or_default();
                        }
                    }
                    IpNetwork::V6(v6) => {
                        if v6.prefix() < 120 {
                            return Err(format!(
                                "IPv6 CIDR '{}' is too broad to expand; use /120../128.",
                                entry.value
                            ));
                        }
                        for ip in v6.iter() {
                            ip_vhosts.entry(IpAddr::V6(ip)).or_default();
                        }
                    }
                }
            }
            TargetType::Domain => {
                let norm = entry.value.to_ascii_lowercase();
                if ignored_domains.contains(&norm) {
                    continue;
                }
                let resolved = resolver(&norm);
                if resolved.is_empty() {
                    warnings.push(format!(
                        "Domain '{norm}' did not resolve to an IP address and was skipped."
                    ));
                } else {
                    for ip in resolved {
                        ip_vhosts.entry(ip).or_default().insert(norm.clone());
                    }
                }
            }
        }
    }

    // Apply IP and CIDR exclusions
    let mut filtered_targets: Vec<ChunkTarget> = Vec::new();
    for (ip, vhosts) in ip_vhosts {
        if ignored_ips.contains(&ip) || exclude_nets.iter().any(|net| net.contains(ip)) {
            continue;
        }
        let active_vhosts: Vec<String> = vhosts
            .into_iter()
            .filter(|vh| !ignored_domains.contains(vh))
            .collect();
        filtered_targets.push(ChunkTarget {
            ip_addr: ip,
            vhosts: active_vhosts,
        });
    }

    let total_targets = u32::try_from(filtered_targets.len()).unwrap_or(u32::MAX);
    let estimated_ports = estimate_port_count(port_spec);
    let raw_chunk_size = rate_pps
        .saturating_mul(TARGET_CHUNK_SECONDS)
        .checked_div(estimated_ports.max(1))
        .unwrap_or(MIN_CHUNK_SIZE);
    let chunk_size = raw_chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);

    if filtered_targets.is_empty() {
        warnings.push(
            "No scannable targets remain after applying exclusions and ignored list.".to_string(),
        );
    }

    // Group by subnet bucket and interleave chunks round-robin across buckets
    let mut by_bucket: BTreeMap<String, Vec<ChunkTarget>> = BTreeMap::new();
    for tgt in filtered_targets {
        let bucket = subnet_bucket_for(tgt.ip_addr);
        by_bucket.entry(bucket).or_default().push(tgt);
    }

    let mut bucket_queues: Vec<VecDeque<(String, Vec<ChunkTarget>)>> = by_bucket
        .into_iter()
        .map(|(bucket, items)| {
            let slice_len = usize::try_from(chunk_size).unwrap_or(16).max(1);
            items
                .chunks(slice_len)
                .map(|chunk| (bucket.clone(), chunk.to_vec()))
                .collect()
        })
        .collect();

    let mut chunks = Vec::new();
    let mut seq = 1_i32;
    loop {
        let mut progressed = false;
        for q in &mut bucket_queues {
            if let Some((bucket, targets)) = q.pop_front() {
                chunks.push(PlannedChunk {
                    sequence_no: seq,
                    subnet_bucket: bucket,
                    targets,
                });
                seq = seq.saturating_add(1);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    Ok(SlicePlan {
        total_targets,
        chunk_size,
        estimated_ports,
        chunks,
        excluded_cidrs,
        warnings,
    })
}

#[must_use]
pub fn subnet_bucket_for(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3])
        }
    }
}

#[must_use]
pub fn compute_preflight(
    asset_group_id: Uuid,
    plan: &SlicePlan,
    rate_pps: u32,
    window_minutes: u32,
) -> PreflightResponse {
    let total_chunks = u32::try_from(plan.chunks.len()).unwrap_or(u32::MAX);
    let packet_time = (f64::from(plan.total_targets) * f64::from(plan.estimated_ports))
        / f64::from(rate_pps.max(1));
    let overhead_time = f64::from(total_chunks) * CHUNK_OVERHEAD_SECONDS;
    let total_est = (packet_time + overhead_time).ceil();
    let estimated_duration_seconds = if total_est.is_finite() && total_est >= 0.0 {
        total_est as u64
    } else {
        0
    };

    let window_seconds = u64::from(window_minutes.max(1)).saturating_mul(60);
    let fits_in_window = estimated_duration_seconds <= window_seconds;
    let mut warnings = plan.warnings.clone();
    if !fits_in_window {
        warnings.push(format!(
            "Estimated scan duration ({estimated_duration_seconds}s) exceeds configured window ({window_seconds}s); scan will pause and resume across windows."
        ));
    }

    PreflightResponse {
        asset_group_id,
        total_targets: plan.total_targets,
        total_chunks,
        chunk_size: plan.chunk_size,
        estimated_ports_per_host: plan.estimated_ports,
        estimated_duration_seconds,
        fits_in_window,
        warnings,
        matched_ignored_targets: Vec::new(),
        overridden_ignored_count: 0,
    }
}

#[must_use]
pub fn update_ema_ms(previous: Option<f64>, sample_ms: u64) -> f64 {
    let sample = sample_ms as f64;
    match previous {
        Some(prev) if prev.is_finite() && prev > 0.0 => {
            EMA_ALPHA * sample + (1.0 - EMA_ALPHA) * prev
        }
        _ => sample,
    }
}

#[must_use]
pub fn estimate_eta_seconds(remaining_chunks: u32, ema_ms: f64) -> u64 {
    if remaining_chunks == 0 || !ema_ms.is_finite() || ema_ms <= 0.0 {
        return 0;
    }
    let total_secs = (f64::from(remaining_chunks) * ema_ms) / 1000.0;
    total_secs.ceil().max(0.0) as u64
}

pub fn expand_ipv4_single(ip: Ipv4Addr) -> IpAddr {
    IpAddr::V4(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtracts_exclusions_and_merges_vhosts() {
        let targets = vec![
            TargetEntry {
                target_type: TargetType::Cidr,
                value: "172.28.0.8/29".to_string(), // .8..15
            },
            TargetEntry {
                target_type: TargetType::ExcludeCidr,
                value: "172.28.0.12/30".to_string(), // excludes .12..15
            },
            TargetEntry {
                target_type: TargetType::Domain,
                value: "app1.lab.local".to_string(),
            },
            TargetEntry {
                target_type: TargetType::Domain,
                value: "staging.lab.local".to_string(),
            },
        ];
        let ignored = vec![IgnoredEntry {
            target_type: IgnoredTargetType::Ip,
            value: "172.28.0.10".to_string(),
        }];

        let plan = slice_targets_with_resolver(&targets, &ignored, "80,443", 500, |domain| {
            if domain == "app1.lab.local" || domain == "staging.lab.local" {
                vec!["172.28.0.11".parse().unwrap()]
            } else {
                vec![]
            }
        })
        .unwrap();

        let all_ips: Vec<IpAddr> = plan
            .chunks
            .iter()
            .flat_map(|c| c.targets.iter().map(|t| t.ip_addr))
            .collect();

        // .8, .9, .11 remain (.10 ignored, .12..15 excluded)
        assert_eq!(all_ips.len(), 3);
        assert!(!all_ips.contains(&"172.28.0.10".parse().unwrap()));
        assert!(!all_ips.contains(&"172.28.0.12".parse().unwrap()));

        let vhost_target = plan
            .chunks
            .iter()
            .flat_map(|c| c.targets.iter())
            .find(|t| t.ip_addr == "172.28.0.11".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!(
            vhost_target.vhosts,
            vec!["app1.lab.local", "staging.lab.local"]
        );
    }

    #[test]
    fn interleaves_chunks_across_subnets_and_clamps_size() {
        let targets = vec![
            TargetEntry {
                target_type: TargetType::Cidr,
                value: "10.1.0.0/26".to_string(),
            },
            TargetEntry {
                target_type: TargetType::Cidr,
                value: "10.2.0.0/26".to_string(),
            },
        ];

        let plan = slice_targets_with_resolver(&targets, &[], "1-65535", 500, |_| vec![]).unwrap();
        // Low rate over 65535 ports clamps to MIN_CHUNK_SIZE = 4
        assert_eq!(plan.chunk_size, 4);
        assert!(plan.chunks.len() >= 4);
        assert_eq!(plan.chunks[0].subnet_bucket, "10.1.0.0/24");
        assert_eq!(plan.chunks[1].subnet_bucket, "10.2.0.0/24");
        assert_eq!(plan.chunks[2].subnet_bucket, "10.1.0.0/24");
    }

    #[test]
    fn updates_ema_and_estimates_preflight() {
        let ema1 = update_ema_ms(None, 10_000);
        assert!((ema1 - 10_000.0).abs() < 0.01);
        let ema2 = update_ema_ms(Some(ema1), 14_000);
        assert!((ema2 - 11_000.0).abs() < 0.01);
        assert_eq!(estimate_eta_seconds(3, ema2), 33);
    }

    #[test]
    fn omits_network_and_broadcast_for_slash_24_and_larger() {
        let targets = vec![TargetEntry {
            target_type: TargetType::Cidr,
            value: "172.28.0.0/24".to_string(),
        }];
        let plan = slice_targets_with_resolver(&targets, &[], "80", 500, |_| vec![]).unwrap();
        let all_ips: Vec<IpAddr> = plan
            .chunks
            .iter()
            .flat_map(|c| c.targets.iter().map(|t| t.ip_addr))
            .collect();
        assert_eq!(all_ips.len(), 254);
        assert!(!all_ips.contains(&"172.28.0.0".parse().unwrap()));
        assert!(!all_ips.contains(&"172.28.0.255".parse().unwrap()));
        assert!(all_ips.contains(&"172.28.0.1".parse().unwrap()));
        assert!(all_ips.contains(&"172.28.0.254".parse().unwrap()));
    }
}
