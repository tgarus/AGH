use std::net::IpAddr;

use asi_common::worker::ChunkTarget;
use ipnetwork::IpNetwork;

/// Defense-in-depth target filter executed directly on asi-worker right before
/// invoking any scanner binary or HTTP probe.
#[derive(Debug, Clone)]
pub struct TargetGuard {
    excluded: Vec<IpNetwork>,
    allow_local_mock_lab: bool,
}

impl TargetGuard {
    #[must_use]
    pub fn new(excluded_cidrs: &[String], allow_local_mock_lab: bool) -> Self {
        let mut excluded = Vec::new();
        for raw in excluded_cidrs {
            if let Ok(net) = raw.trim().parse::<IpNetwork>() {
                excluded.push(net);
            } else if let Ok(ip) = raw.trim().parse::<IpAddr>() {
                excluded.push(IpNetwork::from(ip));
            }
        }
        Self {
            excluded,
            allow_local_mock_lab,
        }
    }

    #[must_use]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        if self.excluded.iter().any(|net| net.contains(ip)) {
            return false;
        }
        if ip.is_multicast() || ip.is_unspecified() {
            return false;
        }
        if !self.allow_local_mock_lab && is_restricted_local(ip) {
            return false;
        }
        true
    }

    #[must_use]
    pub fn filter_targets(&self, targets: &[ChunkTarget]) -> Vec<ChunkTarget> {
        targets
            .iter()
            .filter(|t| self.is_allowed(t.ip_addr))
            .cloned()
            .collect()
    }
}

fn is_restricted_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || ((v6.segments()[0] & 0xffc0) == 0xfe80),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_exclusions_and_loopback_policy() {
        let prod_guard = TargetGuard::new(&["172.28.0.12/30".to_string()], false);
        assert!(!prod_guard.is_allowed("127.0.0.1".parse().unwrap()));
        assert!(!prod_guard.is_allowed("169.254.1.1".parse().unwrap()));
        assert!(!prod_guard.is_allowed("172.28.0.13".parse().unwrap()));
        assert!(prod_guard.is_allowed("172.28.0.10".parse().unwrap()));

        let lab_guard = TargetGuard::new(&["172.28.0.12/30".to_string()], true);
        assert!(lab_guard.is_allowed("127.0.0.1".parse().unwrap()));
        assert!(!lab_guard.is_allowed("172.28.0.13".parse().unwrap()));
    }
}
