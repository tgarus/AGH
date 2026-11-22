use std::collections::{BTreeMap, BTreeSet};

use asi_common::diff::{BulletItem, DiffEventKind, DiffOp, DiffSeverity};
use asi_common::inventory::{HostStatus, PortState};
use chrono::{DateTime, Utc};

use crate::diff_engine::instability::InstabilityAssessment;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSnapshot {
    pub sha256_fingerprint: String,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub san_dns: BTreeSet<String>,
    pub not_after: Option<DateTime<Utc>>,
    pub is_self_signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSnapshot {
    pub http_status: Option<u16>,
    pub redirect_target: Option<String>,
    pub title: Option<String>,
    pub headers_filtered: BTreeMap<String, String>,
    /// Keyed by cookie name -> (http_only, secure, same_site); raw token values are never stored.
    pub cookies_meta: BTreeMap<String, (bool, bool, Option<String>)>,
    pub favicon_mmh3: Option<i64>,
    pub matched_technologies: BTreeSet<String>,
    pub detected_paths: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct PreviousPortState {
    pub state: PortState,
    pub consecutive_misses: u32,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub tunnel: Option<String>,
    pub tls: Option<TlsSnapshot>,
    pub webs: BTreeMap<(String, String), WebSnapshot>,
}

#[derive(Debug, Clone)]
pub struct PreviousHostState {
    pub exists: bool,
    pub status: HostStatus,
    pub consecutive_misses: u32,
    pub is_unstable: bool,
    pub is_probable_tarpit: bool,
    pub last_seen_at_present: bool,
    pub ports: BTreeMap<(u16, String), PreviousPortState>,
}

#[derive(Debug, Clone)]
pub struct CurrentPortObservation {
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub tunnel: Option<String>,
    pub tls: Option<TlsSnapshot>,
    pub webs: BTreeMap<(String, String), WebSnapshot>,
}

#[derive(Debug, Clone)]
pub struct CurrentHostObservation {
    pub is_alive: bool,
    pub is_probable_tarpit: bool,
    pub open_ports: BTreeMap<(u16, String), CurrentPortObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortTransition {
    pub port: u16,
    pub protocol: String,
    pub next_state: PortState,
    pub next_misses: u32,
}

#[derive(Debug, Clone)]
pub struct DiffEventDraft {
    pub event_kind: DiffEventKind,
    pub severity: DiffSeverity,
    pub bullet_items: Vec<BulletItem>,
    pub previous_snapshot: serde_json::Value,
    pub current_snapshot: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct HostEvaluation {
    pub next_host_status: HostStatus,
    pub next_host_misses: u32,
    pub missing_port_transitions: Vec<PortTransition>,
    pub diffs: Vec<DiffEventDraft>,
}

struct DiffCollector {
    confirmed_bullets: Vec<BulletItem>,
    max_confirmed_severity: DiffSeverity,
    variance_bullets: Vec<BulletItem>,
    has_diurnal_variance: bool,
}

impl DiffCollector {
    const fn new() -> Self {
        Self {
            confirmed_bullets: Vec::new(),
            max_confirmed_severity: DiffSeverity::Info,
            variance_bullets: Vec::new(),
            has_diurnal_variance: false,
        }
    }

    fn push_confirmed(&mut self, item: BulletItem, severity: DiffSeverity) {
        self.max_confirmed_severity = self.max_confirmed_severity.max(severity);
        self.confirmed_bullets.push(item);
    }

    fn push_diurnal_variance(&mut self, instability: &InstabilityAssessment) {
        if self.has_diurnal_variance {
            return;
        }
        self.has_diurnal_variance = true;
        self.variance_bullets.push(BulletItem {
            op: DiffOp::Changed,
            key: "diurnal_variance".to_string(),
            params: serde_json::json!({
                "active_hours": instability.active_hours_summary,
                "transitions": instability.transitions_last_10,
            }),
        });
    }

    fn push_port_flapping(&mut self, port: u16, proto: &str, state: &str) {
        self.variance_bullets.push(BulletItem {
            op: DiffOp::Changed,
            key: "port_flapping".to_string(),
            params: serde_json::json!({
                "port": port,
                "proto": proto,
                "state": state,
            }),
        });
    }
}

#[must_use]
pub fn evaluate_host_diff(
    prev: &PreviousHostState,
    curr: &CurrentHostObservation,
    instability: &InstabilityAssessment,
    inactivity_threshold: u32,
    is_initial_baseline: bool,
) -> HostEvaluation {
    if prev.exists && prev.status == HostStatus::Ignored {
        return HostEvaluation {
            next_host_status: HostStatus::Ignored,
            next_host_misses: prev.consecutive_misses,
            missing_port_transitions: Vec::new(),
            diffs: Vec::new(),
        };
    }

    let k = inactivity_threshold.max(1);
    let mut collector = DiffCollector::new();

    let (next_host_status, next_host_misses) = evaluate_host_liveness(
        prev,
        curr,
        instability,
        k,
        is_initial_baseline,
        &mut collector,
    );

    if curr.is_probable_tarpit && !prev.is_probable_tarpit {
        collector.push_confirmed(
            BulletItem {
                op: DiffOp::Changed,
                key: "probable_tarpit_detected".to_string(),
                params: serde_json::json!({
                    "open_port_count": curr.open_ports.len(),
                }),
            },
            DiffSeverity::Medium,
        );
    }

    for ((port, proto), curr_port) in &curr.open_ports {
        match prev.ports.get(&(*port, proto.clone())) {
            None => {
                if !is_initial_baseline {
                    collector.push_confirmed(
                        BulletItem {
                            op: DiffOp::Added,
                            key: "service_added".to_string(),
                            params: serde_json::json!({
                                "port": port,
                                "proto": proto,
                                "service_name": curr_port.service_name,
                                "product": curr_port.product,
                                "version": curr_port.version,
                            }),
                        },
                        DiffSeverity::Medium,
                    );
                    emit_admin_paths_from_webs(*port, curr_port, None, &mut collector);
                }
            }
            Some(prev_port) => {
                if prev_port.state == PortState::Closed {
                    if instability.is_unstable {
                        collector.push_port_flapping(*port, proto, "reappeared");
                    } else {
                        collector.push_confirmed(
                            BulletItem {
                                op: DiffOp::Added,
                                key: "service_added".to_string(),
                                params: serde_json::json!({
                                    "port": port,
                                    "proto": proto,
                                    "service_name": curr_port.service_name,
                                    "product": curr_port.product,
                                    "version": curr_port.version,
                                }),
                            },
                            DiffSeverity::Medium,
                        );
                    }
                }
                compare_service_and_tls(*port, proto, prev_port, curr_port, &mut collector);
                compare_web_observations(*port, prev_port, curr_port, &mut collector);
            }
        }
    }

    let missing_port_transitions =
        evaluate_missing_ports(prev, curr, instability, k, &mut collector);

    let prev_snap = summarize_previous_host(prev);
    let curr_snap = summarize_current_host(next_host_status, curr, instability);

    let mut diffs = Vec::new();
    if !collector.confirmed_bullets.is_empty() {
        diffs.push(DiffEventDraft {
            event_kind: DiffEventKind::ConfirmedChange,
            severity: collector.max_confirmed_severity,
            bullet_items: collector.confirmed_bullets,
            previous_snapshot: prev_snap,
            current_snapshot: curr_snap,
        });
    } else if !collector.variance_bullets.is_empty() {
        diffs.push(DiffEventDraft {
            event_kind: DiffEventKind::ActiveVariance,
            severity: DiffSeverity::Info,
            bullet_items: collector.variance_bullets,
            previous_snapshot: prev_snap,
            current_snapshot: curr_snap,
        });
    }

    HostEvaluation {
        next_host_status,
        next_host_misses,
        missing_port_transitions,
        diffs,
    }
}

fn evaluate_host_liveness(
    prev: &PreviousHostState,
    curr: &CurrentHostObservation,
    instability: &InstabilityAssessment,
    k: u32,
    is_initial_baseline: bool,
    collector: &mut DiffCollector,
) -> (HostStatus, u32) {
    if curr.is_alive {
        if !prev.exists || !prev.last_seen_at_present {
            if !is_initial_baseline {
                collector.push_confirmed(
                    BulletItem {
                        op: DiffOp::Added,
                        key: "host_discovered".to_string(),
                        params: serde_json::json!({
                            "open_ports": curr.open_ports.len(),
                        }),
                    },
                    DiffSeverity::Medium,
                );
            }
        } else if prev.status == HostStatus::Inactive {
            if instability.is_unstable {
                collector.push_diurnal_variance(instability);
            } else {
                collector.push_confirmed(
                    BulletItem {
                        op: DiffOp::Added,
                        key: "host_reactivated".to_string(),
                        params: serde_json::json!({
                            "open_ports": curr.open_ports.len(),
                        }),
                    },
                    DiffSeverity::Low,
                );
            }
        } else if prev.status == HostStatus::MissingPending && instability.is_unstable {
            collector.push_diurnal_variance(instability);
        }
        return (HostStatus::Active, 0);
    }

    let next_misses = prev.consecutive_misses.saturating_add(1);
    if prev.exists && prev.status == HostStatus::Inactive {
        return (HostStatus::Inactive, next_misses);
    }

    let next_status = if next_misses >= k {
        HostStatus::Inactive
    } else {
        HostStatus::MissingPending
    };

    if prev.exists && prev.last_seen_at_present {
        if next_misses >= k {
            if instability.is_unstable {
                collector.push_diurnal_variance(instability);
            } else {
                collector.push_confirmed(
                    BulletItem {
                        op: DiffOp::Removed,
                        key: "host_inactive".to_string(),
                        params: serde_json::json!({
                            "consecutive_misses": next_misses,
                        }),
                    },
                    DiffSeverity::Low,
                );
            }
        } else if instability.is_unstable && prev.status == HostStatus::Active {
            collector.push_diurnal_variance(instability);
        }
    }

    (next_status, next_misses)
}

fn format_service_label(
    service_name: Option<&str>,
    product: Option<&str>,
    version: Option<&str>,
) -> String {
    let mut parts = Vec::new();
    if let Some(p) = product.filter(|s| !s.trim().is_empty()) {
        parts.push(p.trim().to_string());
    } else if let Some(s) = service_name.filter(|s| !s.trim().is_empty()) {
        parts.push(s.trim().to_string());
    }
    if let Some(v) = version.filter(|s| !s.trim().is_empty()) {
        parts.push(v.trim().to_string());
    }
    if parts.is_empty() {
        "unknown".to_string()
    } else {
        parts.join(" ")
    }
}

fn compare_service_and_tls(
    port: u16,
    proto: &str,
    prev_port: &PreviousPortState,
    curr_port: &CurrentPortObservation,
    collector: &mut DiffCollector,
) {
    let prev_has_svc = prev_port.service_name.is_some()
        || prev_port.product.is_some()
        || prev_port.version.is_some();
    let curr_has_svc = curr_port.service_name.is_some()
        || curr_port.product.is_some()
        || curr_port.version.is_some();

    if prev_has_svc
        && curr_has_svc
        && (prev_port.service_name != curr_port.service_name
            || prev_port.product != curr_port.product
            || prev_port.version != curr_port.version
            || prev_port.tunnel != curr_port.tunnel)
    {
        let before = format_service_label(
            prev_port.service_name.as_deref(),
            prev_port.product.as_deref(),
            prev_port.version.as_deref(),
        );
        let after = format_service_label(
            curr_port.service_name.as_deref(),
            curr_port.product.as_deref(),
            curr_port.version.as_deref(),
        );
        collector.push_confirmed(
            BulletItem {
                op: DiffOp::Changed,
                key: "service_changed".to_string(),
                params: serde_json::json!({
                    "port": port,
                    "proto": proto,
                    "before": before,
                    "after": after,
                }),
            },
            DiffSeverity::Medium,
        );
    }

    if let (Some(prev_tls), Some(curr_tls)) = (&prev_port.tls, &curr_port.tls) {
        if prev_tls != curr_tls {
            let sev = if curr_tls.is_self_signed && !prev_tls.is_self_signed {
                DiffSeverity::High
            } else {
                DiffSeverity::Medium
            };
            collector.push_confirmed(
                BulletItem {
                    op: DiffOp::Changed,
                    key: "tls_certificate_changed".to_string(),
                    params: serde_json::json!({
                        "port": port,
                        "subject_cn": curr_tls.subject_cn,
                        "is_self_signed": curr_tls.is_self_signed,
                    }),
                },
                sev,
            );
        }
    }
}

fn emit_admin_paths_from_webs(
    port: u16,
    curr_port: &CurrentPortObservation,
    prev_port: Option<&PreviousPortState>,
    collector: &mut DiffCollector,
) {
    for ((vhost, scheme), curr_web) in &curr_port.webs {
        let prev_paths = prev_port
            .and_then(|pp| pp.webs.get(&(vhost.clone(), scheme.clone())))
            .map(|pw| &pw.detected_paths);
        for path in &curr_web.detected_paths {
            if (path == "/admin" || path == "/login")
                && !prev_paths.is_some_and(|set| set.contains(path))
            {
                collector.push_confirmed(
                    BulletItem {
                        op: DiffOp::Added,
                        key: "admin_panel_detected".to_string(),
                        params: serde_json::json!({
                            "port": port,
                            "vhost": vhost,
                            "path": path,
                        }),
                    },
                    DiffSeverity::High,
                );
            }
        }
    }
}

fn compare_web_observations(
    port: u16,
    prev_port: &PreviousPortState,
    curr_port: &CurrentPortObservation,
    collector: &mut DiffCollector,
) {
    for ((vhost, scheme), curr_web) in &curr_port.webs {
        match prev_port.webs.get(&(vhost.clone(), scheme.clone())) {
            None => {
                collector.push_confirmed(
                    BulletItem {
                        op: DiffOp::Added,
                        key: "vhost_discovered".to_string(),
                        params: serde_json::json!({
                            "port": port,
                            "vhost": vhost,
                            "scheme": scheme,
                            "http_status": curr_web.http_status,
                        }),
                    },
                    DiffSeverity::Low,
                );
                for path in &curr_web.detected_paths {
                    if path == "/admin" || path == "/login" {
                        collector.push_confirmed(
                            BulletItem {
                                op: DiffOp::Added,
                                key: "admin_panel_detected".to_string(),
                                params: serde_json::json!({
                                    "port": port,
                                    "vhost": vhost,
                                    "path": path,
                                }),
                            },
                            DiffSeverity::High,
                        );
                    }
                }
                for tech in &curr_web.matched_technologies {
                    collector.push_confirmed(
                        BulletItem {
                            op: DiffOp::Added,
                            key: "technology_detected".to_string(),
                            params: serde_json::json!({
                                "port": port,
                                "vhost": vhost,
                                "technology": tech,
                            }),
                        },
                        DiffSeverity::Medium,
                    );
                }
            }
            Some(prev_web) => {
                for path in &curr_web.detected_paths {
                    if (path == "/admin" || path == "/login")
                        && !prev_web.detected_paths.contains(path)
                    {
                        collector.push_confirmed(
                            BulletItem {
                                op: DiffOp::Added,
                                key: "admin_panel_detected".to_string(),
                                params: serde_json::json!({
                                    "port": port,
                                    "vhost": vhost,
                                    "path": path,
                                }),
                            },
                            DiffSeverity::High,
                        );
                    }
                }

                for tech in &curr_web.matched_technologies {
                    if !prev_web.matched_technologies.contains(tech) {
                        collector.push_confirmed(
                            BulletItem {
                                op: DiffOp::Added,
                                key: "technology_detected".to_string(),
                                params: serde_json::json!({
                                    "port": port,
                                    "vhost": vhost,
                                    "technology": tech,
                                }),
                            },
                            DiffSeverity::Medium,
                        );
                    }
                }

                if prev_web.title != curr_web.title {
                    collector.push_confirmed(
                        BulletItem {
                            op: DiffOp::Changed,
                            key: "title_changed".to_string(),
                            params: serde_json::json!({
                                "port": port,
                                "vhost": vhost,
                                "before": prev_web.title,
                                "after": curr_web.title,
                            }),
                        },
                        DiffSeverity::Low,
                    );
                }

                if prev_web.http_status != curr_web.http_status
                    || prev_web.redirect_target != curr_web.redirect_target
                {
                    collector.push_confirmed(
                        BulletItem {
                            op: DiffOp::Changed,
                            key: "http_status_changed".to_string(),
                            params: serde_json::json!({
                                "port": port,
                                "vhost": vhost,
                                "before_status": prev_web.http_status,
                                "after_status": curr_web.http_status,
                                "redirect_target": curr_web.redirect_target,
                            }),
                        },
                        DiffSeverity::Low,
                    );
                }

                if prev_web.favicon_mmh3 != curr_web.favicon_mmh3 {
                    collector.push_confirmed(
                        BulletItem {
                            op: DiffOp::Changed,
                            key: "favicon_changed".to_string(),
                            params: serde_json::json!({
                                "port": port,
                                "vhost": vhost,
                                "before": prev_web.favicon_mmh3,
                                "after": curr_web.favicon_mmh3,
                            }),
                        },
                        DiffSeverity::Low,
                    );
                }

                for (name, &(http_only, secure, ref same_site)) in &curr_web.cookies_meta {
                    let changed = prev_web.cookies_meta.get(name).is_none_or(|prev_flags| {
                        prev_flags != &(http_only, secure, same_site.clone())
                    });
                    if changed {
                        let sev = if !http_only || !secure {
                            DiffSeverity::Medium
                        } else {
                            DiffSeverity::Low
                        };
                        collector.push_confirmed(
                            BulletItem {
                                op: DiffOp::Changed,
                                key: "cookie_changed".to_string(),
                                params: serde_json::json!({
                                    "port": port,
                                    "vhost": vhost,
                                    "cookie": name,
                                    "http_only": http_only,
                                    "secure": secure,
                                    "same_site": same_site,
                                }),
                            },
                            sev,
                        );
                    }
                }
            }
        }
    }
}

fn evaluate_missing_ports(
    prev: &PreviousHostState,
    curr: &CurrentHostObservation,
    instability: &InstabilityAssessment,
    k: u32,
    collector: &mut DiffCollector,
) -> Vec<PortTransition> {
    let mut transitions = Vec::new();
    for ((port, proto), prev_port) in &prev.ports {
        if curr.open_ports.contains_key(&(*port, proto.clone())) {
            continue;
        }
        if prev_port.state == PortState::Closed {
            continue;
        }

        let next_misses = prev_port.consecutive_misses.saturating_add(1);
        let next_state = if next_misses >= k {
            PortState::Closed
        } else {
            PortState::MissingPending
        };

        transitions.push(PortTransition {
            port: *port,
            protocol: proto.clone(),
            next_state,
            next_misses,
        });

        if next_misses >= k {
            if instability.is_unstable {
                collector.push_port_flapping(*port, proto, "missing");
            } else {
                collector.push_confirmed(
                    BulletItem {
                        op: DiffOp::Removed,
                        key: "service_removed".to_string(),
                        params: serde_json::json!({
                            "port": port,
                            "proto": proto,
                            "service_name": prev_port.service_name,
                            "consecutive_misses": next_misses,
                        }),
                    },
                    DiffSeverity::Low,
                );
            }
        } else if instability.is_unstable && prev_port.state == PortState::Active {
            collector.push_diurnal_variance(instability);
        }
    }
    transitions
}

fn summarize_previous_host(prev: &PreviousHostState) -> serde_json::Value {
    let ports: Vec<serde_json::Value> = prev
        .ports
        .iter()
        .filter(|(_, p)| p.state != PortState::Closed)
        .map(|((port, proto), p)| {
            serde_json::json!({
                "port": port,
                "protocol": proto,
                "state": p.state,
                "service_name": p.service_name,
                "version": p.version,
            })
        })
        .collect();
    serde_json::json!({
        "status": prev.status,
        "is_unstable": prev.is_unstable,
        "is_probable_tarpit": prev.is_probable_tarpit,
        "ports": ports,
    })
}

fn summarize_current_host(
    next_status: HostStatus,
    curr: &CurrentHostObservation,
    instability: &InstabilityAssessment,
) -> serde_json::Value {
    let ports: Vec<serde_json::Value> = curr
        .open_ports
        .iter()
        .map(|((port, proto), p)| {
            serde_json::json!({
                "port": port,
                "protocol": proto,
                "service_name": p.service_name,
                "version": p.version,
            })
        })
        .collect();
    serde_json::json!({
        "status": next_status,
        "is_unstable": instability.is_unstable,
        "is_probable_tarpit": curr.is_probable_tarpit,
        "ports": ports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use asi_common::diff::{filter_noise_headers, TimeSlot};
    use std::collections::HashMap;

    fn stable_assessment() -> InstabilityAssessment {
        InstabilityAssessment {
            is_unstable: false,
            newly_marked_unstable: false,
            transitions_last_10: 0,
            availability_profile: serde_json::json!({}),
            active_hours_summary: "06:00-18:00".to_string(),
        }
    }

    fn unstable_assessment() -> InstabilityAssessment {
        InstabilityAssessment {
            is_unstable: true,
            newly_marked_unstable: false,
            transitions_last_10: 4,
            availability_profile: serde_json::json!({}),
            active_hours_summary: "06:00-18:00".to_string(),
        }
    }

    fn simple_port(service: Option<&str>, version: Option<&str>) -> CurrentPortObservation {
        CurrentPortObservation {
            service_name: service.map(ToString::to_string),
            product: None,
            version: version.map(ToString::to_string),
            tunnel: None,
            tls: None,
            webs: BTreeMap::new(),
        }
    }

    fn prev_active_port(misses: u32, service: Option<&str>) -> PreviousPortState {
        PreviousPortState {
            state: if misses == 0 {
                PortState::Active
            } else {
                PortState::MissingPending
            },
            consecutive_misses: misses,
            service_name: service.map(ToString::to_string),
            product: None,
            version: None,
            tunnel: None,
            tls: None,
            webs: BTreeMap::new(),
        }
    }

    #[test]
    fn k_threshold_waits_for_three_misses_before_confirmed_removal() {
        let down = CurrentHostObservation {
            is_alive: false,
            is_probable_tarpit: false,
            open_ports: BTreeMap::new(),
        };

        let mut prev = PreviousHostState {
            exists: true,
            status: HostStatus::Active,
            consecutive_misses: 0,
            is_unstable: false,
            is_probable_tarpit: false,
            last_seen_at_present: true,
            ports: BTreeMap::from([((21, "tcp".to_string()), prev_active_port(0, Some("ftp")))]),
        };

        // Miss 1 -> missing_pending, zero confirmed diffs
        let e1 = evaluate_host_diff(&prev, &down, &stable_assessment(), 3, false);
        assert_eq!(e1.next_host_status, HostStatus::MissingPending);
        assert_eq!(e1.next_host_misses, 1);
        assert_eq!(
            e1.missing_port_transitions[0].next_state,
            PortState::MissingPending
        );
        assert!(e1.diffs.is_empty());

        // Miss 2 -> missing_pending, zero confirmed diffs
        prev.status = HostStatus::MissingPending;
        prev.consecutive_misses = 1;
        prev.ports.get_mut(&(21, "tcp".to_string())).unwrap().state = PortState::MissingPending;
        prev.ports
            .get_mut(&(21, "tcp".to_string()))
            .unwrap()
            .consecutive_misses = 1;
        let e2 = evaluate_host_diff(&prev, &down, &stable_assessment(), 3, false);
        assert_eq!(e2.next_host_status, HostStatus::MissingPending);
        assert_eq!(e2.next_host_misses, 2);
        assert!(e2.diffs.is_empty());

        // Miss 3 == K -> closed/inactive + confirmed_change
        prev.consecutive_misses = 2;
        prev.ports
            .get_mut(&(21, "tcp".to_string()))
            .unwrap()
            .consecutive_misses = 2;
        let e3 = evaluate_host_diff(&prev, &down, &stable_assessment(), 3, false);
        assert_eq!(e3.next_host_status, HostStatus::Inactive);
        assert_eq!(e3.next_host_misses, 3);
        assert_eq!(e3.missing_port_transitions[0].next_state, PortState::Closed);
        assert_eq!(e3.diffs.len(), 1);
        assert_eq!(e3.diffs[0].event_kind, DiffEventKind::ConfirmedChange);
        assert!(e3.diffs[0]
            .bullet_items
            .iter()
            .any(|b| b.key == "service_removed"));
    }

    #[test]
    fn flapping_host_avoids_false_confirmed_change_and_emits_active_variance() {
        let prev = PreviousHostState {
            exists: true,
            status: HostStatus::Inactive,
            consecutive_misses: 3,
            is_unstable: true,
            is_probable_tarpit: false,
            last_seen_at_present: true,
            ports: BTreeMap::from([(
                (80, "tcp".to_string()),
                PreviousPortState {
                    state: PortState::Closed,
                    consecutive_misses: 3,
                    service_name: Some("http".to_string()),
                    product: None,
                    version: None,
                    tunnel: None,
                    tls: None,
                    webs: BTreeMap::new(),
                },
            )]),
        };

        let curr = CurrentHostObservation {
            is_alive: true,
            is_probable_tarpit: false,
            open_ports: BTreeMap::from([(
                (80, "tcp".to_string()),
                simple_port(Some("http"), None),
            )]),
        };

        let eval = evaluate_host_diff(&prev, &curr, &unstable_assessment(), 3, false);
        assert_eq!(eval.next_host_status, HostStatus::Active);
        assert_eq!(eval.diffs.len(), 1);
        assert_eq!(eval.diffs[0].event_kind, DiffEventKind::ActiveVariance);
        assert_eq!(eval.diffs[0].severity, DiffSeverity::Info);
        assert!(eval.diffs[0]
            .bullet_items
            .iter()
            .any(|b| b.key == "diurnal_variance" || b.key == "port_flapping"));
    }

    #[test]
    fn unstable_host_still_emits_confirmed_change_for_new_service_or_admin_panel() {
        let mut webs = BTreeMap::new();
        webs.insert(
            ("app.lab.local".to_string(), "https".to_string()),
            WebSnapshot {
                http_status: Some(200),
                redirect_target: None,
                title: Some("Admin Login".to_string()),
                headers_filtered: BTreeMap::new(),
                cookies_meta: BTreeMap::new(),
                favicon_mmh3: None,
                matched_technologies: BTreeSet::from(["Admin Panel".to_string()]),
                detected_paths: BTreeSet::from(["/admin".to_string()]),
            },
        );

        let prev = PreviousHostState {
            exists: true,
            status: HostStatus::Active,
            consecutive_misses: 0,
            is_unstable: true,
            is_probable_tarpit: false,
            last_seen_at_present: true,
            ports: BTreeMap::from([((80, "tcp".to_string()), prev_active_port(0, Some("http")))]),
        };

        let curr = CurrentHostObservation {
            is_alive: true,
            is_probable_tarpit: false,
            open_ports: BTreeMap::from([
                ((80, "tcp".to_string()), simple_port(Some("http"), None)),
                (
                    (8443, "tcp".to_string()),
                    CurrentPortObservation {
                        service_name: Some("https".to_string()),
                        product: None,
                        version: None,
                        tunnel: Some("ssl".to_string()),
                        tls: None,
                        webs,
                    },
                ),
            ]),
        };

        let eval = evaluate_host_diff(&prev, &curr, &unstable_assessment(), 3, false);
        assert_eq!(eval.diffs.len(), 1);
        assert_eq!(eval.diffs[0].event_kind, DiffEventKind::ConfirmedChange);
        assert_eq!(eval.diffs[0].severity, DiffSeverity::High);
        assert!(eval.diffs[0]
            .bullet_items
            .iter()
            .any(|b| b.key == "service_added"));
        assert!(eval.diffs[0]
            .bullet_items
            .iter()
            .any(|b| b.key == "admin_panel_detected"));
    }

    #[test]
    fn filters_noise_headers_and_san_order_and_cookie_values() {
        let headers1 = filter_noise_headers(&HashMap::from([
            (
                "Date".to_string(),
                "Mon, 01 Jan 2026 00:00:00 GMT".to_string(),
            ),
            ("X-Request-Id".to_string(), "req-1".to_string()),
            ("Server".to_string(), "nginx".to_string()),
        ]));
        let headers2 = filter_noise_headers(&HashMap::from([
            (
                "Date".to_string(),
                "Tue, 02 Jan 2026 00:00:00 GMT".to_string(),
            ),
            ("X-Request-Id".to_string(), "req-999".to_string()),
            ("Server".to_string(), "nginx".to_string()),
        ]));
        assert_eq!(headers1, headers2);

        let tls1 = TlsSnapshot {
            sha256_fingerprint: "abc".to_string(),
            subject_cn: Some("app.lab".to_string()),
            issuer_cn: Some("ca.lab".to_string()),
            san_dns: BTreeSet::from(["b.lab".to_string(), "a.lab".to_string()]),
            not_after: None,
            is_self_signed: false,
        };
        let tls2 = TlsSnapshot {
            sha256_fingerprint: "abc".to_string(),
            subject_cn: Some("app.lab".to_string()),
            issuer_cn: Some("ca.lab".to_string()),
            san_dns: BTreeSet::from(["a.lab".to_string(), "b.lab".to_string()]),
            not_after: None,
            is_self_signed: false,
        };

        let mut cookies = BTreeMap::new();
        cookies.insert("SESSION".to_string(), (true, true, Some("lax".to_string())));

        let web = WebSnapshot {
            http_status: Some(200),
            redirect_target: None,
            title: Some("App".to_string()),
            headers_filtered: headers1,
            cookies_meta: cookies.clone(),
            favicon_mmh3: Some(123),
            matched_technologies: BTreeSet::new(),
            detected_paths: BTreeSet::new(),
        };

        let prev = PreviousHostState {
            exists: true,
            status: HostStatus::Active,
            consecutive_misses: 0,
            is_unstable: false,
            is_probable_tarpit: false,
            last_seen_at_present: true,
            ports: BTreeMap::from([(
                (443, "tcp".to_string()),
                PreviousPortState {
                    state: PortState::Active,
                    consecutive_misses: 0,
                    service_name: Some("https".to_string()),
                    product: Some("nginx".to_string()),
                    version: None,
                    tunnel: Some("ssl".to_string()),
                    tls: Some(tls1),
                    webs: BTreeMap::from([(("app.lab".to_string(), "https".to_string()), web)]),
                },
            )]),
        };

        let web2 = WebSnapshot {
            http_status: Some(200),
            redirect_target: None,
            title: Some("App".to_string()),
            headers_filtered: headers2,
            cookies_meta: cookies,
            favicon_mmh3: Some(123),
            matched_technologies: BTreeSet::new(),
            detected_paths: BTreeSet::new(),
        };

        let curr = CurrentHostObservation {
            is_alive: true,
            is_probable_tarpit: false,
            open_ports: BTreeMap::from([(
                (443, "tcp".to_string()),
                CurrentPortObservation {
                    service_name: Some("https".to_string()),
                    product: Some("nginx".to_string()),
                    version: None,
                    tunnel: Some("ssl".to_string()),
                    tls: Some(tls2),
                    webs: BTreeMap::from([(("app.lab".to_string(), "https".to_string()), web2)]),
                },
            )]),
        };

        let eval = evaluate_host_diff(&prev, &curr, &stable_assessment(), 3, false);
        assert!(eval.diffs.is_empty());
        assert_eq!(TimeSlot::Slot0006.as_db_str(), "00_06");
    }

    #[test]
    fn ignored_host_never_emits_diffs() {
        let prev = PreviousHostState {
            exists: true,
            status: HostStatus::Ignored,
            consecutive_misses: 0,
            is_unstable: false,
            is_probable_tarpit: false,
            last_seen_at_present: true,
            ports: BTreeMap::new(),
        };
        let curr = CurrentHostObservation {
            is_alive: true,
            is_probable_tarpit: true,
            open_ports: BTreeMap::from([((22, "tcp".to_string()), simple_port(Some("ssh"), None))]),
        };

        let eval = evaluate_host_diff(&prev, &curr, &stable_assessment(), 3, false);
        assert_eq!(eval.next_host_status, HostStatus::Ignored);
        assert!(eval.diffs.is_empty());
    }
}
