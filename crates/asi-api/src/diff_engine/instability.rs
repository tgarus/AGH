use std::collections::{BTreeMap, BTreeSet};

use asi_common::diff::TimeSlot;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilitySample {
    pub time_slot: TimeSlot,
    pub is_alive: bool,
    pub open_ports_hash: String,
}

#[derive(Debug, Clone)]
pub struct InstabilityAssessment {
    pub is_unstable: bool,
    pub newly_marked_unstable: bool,
    pub transitions_last_10: u32,
    pub availability_profile: serde_json::Value,
    pub active_hours_summary: String,
}

#[must_use]
pub fn compute_open_ports_hash(is_alive: bool, open_ports: &[(u16, &str)]) -> String {
    if !is_alive {
        return "down".to_string();
    }
    let mut normalized = BTreeSet::new();
    for (port, proto) in open_ports {
        normalized.insert(format!("{port}/{}", proto.to_ascii_lowercase()));
    }
    let joined = normalized.into_iter().collect::<Vec<_>>().join(",");
    hex::encode(Sha256::digest(joined.as_bytes()))
}

#[must_use]
pub fn assess_instability(
    previously_unstable: bool,
    samples_oldest_first: &[AvailabilitySample],
) -> InstabilityAssessment {
    let start_idx = samples_oldest_first.len().saturating_sub(10);
    let last_10 = &samples_oldest_first[start_idx..];

    let mut transitions_last_10 = 0_u32;
    for pair in last_10.windows(2) {
        let prev = &pair[0];
        let curr = &pair[1];
        let changed = prev.is_alive != curr.is_alive
            || (prev.is_alive && curr.is_alive && prev.open_ports_hash != curr.open_ports_hash);
        if changed {
            transitions_last_10 = transitions_last_10.saturating_add(1);
        }
    }

    let is_unstable = transitions_last_10 >= 2;
    let newly_marked_unstable = is_unstable && !previously_unstable;

    let mut slot_counts: BTreeMap<&'static str, (u32, u32)> = BTreeMap::new();
    for slot in TimeSlot::ALL {
        slot_counts.insert(slot.as_db_str(), (0, 0));
    }
    for sample in samples_oldest_first {
        let entry = slot_counts
            .entry(sample.time_slot.as_db_str())
            .or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        if sample.is_alive {
            entry.1 = entry.1.saturating_add(1);
        }
    }

    let mut profile_map = serde_json::Map::new();
    let mut active_slots = Vec::new();
    for slot in TimeSlot::ALL {
        let key = slot.as_db_str();
        let (total, up) = slot_counts.get(key).copied().unwrap_or((0, 0));
        let ratio = if total > 0 {
            ((f64::from(up) / f64::from(total)) * 100.0).round() / 100.0
        } else {
            0.0
        };
        if total > 0 && ratio >= 0.5 {
            active_slots.push(slot);
        }
        profile_map.insert(
            key.to_string(),
            serde_json::json!({
                "samples": total,
                "up": up,
                "up_ratio": ratio,
            }),
        );
    }
    profile_map.insert(
        "transitions_last_10".to_string(),
        serde_json::Value::from(transitions_last_10),
    );

    let active_hours_summary = build_active_hours_summary(&active_slots);

    InstabilityAssessment {
        is_unstable,
        newly_marked_unstable,
        transitions_last_10,
        availability_profile: serde_json::Value::Object(profile_map),
        active_hours_summary,
    }
}

fn build_active_hours_summary(active_slots: &[TimeSlot]) -> String {
    if active_slots.is_empty() {
        return "intermittent".to_string();
    }
    if active_slots.len() == 2
        && active_slots.contains(&TimeSlot::Slot0612)
        && active_slots.contains(&TimeSlot::Slot1218)
    {
        return "06:00-18:00".to_string();
    }
    active_slots
        .iter()
        .map(|slot| match slot {
            TimeSlot::Slot0006 => "00:00-06:00",
            TimeSlot::Slot0612 => "06:00-12:00",
            TimeSlot::Slot1218 => "12:00-18:00",
            TimeSlot::Slot1824 => "18:00-24:00",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_ports_hash_is_order_independent_and_marks_down() {
        assert_eq!(compute_open_ports_hash(false, &[(80, "tcp")]), "down");
        let h1 = compute_open_ports_hash(true, &[(443, "tcp"), (80, "TCP")]);
        let h2 = compute_open_ports_hash(true, &[(80, "tcp"), (443, "tcp"), (80, "tcp")]);
        assert_eq!(h1, h2);
        assert_ne!(h1, "down");
    }

    #[test]
    fn detects_diurnal_oscillation_after_two_transitions() {
        let up_hash = compute_open_ports_hash(true, &[(80, "tcp")]);
        let samples = vec![
            AvailabilitySample {
                time_slot: TimeSlot::Slot0612,
                is_alive: true,
                open_ports_hash: up_hash.clone(),
            },
            AvailabilitySample {
                time_slot: TimeSlot::Slot1218,
                is_alive: true,
                open_ports_hash: up_hash.clone(),
            },
            AvailabilitySample {
                time_slot: TimeSlot::Slot0006,
                is_alive: false,
                open_ports_hash: "down".to_string(),
            },
            AvailabilitySample {
                time_slot: TimeSlot::Slot0612,
                is_alive: true,
                open_ports_hash: up_hash,
            },
        ];

        let assessment = assess_instability(false, &samples);
        assert!(assessment.is_unstable);
        assert!(assessment.newly_marked_unstable);
        assert_eq!(assessment.transitions_last_10, 2);
        assert_eq!(assessment.active_hours_summary, "06:00-18:00");
        assert_eq!(assessment.availability_profile["06_12"]["up"], 2);
        assert_eq!(assessment.availability_profile["00_06"]["up"], 0);
    }

    #[test]
    fn single_transition_does_not_mark_unstable() {
        let up_hash = compute_open_ports_hash(true, &[(80, "tcp")]);
        let samples = vec![
            AvailabilitySample {
                time_slot: TimeSlot::Slot0612,
                is_alive: true,
                open_ports_hash: up_hash,
            },
            AvailabilitySample {
                time_slot: TimeSlot::Slot1218,
                is_alive: false,
                open_ports_hash: "down".to_string(),
            },
        ];

        let assessment = assess_instability(false, &samples);
        assert!(!assessment.is_unstable);
        assert!(!assessment.newly_marked_unstable);
        assert_eq!(assessment.transitions_last_10, 1);
    }
}
