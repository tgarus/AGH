use std::time::Duration;

use asi_common::diff::TimeSlot;
use asi_common::scans::ScanTriggerType;
use asi_common::worker::WorkerControlEvent;
use chrono::{DateTime, Datelike, NaiveDate, Timelike, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::app::AppState;
use crate::routes::scans::{emit_scan_status_ui, enqueue_scan_run_for_group, EnqueueScanParams};

const SCHEDULER_TICK_SECONDS: u64 = 60;

#[derive(FromRow)]
struct WindowManagedRunRow {
    id: Uuid,
    status: String,
    completed_chunks: i32,
    time_windows: serde_json::Value,
}

#[derive(FromRow)]
struct SamplingCandidateRow {
    asset_group_id: Uuid,
    time_windows: serde_json::Value,
}

fn parse_hhmm_minutes(raw: &str) -> Option<u32> {
    let (h_str, m_str) = raw.trim().split_once(':')?;
    let h: u32 = h_str.parse().ok()?;
    let m: u32 = m_str.parse().ok()?;
    if h >= 24 || m >= 60 {
        return None;
    }
    Some(h * 60 + m)
}

fn last_sunday_of_month_utc_01(year: i32, month: u32) -> Option<DateTime<Utc>> {
    let last_day = NaiveDate::from_ymd_opt(year, month, 31)?;
    let offset = last_day.weekday().num_days_from_sunday();
    let sunday = 31_u32.saturating_sub(offset);
    let date = NaiveDate::from_ymd_opt(year, month, sunday)?;
    date.and_hms_opt(1, 0, 0).map(|ndt| ndt.and_utc())
}

#[must_use]
pub fn warsaw_utc_offset_hours(dt: DateTime<Utc>) -> i32 {
    let year = dt.year();
    match (
        last_sunday_of_month_utc_01(year, 3),
        last_sunday_of_month_utc_01(year, 10),
    ) {
        (Some(start), Some(end)) if dt >= start && dt < end => 2,
        _ => 1,
    }
}

#[must_use]
pub fn is_within_allowed_windows(time_windows: &serde_json::Value, now_utc: DateTime<Utc>) -> bool {
    let Some(windows) = time_windows
        .get("allowed_windows")
        .and_then(|v| v.as_array())
    else {
        return true;
    };
    if windows.is_empty() {
        return true;
    }

    for win in windows {
        let Some(start_raw) = win.get("start").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(end_raw) = win.get("end").and_then(|v| v.as_str()) else {
            continue;
        };
        let (Some(start_min), Some(end_min)) =
            (parse_hhmm_minutes(start_raw), parse_hhmm_minutes(end_raw))
        else {
            continue;
        };

        let tz = win
            .get("timezone")
            .and_then(|v| v.as_str())
            .unwrap_or("Europe/Warsaw");
        let offset_hours = if tz.eq_ignore_ascii_case("UTC") {
            0
        } else {
            warsaw_utc_offset_hours(now_utc)
        };
        let local_dt = now_utc + chrono::Duration::hours(i64::from(offset_hours));
        let local_min = local_dt.hour() * 60 + local_dt.minute();

        let matches = if start_min <= end_min {
            local_min >= start_min && local_min <= end_min
        } else {
            local_min >= start_min || local_min <= end_min
        };
        if matches {
            return true;
        }
    }

    false
}

#[must_use]
pub fn should_trigger_sampling_slot(
    time_windows: &serde_json::Value,
    now_utc: DateTime<Utc>,
    already_ran_in_slot: bool,
) -> Option<TimeSlot> {
    if already_ran_in_slot || !is_within_allowed_windows(time_windows, now_utc) {
        return None;
    }

    let current_slot = TimeSlot::from_utc_hour(now_utc.hour());
    if let Some(slots) = time_windows
        .get("sampling_slots")
        .and_then(|v| v.as_array())
    {
        let allowed = slots
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(TimeSlot::from_db_str)
            .collect::<Vec<_>>();
        if !allowed.is_empty() && !allowed.contains(&current_slot) {
            return None;
        }
    }

    Some(current_slot)
}

pub fn spawn_scheduler(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(SCHEDULER_TICK_SECONDS));
        loop {
            ticker.tick().await;
            if let Err(err) = run_scheduler_tick(&state).await {
                tracing::warn!(error = %err, "scheduler tick error");
            }
        }
    })
}

async fn run_scheduler_tick(state: &AppState) -> Result<(), String> {
    let Some(pool) = state.db.as_ref() else {
        return Ok(());
    };
    let now = Utc::now();

    // 1. Clean expired ip_locks and reclaim stale chunk leases
    sqlx::query("DELETE FROM ip_locks WHERE locked_until < NOW() AND cooldown_until < NOW()")
        .execute(pool)
        .await
        .map_err(|e| format!("ip_locks cleanup: {e}"))?;

    sqlx::query(
        r#"
        UPDATE scan_chunks sc
        SET status = 'pending',
            leased_by_worker_id = NULL,
            lease_expires_at = NULL,
            error_message = 'lease_expired_requeued'
        FROM scan_runs sr
        WHERE sc.scan_run_id = sr.id
          AND sc.status = 'leased'
          AND sc.lease_expires_at < NOW()
          AND sr.status IN ('queued', 'running')
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| format!("lease reclaim: {e}"))?;

    // 2. Enforce time windows on active scheduled/sampling runs
    let active_runs: Vec<WindowManagedRunRow> = sqlx::query_as(
        r#"
        SELECT sr.id, sr.status, sr.completed_chunks, sp.time_windows
        FROM scan_runs sr
        INNER JOIN asset_groups ag ON ag.id = sr.asset_group_id
        INNER JOIN scan_policies sp ON sp.id = ag.policy_id
        WHERE sr.trigger_type IN ('scheduled', 'sampling')
          AND sr.status IN ('queued', 'running')
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("active window query: {e}"))?;

    for run in active_runs {
        if !is_within_allowed_windows(&run.time_windows, now) {
            let leased_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND status = 'leased'",
            )
            .bind(run.id)
            .fetch_one(pool)
            .await
            .unwrap_or(0);
            let next_status = if leased_count > 0 {
                "pausing"
            } else {
                "paused"
            };

            if sqlx::query(
                "UPDATE scan_runs SET status = $1, cancel_requested_at = NOW() WHERE id = $2",
            )
            .bind(next_status)
            .bind(run.id)
            .execute(pool)
            .await
            .is_ok()
            {
                state.events.emit_worker_control(WorkerControlEvent {
                    action: "pause_scan_run".to_string(),
                    scan_run_id: Some(run.id),
                    chunk_id: None,
                    grace_seconds: Some(3),
                });
                emit_scan_status_ui(
                    state,
                    run.id,
                    &run.status,
                    next_status,
                    Some("time_window_closed".to_string()),
                );
            }
        }
    }

    // 3. Auto-resume paused scheduled/sampling runs when allowed window reopens
    let paused_runs: Vec<WindowManagedRunRow> = sqlx::query_as(
        r#"
        SELECT sr.id, sr.status, sr.completed_chunks, sp.time_windows
        FROM scan_runs sr
        INNER JOIN asset_groups ag ON ag.id = sr.asset_group_id
        INNER JOIN scan_policies sp ON sp.id = ag.policy_id
        WHERE sr.trigger_type IN ('scheduled', 'sampling')
          AND sr.status = 'paused'
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("paused window query: {e}"))?;

    for run in paused_runs {
        if is_within_allowed_windows(&run.time_windows, now) {
            let next_status = if run.completed_chunks > 0 {
                "running"
            } else {
                "queued"
            };
            if sqlx::query(
                "UPDATE scan_runs SET status = $1, cancel_requested_at = NULL WHERE id = $2",
            )
            .bind(next_status)
            .bind(run.id)
            .execute(pool)
            .await
            .is_ok()
            {
                emit_scan_status_ui(
                    state,
                    run.id,
                    &run.status,
                    next_status,
                    Some("time_window_opened".to_string()),
                );
            }
        }
    }

    // 4. Trigger diurnal 4-slot sampling runs
    let current_slot = TimeSlot::from_utc_hour(now.hour());
    let slot_start = now
        .date_naive()
        .and_hms_opt((now.hour() / 6) * 6, 0, 0)
        .map(|ndt| ndt.and_utc())
        .unwrap_or(now);

    let candidates: Vec<SamplingCandidateRow> = sqlx::query_as(
        r#"
        SELECT ag.id AS asset_group_id, sp.time_windows
        FROM asset_groups ag
        INNER JOIN scan_policies sp ON sp.id = ag.policy_id
        WHERE ag.sampling_enabled = TRUE
          AND EXISTS (
              SELECT 1 FROM asset_group_targets agt
              WHERE agt.asset_group_id = ag.id AND agt.target_type <> 'exclude_cidr'
          )
          AND NOT EXISTS (
              SELECT 1 FROM scan_runs sr
              WHERE sr.asset_group_id = ag.id
                AND sr.status IN ('queued', 'running', 'pausing', 'paused')
          )
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("sampling candidates query: {e}"))?;

    for candidate in candidates {
        let already_ran: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM scan_runs
                WHERE asset_group_id = $1
                  AND trigger_type = 'sampling'
                  AND time_slot = $2
                  AND started_at >= $3
            )
            "#,
        )
        .bind(candidate.asset_group_id)
        .bind(current_slot.as_db_str())
        .bind(slot_start)
        .fetch_one(pool)
        .await
        .unwrap_or(true);

        if let Some(slot) = should_trigger_sampling_slot(&candidate.time_windows, now, already_ran)
        {
            if let Err(err) = enqueue_scan_run_for_group(EnqueueScanParams {
                state,
                pool,
                asset_group_id: candidate.asset_group_id,
                trigger: ScanTriggerType::Sampling,
                time_slot: Some(slot),
                started_by: None,
                include_ignored_ids: Vec::new(),
                include_all_ignored: false,
                source_ip: None,
                request_id: None,
                instance: "internal://scheduler/sampling",
            })
            .await
            {
                tracing::debug!(
                    asset_group_id = %candidate.asset_group_id,
                    error = ?err,
                    "skipped scheduled sampling enqueue"
                );
            }
        }
    }

    // 5. Trigger user-defined recurring group scan schedules
    #[derive(FromRow)]
    struct DueRecurringRow {
        id: Uuid,
        asset_group_id: Uuid,
        interval_value: i32,
        interval_unit: String,
        include_all_ignored: bool,
        include_ignored_ids: Vec<Uuid>,
    }

    let due_schedules: Vec<DueRecurringRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, interval_value, interval_unit,
               include_all_ignored, include_ignored_ids
        FROM recurring_scan_schedules
        WHERE next_run_at <= $1
        ORDER BY next_run_at ASC
        "#,
    )
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("recurring schedules query: {e}"))?;

    for sched in due_schedules {
        let active_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM scan_runs
                WHERE asset_group_id = $1
                  AND status IN ('queued', 'running', 'pausing', 'paused')
            )
            "#,
        )
        .bind(sched.asset_group_id)
        .fetch_one(pool)
        .await
        .unwrap_or(false);

        let step_minutes = if sched.interval_unit == "hours" {
            i64::from(sched.interval_value).saturating_mul(60)
        } else {
            i64::from(sched.interval_value)
        }
        .max(1);
        let next_run_at = now + chrono::Duration::minutes(step_minutes);

        if active_exists {
            let _ = sqlx::query(
                "UPDATE recurring_scan_schedules SET next_run_at = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(next_run_at)
            .bind(sched.id)
            .execute(pool)
            .await;
            continue;
        }

        match enqueue_scan_run_for_group(EnqueueScanParams {
            state,
            pool,
            asset_group_id: sched.asset_group_id,
            trigger: ScanTriggerType::Scheduled,
            time_slot: None,
            started_by: None,
            include_ignored_ids: sched.include_ignored_ids,
            include_all_ignored: sched.include_all_ignored,
            source_ip: None,
            request_id: None,
            instance: "internal://scheduler/recurring",
        })
        .await
        {
            Ok(run_dto) => {
                let _ = sqlx::query(
                    r#"
                    UPDATE recurring_scan_schedules
                    SET last_run_at = $1,
                        last_scan_run_id = $2,
                        next_run_at = $3,
                        updated_at = NOW()
                    WHERE id = $4
                    "#,
                )
                .bind(now)
                .bind(run_dto.id)
                .bind(next_run_at)
                .bind(sched.id)
                .execute(pool)
                .await;
            }
            Err(err) => {
                tracing::debug!(
                    schedule_id = %sched.id,
                    error = ?err,
                    "skipped due recurring scan schedule"
                );
                let _ = sqlx::query(
                    "UPDATE recurring_scan_schedules SET next_run_at = $1, updated_at = NOW() WHERE id = $2",
                )
                .bind(next_run_at)
                .bind(sched.id)
                .execute(pool)
                .await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_windows_handles_daytime_and_overnight_ranges() {
        let daytime = serde_json::json!({
            "allowed_windows": [
                { "start": "08:00", "end": "18:00", "timezone": "UTC" }
            ]
        });
        let noon_utc = NaiveDate::from_ymd_opt(2026, 11, 21)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc();
        let night_utc = NaiveDate::from_ymd_opt(2026, 11, 21)
            .unwrap()
            .and_hms_opt(22, 30, 0)
            .unwrap()
            .and_utc();
        assert!(is_within_allowed_windows(&daytime, noon_utc));
        assert!(!is_within_allowed_windows(&daytime, night_utc));

        let overnight = serde_json::json!({
            "allowed_windows": [
                { "start": "22:00", "end": "06:00", "timezone": "UTC" }
            ]
        });
        assert!(is_within_allowed_windows(&overnight, night_utc));
        assert!(!is_within_allowed_windows(&overnight, noon_utc));
    }

    #[test]
    fn sampling_slot_triggers_once_per_slot_within_window() {
        let tw = serde_json::json!({
            "allowed_windows": [
                { "start": "00:00", "end": "23:59", "timezone": "UTC" }
            ],
            "sampling_slots": ["06_12", "18_24"]
        });
        let slot_06_12 = NaiveDate::from_ymd_opt(2026, 11, 21)
            .unwrap()
            .and_hms_opt(8, 0, 0)
            .unwrap()
            .and_utc();
        let slot_12_18 = NaiveDate::from_ymd_opt(2026, 11, 21)
            .unwrap()
            .and_hms_opt(14, 0, 0)
            .unwrap()
            .and_utc();

        assert_eq!(
            should_trigger_sampling_slot(&tw, slot_06_12, false),
            Some(TimeSlot::Slot0612)
        );
        assert_eq!(should_trigger_sampling_slot(&tw, slot_06_12, true), None);
        assert_eq!(should_trigger_sampling_slot(&tw, slot_12_18, false), None);
    }
}
