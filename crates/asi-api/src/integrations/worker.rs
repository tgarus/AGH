//! Wątki tła integracji DefectDojo: outbox (ASI -> DD) i pull (DD -> ASI).

use std::time::Duration;

use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

use crate::app::AppState;
use crate::integrations::push::{
    dd_client, load_config, pull_dd_statuses, push_diff_event, push_scan_run,
    DD_RETRY_DELAYS_SECONDS,
};

const OUTBOX_POLL_SECONDS: u64 = 10;
const PULL_CHECK_SECONDS: u64 = 60;

#[derive(Debug, Clone)]
struct OutboxRow {
    id: Uuid,
    kind: String,
    asset_group_id: Uuid,
    scan_run_id: Option<Uuid>,
    diff_event_id: Option<Uuid>,
    attempt_count: i32,
}

/// Uruchamia oba wątki integracji; zwraca uchwyty do wygaszenia przy shutdown.
pub fn spawn_dd_workers(
    state: AppState,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let outbox_state = state.clone();
    let outbox = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(OUTBOX_POLL_SECONDS));
        loop {
            ticker.tick().await;
            if let Err(err) = process_outbox_due(&outbox_state).await {
                tracing::warn!(error = %err, "dd outbox tick error");
            }
        }
    });

    let pull_state = state.clone();
    let pull = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(PULL_CHECK_SECONDS));
        loop {
            ticker.tick().await;
            if let Err(err) = maybe_pull(&pull_state).await {
                tracing::warn!(error = %err, "dd pull tick error");
            }
        }
    });

    (outbox, pull)
}

pub async fn process_outbox_due(state: &AppState) -> Result<(), String> {
    let Some(pool) = state.db.as_ref() else {
        return Ok(());
    };
    let Some(cfg) = load_config(pool, &state.secret_box).await? else {
        return Ok(()); // integracja wylaczona — outbox czeka
    };
    let client = dd_client(&cfg)?;

    // Odzysk po „osieroconych” wpisach: proces mógł paść między claim a sent — wracają do kolejki.
    sqlx::query(
        r#"UPDATE dd_outbox
           SET status = 'pending', updated_at = NOW()
           WHERE status = 'processing'
             AND updated_at < NOW() - INTERVAL '5 minutes'"#,
    )
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    let rows = sqlx::query(
        r#"
        UPDATE dd_outbox
        SET status = 'processing', updated_at = NOW()
        WHERE id IN (
            SELECT id FROM dd_outbox
            WHERE (
                status = 'pending'
                AND (next_retry_at IS NULL OR next_retry_at <= NOW())
            ) OR (
                status = 'failed'
                AND next_retry_at IS NOT NULL
                AND next_retry_at <= NOW()
            )
            ORDER BY created_at
            LIMIT 10
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, kind, asset_group_id, scan_run_id, diff_event_id, attempt_count
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let had_rows = !rows.is_empty();
    for row in rows {
        let item = OutboxRow {
            id: row.get("id"),
            kind: row.get("kind"),
            asset_group_id: row.get("asset_group_id"),
            scan_run_id: row.get("scan_run_id"),
            diff_event_id: row.get("diff_event_id"),
            attempt_count: row.get("attempt_count"),
        };
        let result = match item.kind.as_str() {
            "diff_event" => match item.diff_event_id {
                Some(diff_id) => push_diff_event(pool, &cfg, &client, diff_id)
                    .await
                    .map(|fid| fid.to_string()),
                None => Err("diff_event outbox row without diff_event_id".to_string()),
            },
            "scan_run" | "manual_sync" => match item.scan_run_id {
                Some(run_id) => push_scan_run(pool, &cfg, &client, &state.events, run_id)
                    .await
                    .map(|n| n.to_string()),
                None => {
                    // manual_sync bez runa: push ostatniego completed runa grupy (lub wszystkie diffy grupy)
                    push_manual_group(pool, &cfg, &client, &state.events, item.asset_group_id).await
                }
            },
            other => Err(format!("unknown outbox kind {other}")),
        };

        match result {
            Ok(info) => {
                sqlx::query(
                    r#"UPDATE dd_outbox SET status = 'sent', last_error = NULL, updated_at = NOW() WHERE id = $1"#,
                )
                .bind(item.id)
                .execute(pool)
                .await
                .map_err(|e| e.to_string())?;
                let _ = sqlx::query(
                    "UPDATE defectdojo_config SET last_error = NULL, updated_at = NOW() WHERE id = TRUE AND last_error IS NOT NULL",
                )
                .execute(pool)
                .await;
                let ev_id = Uuid::new_v4();
                state.events.emit_ui(
                    "defectdojo.outbox",
                    ev_id,
                    serde_json::json!({
                        "event_id": ev_id,
                        "occurred_at": Utc::now(),
                        "outbox_id": item.id,
                        "kind": item.kind,
                        "status": "sent",
                        "detail": info,
                    }),
                );
            }
            Err(err) => {
                let attempt = item.attempt_count.saturating_add(1);
                let delay = DD_RETRY_DELAYS_SECONDS
                    .get(usize::try_from(attempt - 1).unwrap_or(usize::MAX))
                    .copied();
                let next_retry = delay.map(|d| Utc::now() + chrono::Duration::seconds(d));
                sqlx::query(
                    r#"UPDATE dd_outbox
                       SET status = 'failed', attempt_count = $2, last_error = $3,
                           next_retry_at = $4, updated_at = NOW()
                       WHERE id = $1"#,
                )
                .bind(item.id)
                .bind(attempt)
                .bind(truncate_err(&err))
                .bind(next_retry)
                .execute(pool)
                .await
                .map_err(|e| e.to_string())?;
                sqlx::query(
                    "UPDATE defectdojo_config SET last_error = $1, updated_at = NOW() WHERE id = TRUE",
                )
                .bind(truncate_err(&err))
                .execute(pool)
                .await
                .map_err(|e| e.to_string())?;
            }
        }
    }

    if had_rows {
        sqlx::query(
            "UPDATE defectdojo_config SET last_push_at = NOW(), updated_at = NOW() WHERE id = TRUE",
        )
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// manual_sync: push ostatniego ukończonego runa grupy; gdy brak runa — push wszystkich diffów grupy.
async fn push_manual_group(
    pool: &sqlx::PgPool,
    cfg: &crate::integrations::push::LoadedDdConfig,
    client: &crate::integrations::defectdojo::DdClient,
    events: &crate::sse::EventHub,
    group_id: Uuid,
) -> Result<String, String> {
    let last_run: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM scan_runs WHERE asset_group_id = $1 AND status = 'completed' ORDER BY finished_at DESC NULLS LAST LIMIT 1",
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    if let Some(run_id) = last_run {
        let n = push_scan_run(pool, cfg, client, events, run_id).await?;
        return Ok(format!("run {run_id}: pushed {n} findings"));
    }

    let diff_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT de.id FROM diff_events de
           JOIN hosts h ON h.id = de.host_id
           WHERE h.asset_group_id = $1 ORDER BY de.detected_at DESC LIMIT 500"#,
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
    let mut n = 0_usize;
    let mut last_err: Option<String> = None;
    for d in diff_ids {
        match push_diff_event(pool, cfg, client, d).await {
            Ok(_) => n += 1,
            Err(e) => {
                if !e.contains("poza scope") {
                    last_err = Some(e);
                }
            }
        }
    }
    if cfg.finding_scope == asi_common::defectdojo::DdFindingScope::Inventory {
        match crate::integrations::push::push_group_inventory_hosts(pool, cfg, client, group_id)
            .await
        {
            Ok(inv_n) => n += inv_n,
            Err(e) => last_err = Some(e),
        }
    }
    if let Some(e) = last_err {
        return Err(e);
    }
    Ok(format!("group {group_id}: pushed {n} findings (no runs)"))
}

async fn maybe_pull(state: &AppState) -> Result<(), String> {
    let Some(pool) = state.db.as_ref() else {
        return Ok(());
    };
    let Some(cfg) = load_config(pool, &state.secret_box).await? else {
        return Ok(());
    };
    let interval_min = cfg.pull_interval_minutes.max(1) as i64;
    let due: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_pull_at FROM defectdojo_config WHERE id = TRUE")
            .fetch_optional(pool)
            .await
            .map_err(|e| e.to_string())?
            .flatten();
    let due = match due {
        Some(t) if Utc::now() - t < chrono::Duration::minutes(interval_min) => return Ok(()),
        _ => true,
    };
    let _ = due;
    let client = dd_client(&cfg)?;
    let updated = pull_dd_statuses(pool, &client, &state.events).await?;
    if updated > 0 {
        tracing::info!(updated, "defectdojo pull updated findings");
    }
    Ok(())
}

fn truncate_err(s: &str) -> String {
    s.chars().take(500).collect()
}
