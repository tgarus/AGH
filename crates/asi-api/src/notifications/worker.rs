use std::time::Duration;

use asi_common::diff::{BulletItem, DiffEventKind, DiffSeverity};
use asi_common::notification::{NotificationChannelType, NotificationMessage};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use sqlx::{FromRow, PgConnection, PgPool};
use uuid::Uuid;

use crate::app::AppState;
use crate::notifications::sinks::build_sink;

const WORKER_POLL_SECONDS: u64 = 5;
pub const RETRY_DELAYS_SECONDS: [i64; 5] = [10, 30, 120, 600, 1800];

#[derive(FromRow)]
struct PendingDeliveryRow {
    delivery_id: Uuid,
    attempt_count: i32,
    event_type: String,
    custom_payload: Option<serde_json::Value>,
    channel_type: String,
    config_public: serde_json::Value,
    secret_ciphertext: Option<Vec<u8>>,
    secret_nonce: Option<Vec<u8>>,
    diff_event_id: Option<Uuid>,
    host_id: Option<Uuid>,
    asset_group_name: Option<String>,
    ip_addr: Option<IpNetwork>,
    event_kind: Option<String>,
    severity: Option<String>,
    bullet_items: Option<serde_json::Value>,
    detected_at: Option<DateTime<Utc>>,
}

#[must_use]
pub fn next_retry_delay_seconds(failed_attempt: i32) -> Option<i64> {
    if failed_attempt <= 0 {
        return None;
    }
    let idx = usize::try_from(failed_attempt - 1).ok()?;
    RETRY_DELAYS_SECONDS.get(idx).copied()
}

pub async fn enqueue_notifications_for_diff(
    conn: &mut PgConnection,
    asset_group_id: Uuid,
    diff_event_id: Uuid,
    event_kind: DiffEventKind,
) -> Result<(), sqlx::Error> {
    let is_confirmed = event_kind == DiffEventKind::ConfirmedChange;
    let event_type = if is_confirmed {
        "diff.confirmed_change"
    } else {
        "diff.active_variance"
    };
    sqlx::query(
        r#"
        INSERT INTO notification_deliveries (
            channel_id, diff_event_id, event_type, status, attempt_count, next_retry_at
        )
        SELECT nc.id, $1, $4, 'pending', 0, NOW()
        FROM notification_channels nc
        INNER JOIN diff_events de ON de.id = $1
        WHERE nc.is_enabled = TRUE
          AND (nc.asset_group_id IS NULL OR nc.asset_group_id = $2)
          AND (
              (($3 = TRUE AND nc.notify_on_confirmed = TRUE) AND 'diff.confirmed_change' = ANY(nc.subscribed_events))
              OR (($3 = FALSE AND nc.notify_on_variance = TRUE) AND 'diff.active_variance' = ANY(nc.subscribed_events))
              OR (
                  'host.new_discovered' = ANY(nc.subscribed_events)
                  AND de.bullet_items @> '[{"key": "host_discovered"}]'::jsonb
              )
              OR (
                  'host.admin_panel_detected' = ANY(nc.subscribed_events)
                  AND de.bullet_items @> '[{"key": "admin_panel_detected"}]'::jsonb
              )
              OR (
                  'host.anomaly_detected' = ANY(nc.subscribed_events)
                  AND (
                      de.bullet_items @> '[{"key": "probable_tarpit_detected"}]'::jsonb
                      OR de.bullet_items @> '[{"key": "diurnal_variance"}]'::jsonb
                  )
              )
          )
        "#,
    )
    .bind(diff_event_id)
    .bind(asset_group_id)
    .bind(is_confirmed)
    .bind(event_type)
    .execute(&mut *conn)
    .await?;

    Ok(())
}

pub async fn enqueue_webhook_event(
    pool: &PgPool,
    asset_group_id: Option<Uuid>,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO notification_deliveries (
            channel_id, diff_event_id, event_type, custom_payload, status, attempt_count, next_retry_at
        )
        SELECT id, NULL, $1, $2, 'pending', 0, NOW()
        FROM notification_channels
        WHERE is_enabled = TRUE
          AND $1 = ANY(subscribed_events)
          AND (asset_group_id IS NULL OR $3::uuid IS NULL OR asset_group_id = $3)
        "#,
    )
    .bind(event_type)
    .bind(payload)
    .bind(asset_group_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub fn spawn_notification_worker(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(WORKER_POLL_SECONDS));
        loop {
            ticker.tick().await;
            if let Some(pool) = state.db.as_ref() {
                if let Err(err) = process_pending_deliveries(&state, pool).await {
                    tracing::warn!(error = %err, "notification delivery tick error");
                }
            }
        }
    })
}

async fn process_pending_deliveries(state: &AppState, pool: &PgPool) -> Result<(), String> {
    let rows: Vec<PendingDeliveryRow> = sqlx::query_as(
        r#"
        SELECT nd.id AS delivery_id, nd.attempt_count, nd.event_type, nd.custom_payload,
               nc.channel_type, nc.config_public, nc.secret_ciphertext, nc.secret_nonce,
               de.id AS diff_event_id, de.host_id, ag.name AS asset_group_name,
               h.ip_addr, de.event_kind, de.severity, de.bullet_items, de.detected_at
        FROM notification_deliveries nd
        INNER JOIN notification_channels nc ON nc.id = nd.channel_id
        LEFT JOIN diff_events de ON de.id = nd.diff_event_id
        LEFT JOIN hosts h ON h.id = de.host_id
        LEFT JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE nd.status = 'pending'
          AND (nd.next_retry_at IS NULL OR nd.next_retry_at <= NOW())
        ORDER BY nd.created_at ASC
        LIMIT 20
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("fetch pending deliveries: {e}"))?;

    for row in rows {
        let dispatch_res = dispatch_single_delivery(state, &row).await;
        match dispatch_res {
            Ok(()) => {
                let _ = sqlx::query(
                    r#"
                    UPDATE notification_deliveries
                    SET status = 'sent',
                        attempt_count = attempt_count + 1,
                        next_retry_at = NULL,
                        last_error = NULL,
                        sent_at = NOW()
                    WHERE id = $1
                    "#,
                )
                .bind(row.delivery_id)
                .execute(pool)
                .await;
            }
            Err(err_msg) => {
                let next_attempt = row.attempt_count.saturating_add(1);
                if let Some(delay_secs) = next_retry_delay_seconds(next_attempt) {
                    let retry_at = Utc::now() + chrono::Duration::seconds(delay_secs);
                    let _ = sqlx::query(
                        r#"
                        UPDATE notification_deliveries
                        SET attempt_count = $1,
                            next_retry_at = $2,
                            last_error = $3
                        WHERE id = $4
                        "#,
                    )
                    .bind(next_attempt)
                    .bind(retry_at)
                    .bind(&err_msg)
                    .bind(row.delivery_id)
                    .execute(pool)
                    .await;
                } else {
                    let _ = sqlx::query(
                        r#"
                        UPDATE notification_deliveries
                        SET status = 'failed',
                            attempt_count = $1,
                            next_retry_at = NULL,
                            last_error = $2
                        WHERE id = $3
                        "#,
                    )
                    .bind(next_attempt)
                    .bind(&err_msg)
                    .bind(row.delivery_id)
                    .execute(pool)
                    .await;
                }
            }
        }
    }

    Ok(())
}

async fn dispatch_single_delivery(
    state: &AppState,
    row: &PendingDeliveryRow,
) -> Result<(), String> {
    let channel_type = NotificationChannelType::from_db_str(&row.channel_type)
        .ok_or_else(|| format!("unknown channel_type '{}'", row.channel_type))?;

    let decrypted_secret = match (&row.secret_ciphertext, &row.secret_nonce) {
        (Some(ct), Some(nonce)) => {
            let bytes = state
                .secret_box
                .decrypt(ct, nonce)
                .map_err(|e| e.to_string())?;
            Some(
                String::from_utf8(bytes)
                    .map_err(|e| format!("channel secret is not valid UTF-8: {e}"))?,
            )
        }
        _ => None,
    };

    let sink = build_sink(
        channel_type,
        &row.config_public,
        decrypted_secret.as_deref(),
    )
    .map_err(|e| e.to_string())?;

    if let (
        Some(diff_event_id),
        Some(host_id),
        Some(ip_addr),
        Some(event_kind_str),
        Some(detected_at),
    ) = (
        row.diff_event_id,
        row.host_id,
        row.ip_addr,
        row.event_kind.as_deref(),
        row.detected_at,
    ) {
        if row.custom_payload.is_none() {
            let event_kind = DiffEventKind::from_db_str(event_kind_str)
                .ok_or_else(|| format!("unknown event_kind '{event_kind_str}'"))?;
            let severity = row
                .severity
                .as_deref()
                .and_then(DiffSeverity::from_db_str)
                .unwrap_or(DiffSeverity::Info);
            let bullet_items: Vec<BulletItem> = row
                .bullet_items
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let msg = NotificationMessage {
                delivery_id: row.delivery_id,
                diff_event_id,
                asset_group_name: row
                    .asset_group_name
                    .clone()
                    .unwrap_or_else(|| "ASI".to_string()),
                host_id,
                ip_addr: ip_addr.ip(),
                event_kind,
                severity,
                bullet_items,
                detected_at,
            };

            return sink.send(&msg).await.map_err(|e| e.to_string());
        }
    }

    let custom_payload = row
        .custom_payload
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    sink.send_custom_event(&row.event_type, row.delivery_id, &custom_payload)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_schedule_matches_standard_and_stops_at_five() {
        assert_eq!(next_retry_delay_seconds(0), None);
        assert_eq!(next_retry_delay_seconds(1), Some(10));
        assert_eq!(next_retry_delay_seconds(2), Some(30));
        assert_eq!(next_retry_delay_seconds(3), Some(120));
        assert_eq!(next_retry_delay_seconds(4), Some(600));
        assert_eq!(next_retry_delay_seconds(5), Some(1800));
        assert_eq!(next_retry_delay_seconds(6), None);
    }
}
