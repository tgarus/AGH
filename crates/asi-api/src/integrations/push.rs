//! Logika wysyłki ASI -> DefectDojo (outbox enqueue + push) oraz pull DD -> ASI.

use asi_common::defectdojo::{
    dd_finding_description, dd_finding_title, dd_numerical_severity, dd_severity, DdFindingScope,
    DdFindingUpsert,
};
use asi_common::diff::{BulletItem, DiffEventKind};
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::audit::{insert_audit_log, AuditRecord};
use crate::integrations::defectdojo::{DdClient, DD_TEST_TYPE_NAME};
use crate::security::crypto::SecretBox;
use crate::sse::EventHub;

pub const DD_RETRY_DELAYS_SECONDS: [i64; 5] = [10, 30, 120, 600, 1800];

/// Konfiguracja integracji odczytana z bazy (api_key juz odszyfrowany).
pub struct LoadedDdConfig {
    pub base_url: String,
    pub asi_public_url: String,
    pub api_key: String,
    pub finding_scope: DdFindingScope,
    pub auto_push: bool,
    pub pull_interval_minutes: i32,
}

pub async fn load_config(
    pool: &PgPool,
    secret_box: &SecretBox,
) -> Result<Option<LoadedDdConfig>, String> {
    let row = sqlx::query(
        r#"SELECT base_url, asi_public_url, api_key_ciphertext, api_key_nonce,
                  finding_scope, auto_push, pull_interval_minutes, enabled
           FROM defectdojo_config WHERE id = TRUE"#,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("dd config read: {e}"))?;

    let Some(row) = row else {
        return Ok(None);
    };
    let enabled: bool = row.get("enabled");
    if !enabled {
        return Ok(None);
    }
    let base_url: String = row.get("base_url");
    let asi_public_url: String = row.get("asi_public_url");
    let scope_raw: String = row.get("finding_scope");
    let scope = DdFindingScope::from_db_str(&scope_raw).unwrap_or(DdFindingScope::Changes);
    let cipher: Option<Vec<u8>> = row.get("api_key_ciphertext");
    let nonce: Option<Vec<u8>> = row.get("api_key_nonce");
    let api_key = match (cipher, nonce) {
        (Some(c), Some(n)) => String::from_utf8(
            secret_box
                .decrypt(&c, &n)
                .map_err(|e| format!("dd api key decrypt: {e}"))?,
        )
        .map_err(|e| format!("dd api key utf8: {e}"))?,
        _ => return Ok(None), // brak klucza = integracja wylaczona
    };
    Ok(Some(LoadedDdConfig {
        base_url,
        asi_public_url,
        api_key,
        finding_scope: scope,
        auto_push: row.get("auto_push"),
        pull_interval_minutes: row.get("pull_interval_minutes"),
    }))
}

pub fn dd_client(cfg: &LoadedDdConfig) -> Result<DdClient, String> {
    DdClient::new(&cfg.base_url, &cfg.api_key).map_err(|e| e.to_string())
}

/// Enqueue pojedynczego diff_event (hook z diff engine) — z uwzglednieniem scope.
pub async fn enqueue_dd_for_diff(
    conn: &mut PgConnection,
    asset_group_id: Uuid,
    diff_event_id: Uuid,
    event_kind: DiffEventKind,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO dd_outbox (kind, asset_group_id, diff_event_id)
        SELECT 'diff_event', $1, $2
        WHERE EXISTS (
            SELECT 1 FROM defectdojo_config
            WHERE id = TRUE AND enabled = TRUE AND auto_push = TRUE
              AND (
                  (finding_scope = 'changes' AND $3 = 'confirmed_change')
                  OR finding_scope IN ('all_diffs', 'inventory')
              )
        )
        AND NOT EXISTS (
            SELECT 1 FROM dd_outbox
            WHERE diff_event_id = $2 AND status IN ('pending', 'processing', 'sent')
        )
        "#,
    )
    .bind(asset_group_id)
    .bind(diff_event_id)
    .bind(event_kind.as_db_str())
    .execute(conn)
    .await?;
    Ok(())
}

/// Enqueue pushu calego zakończonego scan runa (hook przy finalizacji runa).
pub async fn enqueue_dd_for_run(
    conn: &mut PgConnection,
    asset_group_id: Uuid,
    scan_run_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO dd_outbox (kind, asset_group_id, scan_run_id)
        SELECT 'scan_run', $1, $2
        WHERE EXISTS (SELECT 1 FROM defectdojo_config WHERE id = TRUE AND enabled = TRUE AND auto_push = TRUE)
        AND NOT EXISTS (SELECT 1 FROM dd_outbox WHERE scan_run_id = $2 AND status IN ('pending','processing','sent'))
        "#,
    )
    .bind(asset_group_id)
    .bind(scan_run_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// Reczny sync z UI: jedna grupa (Some) albo wszystkie grupy z targetami (None).
pub async fn enqueue_manual_sync(
    pool: &PgPool,
    asset_group_id: Option<Uuid>,
) -> Result<i64, String> {
    let rows = match asset_group_id {
        Some(gid) => sqlx::query(
            r#"INSERT INTO dd_outbox (kind, asset_group_id)
               SELECT 'manual_sync', id FROM asset_groups WHERE id = $1
               AND NOT EXISTS (SELECT 1 FROM dd_outbox o WHERE o.asset_group_id = $1 AND o.kind='manual_sync' AND o.status IN ('pending','processing'))
               RETURNING id"#,
        )
        .bind(gid)
        .fetch_all(pool)
        .await
        .map_err(|e| e.to_string())?,
        None => sqlx::query(
            r#"INSERT INTO dd_outbox (kind, asset_group_id)
               SELECT 'manual_sync', ag.id FROM asset_groups ag
               WHERE EXISTS (SELECT 1 FROM asset_group_targets t WHERE t.asset_group_id = ag.id AND t.target_type <> 'exclude_cidr')
               AND NOT EXISTS (SELECT 1 FROM dd_outbox o WHERE o.asset_group_id = ag.id AND o.kind='manual_sync' AND o.status IN ('pending','processing'))
               RETURNING id"#,
        )
        .fetch_all(pool)
        .await
        .map_err(|e| e.to_string())?,
    };
    Ok(i64::try_from(rows.len()).unwrap_or(i64::MAX))
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

struct DiffRow {
    host_id: Uuid,
    ip_addr: String,
    scan_run_id: Option<Uuid>,
    event_kind: String,
    severity: String,
    bullet_items: serde_json::Value,
    detected_at: DateTime<Utc>,
    group_id: Uuid,
    group_name: String,
    group_description: Option<String>,
    run_started_at: Option<DateTime<Utc>>,
    run_finished_at: Option<DateTime<Utc>>,
}

async fn load_diff_row(pool: &PgPool, diff_id: Uuid) -> Result<DiffRow, String> {
    sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Option<Uuid>,
            String,
            String,
            serde_json::Value,
            DateTime<Utc>,
            Uuid,
            String,
            Option<String>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        ),
    >(
        r#"
        SELECT de.host_id, h.ip_addr::text, de.scan_run_id, de.event_kind, de.severity,
               de.bullet_items, de.detected_at,
               ag.id, ag.name, ag.description,
               sr.started_at, sr.finished_at
        FROM diff_events de
        JOIN hosts h ON h.id = de.host_id
        JOIN asset_groups ag ON ag.id = h.asset_group_id
        LEFT JOIN scan_runs sr ON sr.id = de.scan_run_id
        WHERE de.id = $1
        "#,
    )
    .bind(diff_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?
    .map(
        |(
            host_id,
            ip_addr,
            scan_run_id,
            event_kind,
            severity,
            bullet_items,
            detected_at,
            group_id,
            group_name,
            group_description,
            run_started_at,
            run_finished_at,
        )| DiffRow {
            host_id,
            ip_addr,
            scan_run_id,
            event_kind,
            severity,
            bullet_items,
            detected_at,
            group_id,
            group_name,
            group_description,
            run_started_at,
            run_finished_at,
        },
    )
    .ok_or_else(|| format!("diff_event {diff_id} not found"))
}

fn parse_bullets(raw: &serde_json::Value) -> Vec<BulletItem> {
    serde_json::from_value(raw.clone()).unwrap_or_default()
}

fn severity_from_db(raw: &str) -> asi_common::diff::DiffSeverity {
    asi_common::diff::DiffSeverity::from_db_str(raw).unwrap_or(asi_common::diff::DiffSeverity::Info)
}

fn kind_from_db(raw: &str) -> DiffEventKind {
    DiffEventKind::from_db_str(raw).unwrap_or(DiffEventKind::ConfirmedChange)
}

fn component_from_bullets(bullets: &[BulletItem]) -> Option<String> {
    bullets.iter().find_map(|b| {
        b.params
            .get("service")
            .or_else(|| b.params.get("technology"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    })
}

/// Zapewnia Product+Engagement+Test dla grupy/runa i zwraca (product_id, engagement_id, test_id).
async fn ensure_dd_hierarchy(
    client: &DdClient,
    pool: &PgPool,
    row: &DiffRow,
) -> Result<(i32, i32, i32), String> {
    let product_id = client
        .ensure_product(
            &row.group_name,
            row.group_description.as_deref().unwrap_or(""),
        )
        .await?;
    sqlx::query(
        r#"UPDATE asset_groups
           SET external_refs = jsonb_set(COALESCE(external_refs,'{}'::jsonb), '{defectdojo,product_id}', to_jsonb($2::int))
           WHERE id = $1"#,
    )
    .bind(row.group_id)
    .bind(product_id)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    let started = row.run_started_at.unwrap_or_else(Utc::now);
    let run_label = row
        .scan_run_id
        .map(|id| id.to_string()[..8].to_string())
        .unwrap_or_else(|| "manual".to_string());
    let engagement_id = client
        .ensure_engagement(product_id, &run_label, started, row.run_finished_at)
        .await?;
    let test_type_id = client.ensure_test_type().await?;
    let test_id = client
        .ensure_test(
            engagement_id,
            test_type_id,
            &run_label,
            started,
            row.run_finished_at,
        )
        .await?;
    if let Some(run_id) = row.scan_run_id {
        sqlx::query(
            r#"UPDATE scan_runs
               SET external_refs = jsonb_set(jsonb_set(COALESCE(external_refs,'{}'::jsonb), '{defectdojo,engagement_id}', to_jsonb($2::int)), '{defectdojo,test_id}', to_jsonb($3::int))
               WHERE id = $1"#,
        )
        .bind(run_id)
        .bind(engagement_id)
        .bind(test_id)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
    }
    Ok((product_id, engagement_id, test_id))
}

fn dd_references(cfg: &LoadedDdConfig, diff_id: Uuid) -> Option<String> {
    if cfg.asi_public_url.is_empty() {
        Some(format!("asi://diffs/{diff_id}"))
    } else {
        Some(format!(
            "{}/diffs/{diff_id}",
            cfg.asi_public_url.trim_end_matches('/')
        ))
    }
}

/// Push pojedynczego diff_event do DD. Zwraca dd_finding_id.
pub async fn push_diff_event(
    pool: &PgPool,
    cfg: &LoadedDdConfig,
    client: &DdClient,
    diff_id: Uuid,
) -> Result<i32, String> {
    let row = load_diff_row(pool, diff_id).await?;
    if !cfg.finding_scope.includes(kind_from_db(&row.event_kind)) {
        return Err(format!(
            "diff {} poza scope {:?} — pomijam",
            diff_id, cfg.finding_scope
        ));
    }
    let (product_id, engagement_id, test_id) = ensure_dd_hierarchy(client, pool, &row).await?;

    let bullets = parse_bullets(&row.bullet_items);
    let kind = kind_from_db(&row.event_kind);
    let severity = severity_from_db(&row.severity);
    let payload = DdFindingUpsert {
        title: dd_finding_title(kind, severity, &bullets, &row.ip_addr),
        description: dd_finding_description(
            &bullets,
            &format!("host {} (diff {})", row.ip_addr, diff_id),
        ),
        severity: dd_severity(severity).to_string(),
        date: row.detected_at.format("%Y-%m-%d").to_string(),
        test: test_id,
        found_by: vec![test_id],
        numerical_severity: dd_numerical_severity(severity).to_string(),
        unique_id_from_tool: diff_id.to_string(),
        component_name: component_from_bullets(&bullets),
        references: dd_references(cfg, diff_id),
        tags: vec![
            "asi".to_string(),
            row.group_name.clone(),
            kind.as_db_str().to_string(),
        ],
        active: true,
        verified: false,
    };
    let finding_id = client.upsert_finding(&payload).await?;

    let tags_json = serde_json::to_value(&payload.tags).unwrap_or_default();
    sqlx::query(
        r#"
        INSERT INTO dd_links (diff_event_id, host_id, asset_group_id, scan_run_id,
                              dd_product_id, dd_engagement_id, dd_test_id, dd_finding_id,
                              dd_finding_status, dd_tags, last_pushed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, NOW())
        ON CONFLICT (diff_event_id) DO UPDATE SET
            dd_product_id = EXCLUDED.dd_product_id,
            dd_engagement_id = EXCLUDED.dd_engagement_id,
            dd_test_id = EXCLUDED.dd_test_id,
            dd_finding_id = EXCLUDED.dd_finding_id,
            dd_tags = EXCLUDED.dd_tags,
            last_pushed_at = NOW()
        "#,
    )
    .bind(diff_id)
    .bind(row.host_id)
    .bind(row.group_id)
    .bind(row.scan_run_id)
    .bind(product_id)
    .bind(engagement_id)
    .bind(test_id)
    .bind(finding_id)
    .bind(tags_json)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok(finding_id)
}

/// Push wszystkich diffow danego scan runa (zgodnie ze scope) + opcjonalnie inventory hostow.
pub async fn push_scan_run(
    pool: &PgPool,
    cfg: &LoadedDdConfig,
    client: &DdClient,
    events: &EventHub,
    scan_run_id: Uuid,
) -> Result<usize, String> {
    let diff_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM diff_events WHERE scan_run_id = $1 ORDER BY detected_at"#,
    )
    .bind(scan_run_id)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let mut pushed = 0_usize;
    let mut last_err: Option<String> = None;
    for diff_id in diff_ids {
        match push_diff_event(pool, cfg, client, diff_id).await {
            Ok(_) => pushed += 1,
            Err(e) => {
                if !e.contains("poza scope") {
                    last_err = Some(e);
                }
            }
        }
    }

    // Inventory: aktywne hosty grupy jako findingi info (unique_id_from_tool = "host:<id>").
    if cfg.finding_scope == DdFindingScope::Inventory {
        let run_row = sqlx::query(
            r#"SELECT asset_group_id, started_at, finished_at, COALESCE(external_refs,'{}'::jsonb)
               FROM scan_runs WHERE id = $1"#,
        )
        .bind(scan_run_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;
        if let Some(run) = run_row {
            let group_id: Uuid = run.get("asset_group_id");
            let started: DateTime<Utc> = run.get("started_at");
            let finished: Option<DateTime<Utc>> = run.get("finished_at");
            let refs: serde_json::Value = run.get("external_refs");
            let group_name: String =
                sqlx::query_scalar("SELECT name FROM asset_groups WHERE id = $1")
                    .bind(group_id)
                    .fetch_one(pool)
                    .await
                    .map_err(|e| e.to_string())?;
            let product_id = client.ensure_product(&group_name, "").await?;
            let run_label = scan_run_id.to_string()[..8].to_string();
            let engagement_id = client
                .ensure_engagement(product_id, &run_label, started, finished)
                .await?;
            let test_type_id = client.ensure_test_type().await?;
            let test_id = client
                .ensure_test(engagement_id, test_type_id, &run_label, started, finished)
                .await?;

            let hosts: Vec<(Uuid, String)> = sqlx::query_as(
                r#"SELECT id, ip_addr::text FROM hosts
                   WHERE asset_group_id = $1 AND status = 'active' ORDER BY ip_addr"#,
            )
            .bind(group_id)
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;
            for (host_id, ip) in hosts {
                let payload = DdFindingUpsert {
                    title: format!("ASI inventory: host {ip} aktywny")
                        .chars()
                        .take(250)
                        .collect(),
                    description: format!(
                        "Host aktywny w grupie '{group_name}' (ASI inventory sync)."
                    ),
                    severity: "Info".to_string(),
                    date: started.format("%Y-%m-%d").to_string(),
                    test: test_id,
                    found_by: vec![test_id],
                    numerical_severity: "S0".to_string(),
                    unique_id_from_tool: format!("host:{host_id}"),
                    component_name: Some("ASI Inventory".to_string()),
                    references: None,
                    tags: vec![
                        "asi".to_string(),
                        "inventory".to_string(),
                        group_name.clone(),
                    ],
                    active: true,
                    verified: false,
                };
                if let Ok(fid) = client.upsert_finding(&payload).await {
                    let _ = sqlx::query(
                        r#"UPDATE hosts SET external_refs = jsonb_set(COALESCE(external_refs,'{}'::jsonb), '{defectdojo,finding_id}', to_jsonb($2::int)) WHERE id = $1"#,
                    )
                    .bind(host_id)
                    .bind(fid)
                    .execute(pool)
                    .await;
                }
            }
            let _ = client.close_engagement(engagement_id).await;
            let _ = refs;
        }
    }

    let ev_id = Uuid::new_v4();
    events.emit_ui(
        "defectdojo.push",
        ev_id,
        serde_json::json!({
            "event_id": ev_id,
            "occurred_at": Utc::now(),
            "scan_run_id": scan_run_id,
            "pushed": pushed,
            "error": last_err,
        }),
    );
    match last_err {
        Some(e) => Err(e),
        None => Ok(pushed),
    }
}

/// Reczny push pojedynczego diffa (z UI) — bez scope check (jawny wybor admina).
pub async fn push_single_diff(
    pool: &PgPool,
    secret_box: &SecretBox,
    diff_id: Uuid,
) -> Result<i32, String> {
    let Some(cfg) = load_config(pool, secret_box).await? else {
        return Err("DefectDojo integracja wylaczona lub brak konfiguracji".to_string());
    };
    let client = dd_client(&cfg)?;
    // scope ignorujemy — admin kliknal "wyslij"; wymuszamy pelny zakres chwilowo:
    let cfg_full = LoadedDdConfig {
        finding_scope: DdFindingScope::AllDiffs,
        ..cfg
    };
    push_diff_event(pool, &cfg_full, &client, diff_id).await
}

// ---------------------------------------------------------------------------
// Pull (DD -> ASI): statusy i tagi findingow
// ---------------------------------------------------------------------------

/// Pobiera statusy findingow z DD i aktualizuje dd_links. Zwraca liczbe zaktualizowanych.
pub async fn pull_dd_statuses(
    pool: &PgPool,
    client: &DdClient,
    events: &EventHub,
) -> Result<usize, String> {
    let links: Vec<(Uuid, i32)> = sqlx::query_as(
        r#"SELECT diff_event_id, dd_finding_id FROM dd_links
           WHERE dd_finding_id IS NOT NULL
           ORDER BY created_at"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let mut ids: Vec<i32> = links.iter().map(|(_, id)| *id).collect();
    ids.sort_unstable();
    ids.dedup();
    let findings = client.findings_by_ids(&ids).await?;
    let mut updated = 0_usize;
    for f in findings {
        // wszystkie linki wskazujace na ten sam finding DD (teoretycznie >1 przy re-push)
        let matched: Vec<Uuid> = links
            .iter()
            .filter(|(_, id)| *id == f.id)
            .map(|(d, _)| *d)
            .collect();
        if matched.is_empty() {
            continue;
        }
        let status = f.status.clone().unwrap_or_default();
        let tags: Vec<String> = f
            .tags
            .iter()
            .map(|t| match t {
                serde_json::Value::String(s) => s.clone(),
                other => other
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
            .filter(|s| !s.is_empty())
            .collect();
        for diff_id in matched {
            let changed = sqlx::query(
                r#"UPDATE dd_links
                   SET dd_finding_status = $2,
                       dd_tags = $3::jsonb,
                       last_pulled_at = NOW()
                   WHERE diff_event_id = $1
                     AND (dd_finding_status IS DISTINCT FROM $2 OR dd_tags IS DISTINCT FROM $3::jsonb)
                   RETURNING diff_event_id"#,
            )
            .bind(diff_id)
            .bind(&status)
            .bind(serde_json::to_value(&tags).unwrap_or_default())
            .fetch_optional(pool)
            .await
            .map_err(|e| e.to_string())?;
            if changed.is_some() {
                updated += 1;
                let ev_id = Uuid::new_v4();
                events.emit_ui(
                    "defectdojo.finding_updated",
                    ev_id,
                    serde_json::json!({
                        "event_id": ev_id,
                        "occurred_at": Utc::now(),
                        "diff_event_id": diff_id,
                        "dd_finding_id": f.id,
                        "status": status,
                        "tags": tags,
                    }),
                );
            }
        }
    }

    sqlx::query(
        "UPDATE defectdojo_config SET last_pull_at = NOW(), updated_at = NOW() WHERE id = TRUE",
    )
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(updated)
}

/// Audit helper dla akcji integracji.
pub async fn audit_dd(
    pool: &PgPool,
    action: &str,
    detail: serde_json::Value,
) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "system",
            actor_id: None,
            action,
            resource_type: "defectdojo_integration",
            resource_id: None,
            before_state: None,
            after_state: Some(detail),
            source_ip: None,
            request_id: None,
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Nazwa test type wyswietlana w DD (dla dokumentacji/UI).
pub fn dd_test_type_label() -> &'static str {
    DD_TEST_TYPE_NAME
}

#[cfg(test)]
mod tests {
    use super::*;
    use asi_common::diff::DiffOp;

    #[test]
    fn component_prefers_service_then_technology() {
        let bullets = vec![
            BulletItem {
                op: DiffOp::Added,
                key: "service 443/tcp".into(),
                params: serde_json::json!({"service": "https"}),
            },
            BulletItem {
                op: DiffOp::Changed,
                key: "technology".into(),
                params: serde_json::json!({"technology": "nginx"}),
            },
        ];
        assert_eq!(component_from_bullets(&bullets).as_deref(), Some("https"));
        let bullets2 = vec![BulletItem {
            op: DiffOp::Changed,
            key: "technology".into(),
            params: serde_json::json!({"technology": "nginx"}),
        }];
        assert_eq!(component_from_bullets(&bullets2).as_deref(), Some("nginx"));
    }

    #[test]
    fn retry_delay_progression() {
        assert_eq!(DD_RETRY_DELAYS_SECONDS[0], 10);
        assert_eq!(DD_RETRY_DELAYS_SECONDS[4], 1800);
    }
}
