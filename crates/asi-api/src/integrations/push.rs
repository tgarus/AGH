//! Logika wysyłki ASI -> DefectDojo (outbox enqueue + push) oraz pull DD -> ASI.

use asi_common::defectdojo::{
    dd_finding_description, dd_finding_title, dd_numerical_severity, dd_severity,
    DdFindingPayloadOverride, DdFindingPreviewDto, DdFindingScope, DdFindingUpsert,
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
    let loaded = load_config_internal(pool, secret_box, false).await?;
    Ok(loaded)
}

pub async fn load_config_allow_disabled(
    pool: &PgPool,
    secret_box: &SecretBox,
) -> Result<Option<LoadedDdConfig>, String> {
    load_config_internal(pool, secret_box, true).await
}

async fn load_config_internal(
    pool: &PgPool,
    secret_box: &SecretBox,
    allow_disabled: bool,
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
    if !allow_disabled && !enabled {
        return Ok(None);
    }
    let base_url: String = row.get("base_url");
    if base_url.trim().is_empty() {
        return Ok(None);
    }
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

#[derive(sqlx::FromRow)]
struct DiffRow {
    host_id: Uuid,
    ip_addr: String,
    scan_run_id: Option<Uuid>,
    event_kind: String,
    severity: String,
    bullet_items: serde_json::Value,
    external_refs: serde_json::Value,
    detected_at: DateTime<Utc>,
    group_id: Uuid,
    group_name: String,
    group_description: Option<String>,
    run_started_at: Option<DateTime<Utc>>,
    run_finished_at: Option<DateTime<Utc>>,
}

async fn load_diff_row(pool: &PgPool, diff_id: Uuid) -> Result<DiffRow, String> {
    sqlx::query_as::<_, DiffRow>(
        r#"
        SELECT de.host_id,
               h.ip_addr::text AS ip_addr,
               de.scan_run_id,
               de.event_kind,
               de.severity,
               de.bullet_items,
               COALESCE(de.external_refs, '{}'::jsonb) AS external_refs,
               de.detected_at,
               COALESCE(ag.id, '00000000-0000-0000-0000-000000000000'::uuid) AS group_id,
               COALESCE(ag.name, 'default') AS group_name,
               ag.description AS group_description,
               sr.started_at AS run_started_at,
               sr.finished_at AS run_finished_at
        FROM diff_events de
        JOIN hosts h ON h.id = de.host_id
        LEFT JOIN asset_groups ag ON ag.id = h.asset_group_id
        LEFT JOIN scan_runs sr ON sr.id = de.scan_run_id
        WHERE de.id = $1
        "#,
    )
    .bind(diff_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?
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

fn extract_saved_override(external_refs: &serde_json::Value) -> Option<DdFindingPayloadOverride> {
    external_refs
        .get("dd_override")
        .and_then(|v| serde_json::from_value::<DdFindingPayloadOverride>(v.clone()).ok())
}

fn dd_references_for(asi_public_url: &str, kind: &str, id: Uuid) -> Option<String> {
    if asi_public_url.trim().is_empty() {
        Some(format!("asi://{kind}/{id}"))
    } else {
        Some(format!(
            "{}/{kind}/{id}",
            asi_public_url.trim_end_matches('/')
        ))
    }
}

fn build_default_diff_payload(
    asi_public_url: &str,
    row: &DiffRow,
    diff_id: Uuid,
    test_id: i32,
    test_type_id: i32,
) -> DdFindingUpsert {
    let bullets = parse_bullets(&row.bullet_items);
    let kind = kind_from_db(&row.event_kind);
    let severity = severity_from_db(&row.severity);
    DdFindingUpsert {
        title: dd_finding_title(kind, severity, &bullets, &row.ip_addr),
        description: dd_finding_description(
            &bullets,
            &format!("host {} (diff {})", row.ip_addr, diff_id),
        ),
        severity: dd_severity(severity).to_string(),
        date: row.detected_at.format("%Y-%m-%d").to_string(),
        test: test_id,
        found_by: if test_type_id > 0 {
            vec![test_type_id]
        } else {
            vec![]
        },
        numerical_severity: dd_numerical_severity(severity).to_string(),
        unique_id_from_tool: diff_id.to_string(),
        component_name: component_from_bullets(&bullets),
        references: dd_references_for(asi_public_url, "diffs", diff_id),
        tags: vec![
            "asi".to_string(),
            row.group_name.clone(),
            kind.as_db_str().to_string(),
        ],
        active: true,
        verified: false,
        ..Default::default()
    }
}

pub async fn build_diff_dd_preview(
    pool: &PgPool,
    asi_public_url: &str,
    diff_id: Uuid,
) -> Result<DdFindingPreviewDto, String> {
    let row = load_diff_row(pool, diff_id).await?;
    let default_payload = build_default_diff_payload(asi_public_url, &row, diff_id, 0, 0);
    let saved_override = extract_saved_override(&row.external_refs);
    let mut effective_payload = default_payload.clone();
    if let Some(ref ov) = saved_override {
        effective_payload.apply_override(ov);
    }
    Ok(DdFindingPreviewDto {
        target_kind: "diff_event".to_string(),
        target_id: diff_id,
        ip_addr: row.ip_addr,
        asset_group_name: row.group_name,
        default_payload,
        saved_override,
        effective_payload,
    })
}

pub async fn save_diff_dd_override(
    pool: &PgPool,
    diff_id: Uuid,
    ov: &DdFindingPayloadOverride,
) -> Result<(), String> {
    let ov_json = serde_json::to_value(ov).map_err(|e| e.to_string())?;
    let res = sqlx::query(
        r#"
        UPDATE diff_events
        SET external_refs = jsonb_set(COALESCE(external_refs, '{}'::jsonb), '{dd_override}', $2::jsonb, TRUE)
        WHERE id = $1
        "#,
    )
    .bind(diff_id)
    .bind(ov_json)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    if res.rows_affected() == 0 {
        return Err(format!("diff_event {diff_id} not found"));
    }
    Ok(())
}

struct DdGroupHierarchyParams<'a> {
    group_id: Uuid,
    group_name: &'a str,
    group_description: Option<&'a str>,
    scan_run_id: Option<Uuid>,
    started_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
}

/// Zapewnia Product+Engagement+Test dla grupy/runa i zwraca (product_id, engagement_id, test_type_id, test_id).
async fn ensure_dd_group_hierarchy(
    client: &DdClient,
    pool: &PgPool,
    params: DdGroupHierarchyParams<'_>,
) -> Result<(i32, i32, i32, i32), String> {
    let product_id = client
        .ensure_product(params.group_name, params.group_description.unwrap_or(""))
        .await?;
    sqlx::query(
        r#"UPDATE asset_groups
           SET external_refs = jsonb_set(COALESCE(external_refs,'{}'::jsonb), '{defectdojo,product_id}', to_jsonb($2::int))
           WHERE id = $1"#,
    )
    .bind(params.group_id)
    .bind(product_id)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    let run_label = params
        .scan_run_id
        .map(|id| id.to_string()[..8].to_string())
        .unwrap_or_else(|| "manual".to_string());
    let engagement_id = client
        .ensure_engagement(
            product_id,
            &run_label,
            params.started_at,
            params.finished_at,
        )
        .await?;
    let test_type_id = client.ensure_test_type().await?;
    let test_id = client
        .ensure_test(
            engagement_id,
            test_type_id,
            &run_label,
            params.started_at,
            params.finished_at,
        )
        .await?;
    if let Some(run_id) = params.scan_run_id {
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
    Ok((product_id, engagement_id, test_type_id, test_id))
}

async fn ensure_dd_hierarchy(
    client: &DdClient,
    pool: &PgPool,
    row: &DiffRow,
) -> Result<(i32, i32, i32, i32), String> {
    ensure_dd_group_hierarchy(
        client,
        pool,
        DdGroupHierarchyParams {
            group_id: row.group_id,
            group_name: &row.group_name,
            group_description: row.group_description.as_deref(),
            scan_run_id: row.scan_run_id,
            started_at: row.run_started_at.unwrap_or_else(Utc::now),
            finished_at: row.run_finished_at,
        },
    )
    .await
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
    let (product_id, engagement_id, test_type_id, test_id) =
        ensure_dd_hierarchy(client, pool, &row).await?;

    let mut payload =
        build_default_diff_payload(&cfg.asi_public_url, &row, diff_id, test_id, test_type_id);
    if let Some(ov) = extract_saved_override(&row.external_refs) {
        payload.apply_override(&ov);
    }
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

    let _ = crate::notifications::worker::enqueue_webhook_event(
        pool,
        Some(row.group_id),
        "defectdojo.finding_pushed",
        serde_json::json!({
            "target_kind": "diff_event",
            "diff_event_id": diff_id,
            "host_id": row.host_id,
            "ip_addr": row.ip_addr,
            "dd_finding_id": finding_id,
            "title": payload.title,
            "severity": payload.severity,
        }),
    )
    .await;

    Ok(finding_id)
}

// ---------------------------------------------------------------------------
// Host Preview, Override & Push
// ---------------------------------------------------------------------------

struct HostPushRow {
    host_id: Uuid,
    ip_addr: String,
    status: String,
    is_unstable: bool,
    is_probable_tarpit: bool,
    auto_tags: Vec<String>,
    manual_tags: Vec<String>,
    notes: Option<String>,
    owner_hint: Option<String>,
    external_refs: serde_json::Value,
    group_id: Uuid,
    group_name: String,
    group_description: Option<String>,
}

async fn load_host_push_row(pool: &PgPool, host_id: Uuid) -> Result<HostPushRow, String> {
    let row = sqlx::query(
        r#"
        SELECT h.id, h.ip_addr::text, h.status, h.is_unstable, h.is_probable_tarpit,
               h.auto_tags, h.manual_tags, h.notes, h.owner_hint,
               COALESCE(h.external_refs, '{}'::jsonb) AS external_refs,
               ag.id AS group_id, ag.name AS group_name, ag.description AS group_description
        FROM hosts h
        JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE h.id = $1
        "#,
    )
    .bind(host_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| format!("host {host_id} not found"))?;

    Ok(HostPushRow {
        host_id: row.get("id"),
        ip_addr: row.get("ip_addr"),
        status: row.get("status"),
        is_unstable: row.get("is_unstable"),
        is_probable_tarpit: row.get("is_probable_tarpit"),
        auto_tags: row.get("auto_tags"),
        manual_tags: row.get("manual_tags"),
        notes: row.get("notes"),
        owner_hint: row.get("owner_hint"),
        external_refs: row.get("external_refs"),
        group_id: row.get("group_id"),
        group_name: row.get("group_name"),
        group_description: row.get("group_description"),
    })
}

#[derive(sqlx::FromRow)]
struct HostPortExportRow {
    id: Uuid,
    port: i32,
    protocol: String,
    service_name: Option<String>,
    product: Option<String>,
    version: Option<String>,
}

#[derive(sqlx::FromRow)]
struct HostWebObsExportRow {
    vhost: String,
    scheme: String,
    http_status: Option<i32>,
    title: Option<String>,
    matched_technologies: serde_json::Value,
    detected_paths: Vec<String>,
}

async fn build_default_host_payload(
    pool: &PgPool,
    asi_public_url: &str,
    host: &HostPushRow,
    test_id: i32,
    test_type_id: i32,
) -> Result<DdFindingUpsert, String> {
    let port_rows: Vec<HostPortExportRow> = sqlx::query_as(
        r#"
            SELECT id, port, protocol, service_name, product, version
            FROM host_ports
            WHERE host_id = $1 AND state <> 'closed'
            ORDER BY port ASC
            "#,
    )
    .bind(host.host_id)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let port_ids: Vec<Uuid> = port_rows.iter().map(|p| p.id).collect();
    let mut web_lines: Vec<String> = Vec::new();
    let mut tls_lines: Vec<String> = Vec::new();
    let mut has_admin_panel = false;
    let mut has_self_signed = false;
    let mut first_component: Option<String> = None;

    if !port_ids.is_empty() {
        let webs: Vec<HostWebObsExportRow> = sqlx::query_as(
            r#"
                SELECT vhost, scheme, http_status, title, matched_technologies, detected_paths
                FROM web_observations
                WHERE host_port_id = ANY($1)
                ORDER BY vhost ASC
                "#,
        )
        .bind(&port_ids)
        .fetch_all(pool)
        .await
        .map_err(|e| e.to_string())?;

        for web in webs {
            let techs: Vec<String> =
                serde_json::from_value(web.matched_technologies).unwrap_or_default();
            if first_component.is_none() {
                first_component = techs.first().cloned();
            }
            if web
                .detected_paths
                .iter()
                .any(|p| p.contains("admin") || p.contains("login"))
                || techs
                    .iter()
                    .any(|t| t.to_ascii_lowercase().contains("admin"))
            {
                has_admin_panel = true;
            }
            web_lines.push(format!(
                "- {}://{} [{}] title={} tech=[{}] paths=[{}]",
                web.scheme,
                web.vhost,
                web.http_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into()),
                web.title.unwrap_or_else(|| "—".into()),
                techs.join(", "),
                web.detected_paths.join(", ")
            ));
        }

        let certs: Vec<(Option<String>, bool)> = sqlx::query_as(
            "SELECT subject_cn, is_self_signed FROM tls_certificates WHERE host_port_id = ANY($1)",
        )
        .bind(&port_ids)
        .fetch_all(pool)
        .await
        .map_err(|e| e.to_string())?;
        for (cn, self_signed) in certs {
            if self_signed {
                has_self_signed = true;
            }
            tls_lines.push(format!(
                "- TLS CN={} self_signed={}",
                cn.unwrap_or_else(|| "—".into()),
                self_signed
            ));
        }
    }

    let has_sensitive_port = port_rows.iter().any(|row| {
        matches!(
            row.port,
            21 | 23 | 3306 | 5432 | 6379 | 15432 | 15672 | 27017
        ) || row
            .service_name
            .as_deref()
            .map(|s| matches!(s, "redis" | "ftp" | "telnet" | "postgresql" | "mysql"))
            .unwrap_or(false)
    });

    let (severity, num_sev) = if has_admin_panel || has_sensitive_port {
        ("High", "S3")
    } else if host.is_probable_tarpit || has_self_signed {
        ("Medium", "S2")
    } else {
        ("Info", "S0")
    };

    let mut desc = format!(
        "Host inwentarzowy ASI w grupie '{}'.\n\nIP: {}\nStatus: {}\nNiestabilny (flapping): {}\nProbable Tarpit: {}\n",
        host.group_name, host.ip_addr, host.status, host.is_unstable, host.is_probable_tarpit
    );
    if let Some(ref owner) = host.owner_hint {
        if !owner.trim().is_empty() {
            desc.push_str(&format!("Właściciel / Zespół: {owner}\n"));
        }
    }
    if let Some(ref notes) = host.notes {
        if !notes.trim().is_empty() {
            desc.push_str(&format!("Notatki analityka: {notes}\n"));
        }
    }
    if !port_rows.is_empty() {
        desc.push_str("\nOtwarte porty i usługi:\n");
        for row in &port_rows {
            if first_component.is_none() {
                first_component = row.service_name.clone();
            }
            desc.push_str(&format!(
                "- {}/{}: {} {} {}\n",
                row.port,
                row.protocol,
                row.service_name.as_deref().unwrap_or("unknown"),
                row.product.as_deref().unwrap_or(""),
                row.version.as_deref().unwrap_or("")
            ));
        }
    }
    if !web_lines.is_empty() {
        desc.push_str("\nObserwacje Web/HTTP:\n");
        for line in &web_lines {
            desc.push_str(line);
            desc.push('\n');
        }
    }
    if !tls_lines.is_empty() {
        desc.push_str("\nCertyfikaty TLS:\n");
        for line in &tls_lines {
            desc.push_str(line);
            desc.push('\n');
        }
    }

    let mut tags = vec![
        "asi".to_string(),
        "inventory".to_string(),
        host.group_name.clone(),
    ];
    for t in host.manual_tags.iter().chain(host.auto_tags.iter()) {
        let trimmed = t.trim();
        if !trimmed.is_empty() && !tags.iter().any(|x| x == trimmed) {
            tags.push(trimmed.to_string());
        }
    }

    let title = format!(
        "ASI host [{}] {} ({} portow)",
        severity,
        host.ip_addr,
        port_rows.len()
    )
    .chars()
    .take(250)
    .collect();

    Ok(DdFindingUpsert {
        title,
        description: desc,
        severity: severity.to_string(),
        date: Utc::now().format("%Y-%m-%d").to_string(),
        test: test_id,
        found_by: if test_type_id > 0 {
            vec![test_type_id]
        } else {
            vec![]
        },
        numerical_severity: num_sev.to_string(),
        unique_id_from_tool: format!("host:{}", host.host_id),
        component_name: first_component.or_else(|| Some("ASI Inventory".to_string())),
        references: dd_references_for(asi_public_url, "hosts", host.host_id),
        tags,
        active: true,
        verified: false,
        ..Default::default()
    })
}

pub async fn build_host_dd_preview(
    pool: &PgPool,
    asi_public_url: &str,
    host_id: Uuid,
) -> Result<DdFindingPreviewDto, String> {
    let host = load_host_push_row(pool, host_id).await?;
    let default_payload = build_default_host_payload(pool, asi_public_url, &host, 0, 0).await?;
    let saved_override = extract_saved_override(&host.external_refs);
    let mut effective_payload = default_payload.clone();
    if let Some(ref ov) = saved_override {
        effective_payload.apply_override(ov);
    }
    Ok(DdFindingPreviewDto {
        target_kind: "host".to_string(),
        target_id: host_id,
        ip_addr: host.ip_addr,
        asset_group_name: host.group_name,
        default_payload,
        saved_override,
        effective_payload,
    })
}

pub async fn save_host_dd_override(
    pool: &PgPool,
    host_id: Uuid,
    ov: &DdFindingPayloadOverride,
) -> Result<(), String> {
    let ov_json = serde_json::to_value(ov).map_err(|e| e.to_string())?;
    let res = sqlx::query(
        r#"
        UPDATE hosts
        SET external_refs = jsonb_set(COALESCE(external_refs, '{}'::jsonb), '{dd_override}', $2::jsonb, TRUE)
        WHERE id = $1
        "#,
    )
    .bind(host_id)
    .bind(ov_json)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    if res.rows_affected() == 0 {
        return Err(format!("host {host_id} not found"));
    }
    Ok(())
}

pub async fn push_single_host(
    pool: &PgPool,
    secret_box: &SecretBox,
    host_id: Uuid,
    override_opt: Option<DdFindingPayloadOverride>,
) -> Result<i32, String> {
    if let Some(ref ov) = override_opt {
        save_host_dd_override(pool, host_id, ov).await?;
    }
    let Some(cfg) = load_config_allow_disabled(pool, secret_box).await? else {
        return Err("Brak zapisanej konfiguracji DefectDojo (Base URL lub API key).".to_string());
    };
    let client = dd_client(&cfg)?;
    let host = load_host_push_row(pool, host_id).await?;

    let latest_run: Option<(Uuid, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, started_at, finished_at FROM scan_runs WHERE asset_group_id = $1 ORDER BY started_at DESC LIMIT 1",
    )
    .bind(host.group_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    let (run_id, started, finished) = match latest_run {
        Some((rid, s, f)) => (Some(rid), s, f),
        None => (None, Utc::now(), None),
    };
    let (product_id, engagement_id, test_type_id, test_id) = ensure_dd_group_hierarchy(
        &client,
        pool,
        DdGroupHierarchyParams {
            group_id: host.group_id,
            group_name: &host.group_name,
            group_description: host.group_description.as_deref(),
            scan_run_id: run_id,
            started_at: started,
            finished_at: finished,
        },
    )
    .await?;

    let mut payload =
        build_default_host_payload(pool, &cfg.asi_public_url, &host, test_id, test_type_id).await?;
    if let Some(ov) = override_opt.or_else(|| extract_saved_override(&host.external_refs)) {
        payload.apply_override(&ov);
    }

    let finding_id = match client.upsert_finding(&payload).await {
        Ok(fid) => {
            let _ = sqlx::query(
                "UPDATE defectdojo_config SET last_error = NULL, last_push_at = NOW(), updated_at = NOW() WHERE id = TRUE",
            )
            .execute(pool)
            .await;
            fid
        }
        Err(e) => {
            let _ = sqlx::query(
                "UPDATE defectdojo_config SET last_error = $1, updated_at = NOW() WHERE id = TRUE",
            )
            .bind(&e)
            .execute(pool)
            .await;
            return Err(e);
        }
    };

    let _ = sqlx::query(
        r#"UPDATE hosts SET external_refs = jsonb_set(COALESCE(external_refs,'{}'::jsonb), '{defectdojo,finding_id}', to_jsonb($2::int)) WHERE id = $1"#,
    )
    .bind(host_id)
    .bind(finding_id)
    .execute(pool)
    .await;

    let tags_json = serde_json::to_value(&payload.tags).unwrap_or_default();
    let _ = sqlx::query(
        r#"
        INSERT INTO dd_links (diff_event_id, host_id, asset_group_id, scan_run_id,
                              dd_product_id, dd_engagement_id, dd_test_id, dd_finding_id,
                              dd_finding_status, dd_tags, last_pushed_at)
        VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, 'active', $8, NOW())
        ON CONFLICT (host_id) WHERE diff_event_id IS NULL AND host_id IS NOT NULL DO UPDATE SET
            dd_product_id = EXCLUDED.dd_product_id,
            dd_engagement_id = EXCLUDED.dd_engagement_id,
            dd_test_id = EXCLUDED.dd_test_id,
            dd_finding_id = EXCLUDED.dd_finding_id,
            dd_tags = EXCLUDED.dd_tags,
            last_pushed_at = NOW()
        "#,
    )
    .bind(host_id)
    .bind(host.group_id)
    .bind(run_id)
    .bind(product_id)
    .bind(engagement_id)
    .bind(test_id)
    .bind(finding_id)
    .bind(tags_json)
    .execute(pool)
    .await;

    let _ = crate::notifications::worker::enqueue_webhook_event(
        pool,
        Some(host.group_id),
        "defectdojo.finding_pushed",
        serde_json::json!({
            "target_kind": "host",
            "host_id": host_id,
            "ip_addr": host.ip_addr,
            "dd_finding_id": finding_id,
            "title": payload.title,
            "severity": payload.severity,
        }),
    )
    .await;

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

            let hosts: Vec<Uuid> = sqlx::query_scalar(
                r#"SELECT id FROM hosts
                   WHERE asset_group_id = $1 AND status = 'active' ORDER BY ip_addr"#,
            )
            .bind(group_id)
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;
            for host_id in hosts {
                if let Ok(host) = load_host_push_row(pool, host_id).await {
                    if let Ok(mut payload) = build_default_host_payload(
                        pool,
                        &cfg.asi_public_url,
                        &host,
                        test_id,
                        test_type_id,
                    )
                    .await
                    {
                        if let Some(ov) = extract_saved_override(&host.external_refs) {
                            payload.apply_override(&ov);
                        }
                        if let Ok(fid) = client.upsert_finding(&payload).await {
                            let _ = sqlx::query(
                                r#"UPDATE hosts SET external_refs = jsonb_set(COALESCE(external_refs,'{}'::jsonb), '{defectdojo,finding_id}', to_jsonb($2::int)) WHERE id = $1"#,
                            )
                            .bind(host_id)
                            .bind(fid)
                            .execute(pool)
                            .await;
                            let tags_json = serde_json::to_value(&payload.tags).unwrap_or_default();
                            let _ = sqlx::query(
                                r#"
                                INSERT INTO dd_links (diff_event_id, host_id, asset_group_id, scan_run_id,
                                                      dd_product_id, dd_engagement_id, dd_test_id, dd_finding_id,
                                                      dd_finding_status, dd_tags, last_pushed_at)
                                VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, 'active', $8, NOW())
                                ON CONFLICT (host_id) WHERE diff_event_id IS NULL AND host_id IS NOT NULL DO UPDATE SET
                                    dd_product_id = EXCLUDED.dd_product_id,
                                    dd_engagement_id = EXCLUDED.dd_engagement_id,
                                    dd_test_id = EXCLUDED.dd_test_id,
                                    dd_finding_id = EXCLUDED.dd_finding_id,
                                    dd_tags = EXCLUDED.dd_tags,
                                    last_pushed_at = NOW()
                                "#,
                            )
                            .bind(host_id)
                            .bind(group_id)
                            .bind(scan_run_id)
                            .bind(product_id)
                            .bind(engagement_id)
                            .bind(test_id)
                            .bind(fid)
                            .bind(tags_json)
                            .execute(pool)
                            .await;
                        }
                    }
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

pub async fn push_group_inventory_hosts(
    pool: &PgPool,
    cfg: &LoadedDdConfig,
    client: &DdClient,
    group_id: Uuid,
) -> Result<usize, String> {
    let group_row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT name, description FROM asset_groups WHERE id = $1")
            .bind(group_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| e.to_string())?;
    let Some((group_name, group_description)) = group_row else {
        return Ok(0);
    };

    let (product_id, engagement_id, test_type_id, test_id) = ensure_dd_group_hierarchy(
        client,
        pool,
        DdGroupHierarchyParams {
            group_id,
            group_name: &group_name,
            group_description: group_description.as_deref(),
            scan_run_id: None,
            started_at: Utc::now(),
            finished_at: None,
        },
    )
    .await?;

    let host_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM hosts WHERE asset_group_id = $1 AND status = 'active' ORDER BY ip_addr",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let mut pushed = 0_usize;
    for host_id in host_ids {
        if let Ok(host) = load_host_push_row(pool, host_id).await {
            if let Ok(mut payload) =
                build_default_host_payload(pool, &cfg.asi_public_url, &host, test_id, test_type_id)
                    .await
            {
                if let Some(ov) = extract_saved_override(&host.external_refs) {
                    payload.apply_override(&ov);
                }
                if let Ok(fid) = client.upsert_finding(&payload).await {
                    pushed += 1;
                    let _ = sqlx::query(
                        r#"UPDATE hosts SET external_refs = jsonb_set(COALESCE(external_refs,'{}'::jsonb), '{defectdojo,finding_id}', to_jsonb($2::int)) WHERE id = $1"#,
                    )
                    .bind(host_id)
                    .bind(fid)
                    .execute(pool)
                    .await;
                    let tags_json = serde_json::to_value(&payload.tags).unwrap_or_default();
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO dd_links (diff_event_id, host_id, asset_group_id, scan_run_id,
                                              dd_product_id, dd_engagement_id, dd_test_id, dd_finding_id,
                                              dd_finding_status, dd_tags, last_pushed_at)
                        VALUES (NULL, $1, $2, NULL, $3, $4, $5, $6, 'active', $7, NOW())
                        ON CONFLICT (host_id) WHERE diff_event_id IS NULL AND host_id IS NOT NULL DO UPDATE SET
                            dd_product_id = EXCLUDED.dd_product_id,
                            dd_engagement_id = EXCLUDED.dd_engagement_id,
                            dd_test_id = EXCLUDED.dd_test_id,
                            dd_finding_id = EXCLUDED.dd_finding_id,
                            dd_tags = EXCLUDED.dd_tags,
                            last_pushed_at = NOW()
                        "#,
                    )
                    .bind(host_id)
                    .bind(group_id)
                    .bind(product_id)
                    .bind(engagement_id)
                    .bind(test_id)
                    .bind(fid)
                    .bind(tags_json)
                    .execute(pool)
                    .await;
                }
            }
        }
    }
    Ok(pushed)
}

/// Reczny push pojedynczego diffa (z UI) — bez scope check (jawny wybor admina).
pub async fn push_single_diff(
    pool: &PgPool,
    secret_box: &SecretBox,
    diff_id: Uuid,
    override_opt: Option<DdFindingPayloadOverride>,
) -> Result<i32, String> {
    if let Some(ref ov) = override_opt {
        save_diff_dd_override(pool, diff_id, ov).await?;
    }
    let Some(cfg) = load_config_allow_disabled(pool, secret_box).await? else {
        return Err("Brak zapisanej konfiguracji DefectDojo (Base URL lub API key).".to_string());
    };
    let client = dd_client(&cfg)?;
    // scope ignorujemy — admin kliknal "wyslij"; wymuszamy pelny zakres chwilowo:
    let cfg_full = LoadedDdConfig {
        finding_scope: DdFindingScope::AllDiffs,
        ..cfg
    };
    match push_diff_event(pool, &cfg_full, &client, diff_id).await {
        Ok(fid) => {
            let _ = sqlx::query(
                "UPDATE defectdojo_config SET last_error = NULL, last_push_at = NOW(), updated_at = NOW() WHERE id = TRUE",
            )
            .execute(pool)
            .await;
            Ok(fid)
        }
        Err(e) => {
            let _ = sqlx::query(
                "UPDATE defectdojo_config SET last_error = $1, updated_at = NOW() WHERE id = TRUE",
            )
            .bind(&e)
            .execute(pool)
            .await;
            Err(e)
        }
    }
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
    let links: Vec<(Uuid, Option<Uuid>, Option<Uuid>, i32)> = sqlx::query_as(
        r#"SELECT id, diff_event_id, host_id, dd_finding_id FROM dd_links
           WHERE dd_finding_id IS NOT NULL
           ORDER BY created_at"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let mut ids: Vec<i32> = links.iter().map(|(_, _, _, id)| *id).collect();
    ids.sort_unstable();
    ids.dedup();
    let findings = client.findings_by_ids(&ids).await?;
    let mut updated = 0_usize;
    for f in findings {
        // wszystkie linki wskazujace na ten sam finding DD (diff lub host)
        let matched: Vec<(Uuid, Option<Uuid>, Option<Uuid>)> = links
            .iter()
            .filter(|(_, _, _, id)| *id == f.id)
            .map(|(lid, d, h, _)| (*lid, *d, *h))
            .collect();
        if matched.is_empty() {
            continue;
        }
        let status = f.effective_status();
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
        for (link_id, diff_id, host_id) in matched {
            let changed = sqlx::query(
                r#"UPDATE dd_links
                   SET dd_finding_status = $2,
                       dd_tags = $3::jsonb,
                       last_pulled_at = NOW()
                   WHERE id = $1
                     AND (dd_finding_status IS DISTINCT FROM $2 OR dd_tags IS DISTINCT FROM $3::jsonb)
                   RETURNING id"#,
            )
            .bind(link_id)
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
                        "host_id": host_id,
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

    #[test]
    fn build_default_diff_payload_uses_test_type_id_for_found_by() {
        let diff_id = Uuid::new_v4();
        let row = DiffRow {
            host_id: Uuid::new_v4(),
            ip_addr: "10.20.30.40".to_string(),
            scan_run_id: Some(Uuid::new_v4()),
            event_kind: "confirmed_change".to_string(),
            severity: "high".to_string(),
            bullet_items: serde_json::json!([
                {
                    "op": "+",
                    "key": "service 443/tcp",
                    "params": { "port": 443, "proto": "tcp", "service": "https" }
                }
            ]),
            external_refs: serde_json::json!({}),
            detected_at: Utc::now(),
            group_id: Uuid::new_v4(),
            group_name: "AGH Core".to_string(),
            group_description: None,
            run_started_at: None,
            run_finished_at: None,
        };
        let payload = build_default_diff_payload("https://asi.agh.edu.pl", &row, diff_id, 42, 7);
        assert_eq!(payload.test, 42);
        assert_eq!(payload.found_by, vec![7]);
        assert!(payload
            .references
            .as_deref()
            .unwrap_or("")
            .contains("https://asi.agh.edu.pl/diffs/"));
    }
}
