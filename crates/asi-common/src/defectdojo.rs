//! Kontrakt integracji dwukierunkowej z DefectDojo (Faza 6, ADR-0008).
//!
//! Mapowanie: asset_group -> Product, scan_run -> Engagement + Test,
//! diff_event -> Finding (upsert po `unique_id_from_tool`). Komunikacja
//! bezposrednio przez REST API v2 DefectDojo (bez reimport-scan).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::diff::{BulletItem, DiffEventKind, DiffSeverity};

/// Zakres danych publikowanych do DefectDojo jako findingi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DdFindingScope {
    /// Tylko `confirmed_change` ("Hej, coś się zmieniło").
    Changes,
    /// `confirmed_change` + `active_variance` ("Hej, coś się zmienia").
    AllDiffs,
    /// Jak `all_diffs` + pelny inventory aktywnych hostow jako findingi info.
    Inventory,
}

impl DdFindingScope {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Changes => "changes",
            Self::AllDiffs => "all_diffs",
            Self::Inventory => "inventory",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "changes" => Some(Self::Changes),
            "all_diffs" => Some(Self::AllDiffs),
            "inventory" => Some(Self::Inventory),
            _ => None,
        }
    }

    /// Czy dany rodzaj diffu kwalifikuje sie do publikacji w tym scope.
    #[must_use]
    pub fn includes(self, kind: DiffEventKind) -> bool {
        match self {
            Self::Changes => kind == DiffEventKind::ConfirmedChange,
            Self::AllDiffs | Self::Inventory => true,
        }
    }
}

/// Konfiguracja integracji (sekret API key nigdy nie opuszcza backendu).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DefectDojoConfigDto {
    pub base_url: String,
    pub finding_scope: DdFindingScope,
    pub auto_push: bool,
    pub pull_interval_minutes: i32,
    pub enabled: bool,
    pub has_api_key: bool,
    pub pending_outbox: i64,
    pub last_push_at: Option<DateTime<Utc>>,
    pub last_pull_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Aktualizacja konfiguracji; `api_key = None` oznacza "zostaw stary klucz".
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateDefectDojoConfigRequest {
    pub base_url: Option<String>,
    /// Publiczny adres ASI (uzywany w polu `references` findingow DD).
    pub asi_public_url: Option<String>,
    pub api_key: Option<String>,
    pub finding_scope: Option<DdFindingScope>,
    pub auto_push: Option<bool>,
    pub pull_interval_minutes: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdTestConnectionResponse {
    pub ok: bool,
    pub base_url: String,
    pub product_count: Option<i64>,
    pub error: Option<String>,
}

/// Reczny sync: jedna grupa albo wszystkie (None = wszystkie aktywne grupy).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdSyncRequest {
    pub asset_group_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdSyncResponse {
    pub enqueued: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdPushDiffResponse {
    pub diff_event_id: Uuid,
    pub enqueued: bool,
    pub note: String,
}

/// Powiazanie diff_event z obiektem Finding w DefectDojo (do wyswietlenia w UI).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdLinkDto {
    pub diff_event_id: Uuid,
    pub dd_product_id: Option<i32>,
    pub dd_engagement_id: Option<i32>,
    pub dd_test_id: Option<i32>,
    pub dd_finding_id: Option<i32>,
    pub dd_finding_status: Option<String>,
    pub dd_tags: Vec<String>,
    pub last_pushed_at: Option<DateTime<Utc>>,
    pub last_pulled_at: Option<DateTime<Utc>>,
}

/// Wiersz kolejki outbox (do podgladu w UI).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdOutboxItemDto {
    pub id: Uuid,
    pub kind: String,
    pub asset_group_id: Uuid,
    pub scan_run_id: Option<Uuid>,
    pub diff_event_id: Option<Uuid>,
    pub status: String,
    pub attempt_count: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Wire types DefectDojo REST API v2 (subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdPaginated<T> {
    pub count: i64,
    pub results: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdProduct {
    pub id: i32,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdProductCreate {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdEngagement {
    pub id: i32,
    pub name: String,
    pub product: i32,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdEngagementCreate {
    pub name: String,
    pub product: i32,
    pub target_start: String,
    pub target_end: String,
    pub status: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdTestType {
    pub id: i32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdTest {
    pub id: i32,
    pub title: String,
    pub test_type: i32,
    pub engagement: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdTestCreate {
    pub title: String,
    pub test_type: i32,
    pub engagement: i32,
    pub target_start: String,
    pub target_end: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdFinding {
    pub id: i32,
    pub title: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub unique_id_from_tool: Option<String>,
    #[serde(default)]
    pub tags: Vec<serde_json::Value>,
    #[serde(default)]
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdFindingUpsert {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub date: String,
    pub test: i32,
    #[serde(default)]
    pub found_by: Vec<i32>,
    #[serde(default)]
    pub numerical_severity: String,
    pub unique_id_from_tool: String,
    #[serde(default)]
    pub component_name: Option<String>,
    #[serde(default)]
    pub references: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub active: bool,
    pub verified: bool,
}

/// Mapowanie severity ASI -> DefectDojo (API v2 przyjmuje slugi pisane malymi literami).
#[must_use]
pub fn dd_severity(severity: DiffSeverity) -> &'static str {
    match severity {
        DiffSeverity::Info => "Info",
        DiffSeverity::Low => "Low",
        DiffSeverity::Medium => "Medium",
        DiffSeverity::High => "High",
    }
}

/// Mapowanie severity ASI -> numerical_severity wymagane przez nowsze API v2 DefectDojo (S0..S5).
#[must_use]
pub fn dd_numerical_severity(severity: DiffSeverity) -> &'static str {
    match severity {
        DiffSeverity::Info => "S0",
        DiffSeverity::Low => "S1",
        DiffSeverity::Medium => "S2",
        DiffSeverity::High => "S3",
    }
}

/// Krotki, jedno-liniowy tytul findinga z bullet-changeloga (max 250 znakow jak DD).
#[must_use]
pub fn dd_finding_title(
    kind: DiffEventKind,
    severity: DiffSeverity,
    bullets: &[BulletItem],
    ip: &str,
) -> String {
    let head = match kind {
        DiffEventKind::ConfirmedChange => "ASI zmiana",
        DiffEventKind::ActiveVariance => "ASI wariancja",
    };
    let first = bullets
        .first()
        .map(|b| format!("{} {}", b.op_label(), b.key))
        .unwrap_or_else(|| "zmiana stanu".to_string());
    let title = format!("{head} [{}] {ip}: {first}", dd_severity(severity));
    title.chars().take(250).collect()
}

/// Pelny opis findinga: bullet-changelog + info o wykrywcy.
#[must_use]
pub fn dd_finding_description(bullets: &[BulletItem], host_link: &str) -> String {
    let mut out =
        String::from("Wykryte przez ASI (Attack Surface Intelligence, AGH).\n\nZmiany:\n");
    for b in bullets {
        out.push_str(&format!("- {} {}: {}\n", b.op_label(), b.key, b.params));
    }
    out.push_str(&format!("\nSzczegoly w ASI: {host_link}\n"));
    out
}

impl BulletItem {
    /// Etykieta operacji diffu do czytelnego komunikatu ("+", "-", "~").
    #[must_use]
    pub fn op_label(&self) -> &'static str {
        match self.op {
            crate::diff::DiffOp::Added => "+",
            crate::diff::DiffOp::Removed => "-",
            crate::diff::DiffOp::Changed => "~",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::DiffOp;

    #[test]
    fn scope_gating_matches_configuration() {
        assert!(DdFindingScope::Changes.includes(DiffEventKind::ConfirmedChange));
        assert!(!DdFindingScope::Changes.includes(DiffEventKind::ActiveVariance));
        assert!(DdFindingScope::AllDiffs.includes(DiffEventKind::ActiveVariance));
        assert!(DdFindingScope::Inventory.includes(DiffEventKind::ConfirmedChange));
        assert_eq!(
            DdFindingScope::from_db_str("all_diffs"),
            Some(DdFindingScope::AllDiffs)
        );
        assert_eq!(DdFindingScope::from_db_str("nope"), None);
    }

    #[test]
    fn severity_maps_to_dd_slugs() {
        assert_eq!(dd_severity(DiffSeverity::Info), "Info");
        assert_eq!(dd_severity(DiffSeverity::High), "High");
    }

    #[test]
    fn title_is_truncated_and_contains_ip() {
        let bullets = vec![BulletItem {
            op: DiffOp::Added,
            key: "service 8443/tcp".to_string(),
            params: serde_json::json!({"service": "https"}),
        }];
        let title = dd_finding_title(
            DiffEventKind::ConfirmedChange,
            DiffSeverity::Medium,
            &bullets,
            "10.0.0.5",
        );
        assert!(title.contains("10.0.0.5"));
        assert!(title.contains("+ service 8443/tcp"));
        assert!(title.len() <= 250);
    }
}
