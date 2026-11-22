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
    #[serde(default)]
    pub asi_public_url: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdRetryOutboxResponse {
    pub retried_count: i64,
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
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub is_mitigated: Option<bool>,
    #[serde(default)]
    pub false_p: Option<bool>,
    #[serde(default)]
    pub out_of_scope: Option<bool>,
    #[serde(default)]
    pub risk_accepted: Option<bool>,
}

impl DdFinding {
    #[must_use]
    pub fn effective_status(&self) -> String {
        if let Some(s) = &self.status {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        let mut parts = Vec::new();
        if self.is_mitigated == Some(true) {
            parts.push("Mitigated");
        } else if self.false_p == Some(true) {
            parts.push("False Positive");
        } else if self.risk_accepted == Some(true) {
            parts.push("Risk Accepted");
        } else if self.out_of_scope == Some(true) {
            parts.push("Out of Scope");
        } else if self.active == Some(true) {
            parts.push("Active");
        } else {
            parts.push("Inactive");
        }
        if self.verified == Some(true) {
            parts.push("Verified");
        }
        parts.join(", ")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DdFindingPayloadOverride {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub numerical_severity: Option<String>,
    #[serde(default)]
    pub mitigation: Option<String>,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub component_name: Option<String>,
    #[serde(default)]
    pub references: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub false_p: Option<bool>,
    #[serde(default)]
    pub out_of_scope: Option<bool>,
    #[serde(default)]
    pub extra_notes: Option<String>,
    #[serde(default)]
    pub custom_fields: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub false_p: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_of_scope: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<serde_json::Value>,
}

#[must_use]
pub fn normalize_dd_severity(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => "Critical".to_string(),
        "high" => "High".to_string(),
        "medium" => "Medium".to_string(),
        "low" => "Low".to_string(),
        "info" | "informational" => "Info".to_string(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => "Info".to_string(),
            }
        }
    }
}

#[must_use]
pub fn dd_numerical_from_severity_str(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => "S4",
        "high" => "S3",
        "medium" => "S2",
        "low" => "S1",
        _ => "S0",
    }
}

impl DdFindingUpsert {
    pub fn apply_override(&mut self, ov: &DdFindingPayloadOverride) {
        if let Some(title) = ov.title.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            self.title = title.chars().take(250).collect();
        }
        if let Some(description) = ov.description.as_deref() {
            if !description.trim().is_empty() {
                self.description = description.to_string();
            }
        }
        if let Some(extra) = ov
            .extra_notes
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if !self.description.ends_with('\n') {
                self.description.push('\n');
            }
            self.description
                .push_str(&format!("\nNotatka analityka:\n{extra}\n"));
        }
        if let Some(sev) = ov
            .severity
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let norm = normalize_dd_severity(sev);
            self.severity = norm.clone();
            if ov
                .numerical_severity
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_none()
            {
                self.numerical_severity = dd_numerical_from_severity_str(&norm).to_string();
            }
        }
        if let Some(num) = ov
            .numerical_severity
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            self.numerical_severity = num.to_string();
        }
        if let Some(mitigation) = &ov.mitigation {
            let trimmed = mitigation.trim();
            self.mitigation = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Some(impact) = &ov.impact {
            let trimmed = impact.trim();
            self.impact = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Some(component) = &ov.component_name {
            let trimmed = component.trim();
            self.component_name = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Some(references) = &ov.references {
            let trimmed = references.trim();
            self.references = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Some(tags) = &ov.tags {
            self.tags = tags
                .iter()
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
        }
        if let Some(active) = ov.active {
            self.active = active;
        }
        if let Some(verified) = ov.verified {
            self.verified = verified;
        }
        if let Some(false_p) = ov.false_p {
            self.false_p = Some(false_p);
        }
        if let Some(out_of_scope) = ov.out_of_scope {
            self.out_of_scope = Some(out_of_scope);
        }
        if let Some(cf) = &ov.custom_fields {
            if cf.is_object() {
                self.custom_fields = Some(cf.clone());
            } else if cf.is_null() {
                self.custom_fields = None;
            }
        }
    }

    #[must_use]
    pub fn to_wire_json(&self) -> serde_json::Value {
        let mut val = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(obj) = val.as_object_mut() {
            obj.remove("custom_fields");
            if let Some(serde_json::Value::Object(extra)) = &self.custom_fields {
                for (k, v) in extra {
                    let key = k.trim();
                    if !key.is_empty() {
                        obj.insert(key.to_string(), v.clone());
                    }
                }
            }
        }
        val
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdFindingPreviewDto {
    pub target_kind: String,
    pub target_id: Uuid,
    pub ip_addr: String,
    pub asset_group_name: String,
    pub default_payload: DdFindingUpsert,
    pub saved_override: Option<DdFindingPayloadOverride>,
    pub effective_payload: DdFindingUpsert,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DdPushHostResponse {
    pub host_id: Uuid,
    pub dd_finding_id: i32,
    pub note: String,
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

    #[test]
    fn override_and_wire_json_apply_all_fields_and_custom_fields() {
        let mut payload = DdFindingUpsert {
            title: "Original title".to_string(),
            description: "Original description".to_string(),
            severity: "Low".to_string(),
            date: "2026-11-22".to_string(),
            test: 10,
            found_by: vec![10],
            numerical_severity: "S1".to_string(),
            unique_id_from_tool: "diff-123".to_string(),
            component_name: Some("http".to_string()),
            references: None,
            tags: vec!["asi".to_string()],
            active: true,
            verified: false,
            ..Default::default()
        };

        let ov = DdFindingPayloadOverride {
            title: Some("Custom title".to_string()),
            severity: Some("critical".to_string()),
            extra_notes: Some("Potwierdzono przez SOC".to_string()),
            mitigation: Some("Ogranicz dostep przez VPN".to_string()),
            impact: Some("Wystawiony panel admin".to_string()),
            tags: Some(vec!["asi".to_string(), "urgent".to_string()]),
            verified: Some(true),
            custom_fields: Some(serde_json::json!({
                "endpoints": ["https://10.0.0.5/admin"],
                "cwe": 284
            })),
            ..Default::default()
        };

        payload.apply_override(&ov);
        assert_eq!(payload.title, "Custom title");
        assert_eq!(payload.severity, "Critical");
        assert_eq!(payload.numerical_severity, "S4");
        assert!(payload.description.contains("Original description"));
        assert!(payload.description.contains("Potwierdzono przez SOC"));
        assert_eq!(
            payload.mitigation.as_deref(),
            Some("Ogranicz dostep przez VPN")
        );
        assert_eq!(payload.impact.as_deref(), Some("Wystawiony panel admin"));
        assert!(payload.verified);
        assert_eq!(payload.tags, vec!["asi", "urgent"]);

        let wire = payload.to_wire_json();
        assert!(wire.get("custom_fields").is_none());
        assert_eq!(wire["cwe"], 284);
        assert_eq!(wire["endpoints"][0], "https://10.0.0.5/admin");
    }

    #[test]
    fn effective_status_derives_from_booleans_when_status_missing() {
        let f_active = DdFinding {
            id: 1,
            title: "Open port".to_string(),
            severity: Some("High".to_string()),
            status: None,
            unique_id_from_tool: None,
            tags: vec![],
            active: Some(true),
            verified: Some(true),
            is_mitigated: None,
            false_p: None,
            out_of_scope: None,
            risk_accepted: None,
        };
        assert_eq!(f_active.effective_status(), "Active, Verified");

        let f_mitigated = DdFinding {
            is_mitigated: Some(true),
            verified: Some(false),
            ..f_active.clone()
        };
        assert_eq!(f_mitigated.effective_status(), "Mitigated");

        let f_explicit = DdFinding {
            status: Some("Fixed".to_string()),
            ..f_active
        };
        assert_eq!(f_explicit.effective_status(), "Fixed");
    }
}
