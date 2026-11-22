use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::assets::{IgnoredTargetDto, ScanPolicyDto, TargetInput, TargetType};
use crate::inventory::{DiffEventDto, HostSummaryDto, ServiceRowDto};

pub const EXPORT_SCHEMA_VERSION: &str = "1.0";

/// Standard versioned JSON envelope for all ASI exports.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JsonEnvelope<T> {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub entity_type: String,
    pub items: Vec<T>,
}

impl<T> JsonEnvelope<T> {
    #[must_use]
    pub fn new(entity_type: impl Into<String>, items: Vec<T>) -> Self {
        Self {
            schema_version: EXPORT_SCHEMA_VERSION.to_string(),
            exported_at: Utc::now(),
            entity_type: entity_type.into(),
            items,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExportTargetItem {
    pub asset_group_id: Uuid,
    pub asset_group_name: String,
    pub target_type: TargetType,
    pub value: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExportTargetsEnvelope {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub entity_type: String,
    pub items: Vec<ExportTargetItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExportPoliciesEnvelope {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub entity_type: String,
    pub items: Vec<ScanPolicyDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExportIgnoredTargetsEnvelope {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub entity_type: String,
    pub items: Vec<IgnoredTargetDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExportHostsEnvelope {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub entity_type: String,
    pub items: Vec<HostSummaryDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExportDiffsEnvelope {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub entity_type: String,
    pub items: Vec<DiffEventDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExportServicesEnvelope {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub entity_type: String,
    pub items: Vec<ServiceRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportTargetsJsonRequest {
    pub schema_version: String,
    pub asset_group_id: Uuid,
    #[serde(default)]
    pub dry_run: bool,
    pub items: Vec<TargetInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ImportTargetsJsonResponse {
    pub schema_version: String,
    pub dry_run: bool,
    pub asset_group_id: Uuid,
    pub received_count: usize,
    pub inserted_count: usize,
    pub skipped_duplicates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportTargetsFlexibleRequest {
    pub asset_group_id: Option<Uuid>,
    pub new_group_name: Option<String>,
    pub format: Option<String>,
    pub content: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub start_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportTargetsFlexibleResponse {
    pub asset_group_id: Uuid,
    pub asset_group_name: String,
    pub dry_run: bool,
    pub received_count: usize,
    pub inserted_count: usize,
    pub skipped_duplicates: usize,
    pub detected_summary: BTreeMap<String, usize>,
    pub started_scan_run_id: Option<Uuid>,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanResultImportItem {
    pub ip_addr: String,
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub vhost: Option<String>,
    pub scheme: Option<String>,
    pub http_status: Option<u16>,
    pub title: Option<String>,
    #[serde(default)]
    pub technologies: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportScanResultsRequest {
    pub asset_group_id: Uuid,
    pub format: Option<String>,
    pub content: Option<String>,
    #[serde(default)]
    pub items: Vec<ScanResultImportItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportScanResultsResponse {
    pub asset_group_id: Uuid,
    pub hosts_upserted: usize,
    pub ports_upserted: usize,
    pub web_observations_upserted: usize,
    pub diff_events_created: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_envelope_sets_schema_version_1_0() {
        let env: JsonEnvelope<String> =
            JsonEnvelope::new("targets", vec!["10.0.0.0/24".to_string()]);
        assert_eq!(env.schema_version, "1.0");
        assert_eq!(env.entity_type, "targets");
        assert_eq!(env.items.len(), 1);
    }

    #[test]
    fn import_request_round_trips() {
        let json = r#"{
            "schema_version": "1.0",
            "asset_group_id": "00000000-0000-0000-0000-000000000001",
            "dry_run": true,
            "items": [
                { "target_type": "cidr", "value": "172.28.0.0/24", "notes": "Mock lab" }
            ]
        }"#;
        let parsed: ImportTargetsJsonRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.schema_version, "1.0");
        assert!(parsed.dry_run);
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].target_type, TargetType::Cidr);
    }
}
