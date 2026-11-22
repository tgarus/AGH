use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiffEventKind {
    ConfirmedChange,
    ActiveVariance,
}

impl DiffEventKind {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::ConfirmedChange => "confirmed_change",
            Self::ActiveVariance => "active_variance",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "confirmed_change" => Some(Self::ConfirmedChange),
            "active_variance" => Some(Self::ActiveVariance),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiffSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl DiffSeverity {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum DiffOp {
    #[serde(rename = "+")]
    Added,
    #[serde(rename = "-")]
    Removed,
    #[serde(rename = "~")]
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulletItem {
    pub op: DiffOp,
    pub key: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum TimeSlot {
    #[serde(rename = "00_06")]
    Slot0006,
    #[serde(rename = "06_12")]
    Slot0612,
    #[serde(rename = "12_18")]
    Slot1218,
    #[serde(rename = "18_24")]
    Slot1824,
}

impl TimeSlot {
    pub const ALL: [Self; 4] = [
        Self::Slot0006,
        Self::Slot0612,
        Self::Slot1218,
        Self::Slot1824,
    ];

    #[must_use]
    pub const fn from_utc_hour(hour: u32) -> Self {
        match hour {
            0..=5 => Self::Slot0006,
            6..=11 => Self::Slot0612,
            12..=17 => Self::Slot1218,
            _ => Self::Slot1824,
        }
    }

    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Slot0006 => "00_06",
            Self::Slot0612 => "06_12",
            Self::Slot1218 => "12_18",
            Self::Slot1824 => "18_24",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "00_06" => Some(Self::Slot0006),
            "06_12" => Some(Self::Slot0612),
            "12_18" => Some(Self::Slot1218),
            "18_24" => Some(Self::Slot1824),
            _ => None,
        }
    }
}

const IGNORED_NOISE_HEADERS: &[&str] = &[
    "date",
    "etag",
    "age",
    "expires",
    "last-modified",
    "x-request-id",
    "x-correlation-id",
    "cf-ray",
    "x-amz-cf-id",
    "server-timing",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "cookie",
];

/// Returns true for volatile/technical HTTP headers excluded from diff noise
/// and headers handled separately (such as Set-Cookie metadata).
#[must_use]
pub fn is_ignored_http_header(header_name: &str) -> bool {
    let normalized = header_name.trim().to_ascii_lowercase();
    IGNORED_NOISE_HEADERS.contains(&normalized.as_str())
}

/// Normalizes header keys to lowercase and strips volatile noise headers.
#[must_use]
pub fn filter_noise_headers(headers: &HashMap<String, String>) -> BTreeMap<String, String> {
    let mut filtered = BTreeMap::new();
    for (key, value) in headers {
        let normalized = key.trim().to_ascii_lowercase();
        if !normalized.is_empty() && !is_ignored_http_header(&normalized) {
            filtered.insert(normalized, value.clone());
        }
    }
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_headers_are_filtered_case_insensitively() {
        assert!(is_ignored_http_header("Date"));
        assert!(is_ignored_http_header("X-Request-Id"));
        assert!(is_ignored_http_header("CF-RAY"));
        assert!(is_ignored_http_header("ETag"));
        assert!(is_ignored_http_header("Authorization"));
        assert!(is_ignored_http_header("Proxy-Authorization"));
        assert!(is_ignored_http_header("Cookie"));
        assert!(!is_ignored_http_header("Server"));
        assert!(!is_ignored_http_header("X-Powered-By"));

        let raw = HashMap::from([
            (
                "Date".to_string(),
                "Sat, 21 Nov 2026 12:00:00 GMT".to_string(),
            ),
            ("X-Request-Id".to_string(), "abc-123".to_string()),
            ("Authorization".to_string(), "Bearer secret-jwt".to_string()),
            (
                "Proxy-Authorization".to_string(),
                "Basic c2VjcmV0".to_string(),
            ),
            ("Cookie".to_string(), "sid=secret-cookie".to_string()),
            ("Set-Cookie".to_string(), "sid=secret-cookie".to_string()),
            ("Server".to_string(), "nginx/1.27".to_string()),
        ]);
        let filtered = filter_noise_headers(&raw);
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered.get("server").map(String::as_str),
            Some("nginx/1.27")
        );
    }

    #[test]
    fn time_slots_and_severity_ordering_work() {
        assert_eq!(TimeSlot::from_utc_hour(2), TimeSlot::Slot0006);
        assert_eq!(TimeSlot::from_utc_hour(9), TimeSlot::Slot0612);
        assert_eq!(TimeSlot::from_utc_hour(14), TimeSlot::Slot1218);
        assert_eq!(TimeSlot::from_utc_hour(21), TimeSlot::Slot1824);
        assert_eq!(TimeSlot::from_db_str("12_18"), Some(TimeSlot::Slot1218));
        assert_eq!(TimeSlot::from_db_str("bad"), None);
        assert!(DiffSeverity::High > DiffSeverity::Medium);
        assert!(DiffSeverity::Medium > DiffSeverity::Low);
        assert!(DiffSeverity::Low > DiffSeverity::Info);
    }
}
