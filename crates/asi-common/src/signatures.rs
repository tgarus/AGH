use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignatureRuleSource {
    Fingerprinthub,
    FingerprinthubRepo,
    Custom,
}

impl SignatureRuleSource {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Fingerprinthub => "fingerprinthub",
            Self::FingerprinthubRepo => "fingerprinthub_repo",
            Self::Custom => "custom",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "fingerprinthub" => Some(Self::Fingerprinthub),
            "fingerprinthub_repo" => Some(Self::FingerprinthubRepo),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignatureRuleDto {
    pub id: Uuid,
    pub template_id: String,
    pub name: String,
    pub source: SignatureRuleSource,
    pub format: String,
    pub yaml_content: String,
    pub content_sha256: String,
    pub tags: Vec<String>,
    pub is_enabled: bool,
    pub created_by: Option<Uuid>,
    pub synced_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateSignatureRuleRequest {
    pub yaml_content: String,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateSignatureRuleRequest {
    pub yaml_content: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateSignatureRequest {
    pub yaml_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateSignatureResponse {
    pub valid: bool,
    pub template_id: Option<String>,
    pub name: Option<String>,
    pub tags: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportSignaturesJsonRequest {
    pub schema_version: String,
    #[serde(default)]
    pub dry_run: bool,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportSignaturesJsonResponse {
    pub schema_version: String,
    pub dry_run: bool,
    pub received_count: usize,
    pub upserted_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SyncSignaturesResponse {
    pub synced_count: usize,
    #[serde(default)]
    pub builtin_count: usize,
    #[serde(default)]
    pub repo_count: usize,
    #[serde(default)]
    pub skipped_count: usize,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub repo_error: Option<String>,
    pub synced_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FingerprintTemplate {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub http: Vec<HttpProbeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateInfo {
    pub name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default, deserialize_with = "deserialize_tags")]
    pub tags: Vec<String>,
}

fn deserialize_tags<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TagsRepr {
        List(Vec<String>),
        Csv(String),
    }

    match Option::<TagsRepr>::deserialize(deserializer)? {
        Some(TagsRepr::List(v)) => Ok(v),
        Some(TagsRepr::Csv(s)) => Ok(s
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(ToString::to_string)
            .collect()),
        None => Ok(Vec::new()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HttpProbeSpec {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: ConditionOp,
    #[serde(default)]
    pub matchers: Vec<TemplateMatcher>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOp {
    #[default]
    Or,
    And,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatcherType {
    #[default]
    Word,
    Regex,
    Status,
    Favicon,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatcherPart {
    #[default]
    All,
    Body,
    Header,
    Title,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateMatcher {
    #[serde(rename = "type")]
    pub matcher_type: MatcherType,
    #[serde(default)]
    pub part: MatcherPart,
    #[serde(default)]
    pub condition: ConditionOp,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub hash: Vec<String>,
    #[serde(default)]
    pub negative: bool,
}

pub fn parse_fingerprinthub_v4_yaml(yaml: &str) -> Result<FingerprintTemplate, String> {
    let parsed: FingerprintTemplate = serde_yaml::from_str(yaml)
        .map_err(|err| format!("Invalid FingerprintHub v4 YAML: {err}"))?;

    if parsed.id.trim().is_empty() {
        return Err("Template 'id' cannot be empty.".to_string());
    }
    if parsed.info.name.trim().is_empty() {
        return Err("Template 'info.name' cannot be empty.".to_string());
    }
    if parsed.http.is_empty() {
        return Err("Template must define at least one 'http' probe block.".to_string());
    }

    for probe in &parsed.http {
        for matcher in &probe.matchers {
            for pat in &matcher.regex {
                Regex::new(pat).map_err(|err| format!("Invalid regex pattern '{pat}': {err}"))?;
            }
        }
    }

    Ok(parsed)
}

#[must_use]
pub fn builtin_default_signatures_yaml() -> Vec<String> {
    vec![
        r#"id: nginx-web-server
info:
  name: Nginx
  author: asi-builtin
  severity: info
  tags: web,server
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "Server: nginx"
          - "server: nginx"
"#
        .to_string(),
        r#"id: agh-staging-environment
info:
  name: Staging Environment
  author: asi-builtin
  severity: info
  tags: staging,shadow-it
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        part: all
        regex:
          - "(?i)(staging|preprod|test-portal)"
"#
        .to_string(),
        r#"id: generic-admin-login-panel
info:
  name: Admin Panel
  author: asi-builtin
  severity: info
  tags: admin-panel,login
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/login"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - "(?i)(admin|administration|login)"
"#
        .to_string(),
        r#"id: apache-httpd
info:
  name: Apache HTTP Server
  author: asi-builtin
  severity: info
  tags: web,server
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "server: Apache"
          - "Server: Apache"
"#
        .to_string(),
        r#"id: wordpress-cms
info:
  name: WordPress
  author: asi-builtin
  severity: info
  tags: cms,wordpress
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        part: body
        regex:
          - "(?i)(/wp-content/|/wp-includes/|name=\"generator\" content=\"WordPress)"
"#
        .to_string(),
        r#"id: grafana-dashboard
info:
  name: Grafana
  author: asi-builtin
  severity: info
  tags: monitoring,dashboard
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/login"
    matchers:
      - type: regex
        part: all
        regex:
          - "(?i)(<title>Grafana</title>|grafana-app)"
"#
        .to_string(),
        r#"id: jenkins-ci
info:
  name: Jenkins
  author: asi-builtin
  severity: info
  tags: ci,devops
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/login"
    matchers:
      - type: regex
        part: all
        regex:
          - "(?i)(x-jenkins:|Dashboard \\[Jenkins\\])"
"#
        .to_string(),
        r#"id: gitlab-instance
info:
  name: GitLab
  author: asi-builtin
  severity: info
  tags: devops,git
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/login"
    matchers:
      - type: regex
        part: all
        regex:
          - "(?i)(_gitlab_session|content=\"GitLab\"|Sign in · GitLab)"
"#
        .to_string(),
        r#"id: prometheus-monitoring
info:
  name: Prometheus
  author: asi-builtin
  severity: info
  tags: monitoring,metrics
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        part: all
        regex:
          - "(?i)(Prometheus Time Series Collection|# TYPE go_goroutines)"
"#
        .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_builtin_fingerprinthub_v4_rules() {
        for yaml in builtin_default_signatures_yaml() {
            let tpl = parse_fingerprinthub_v4_yaml(&yaml).unwrap();
            assert!(!tpl.id.is_empty());
            assert!(!tpl.http.is_empty());
        }
    }

    #[test]
    fn rejects_invalid_regex_in_yaml() {
        let bad = r#"id: bad-regex
info:
  name: Bad
http:
  - method: GET
    matchers:
      - type: regex
        regex:
          - "[unclosed"
"#;
        assert!(parse_fingerprinthub_v4_yaml(bad).is_err());
    }
}
