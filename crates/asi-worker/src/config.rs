use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerLogFormat {
    Json,
    Pretty,
}

#[derive(Clone)]
pub struct WorkerConfig {
    pub api_url: String,
    pub worker_name: String,
    pub segment_tag: Option<String>,
    pub worker_token: Option<String>,
    pub max_concurrency: u32,
    pub kill_grace_seconds: u64,
    pub allow_local_mock_lab: bool,
    pub log_format: WorkerLogFormat,
}

impl fmt::Debug for WorkerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerConfig")
            .field("api_url", &self.api_url)
            .field("worker_name", &self.worker_name)
            .field("segment_tag", &self.segment_tag)
            .field(
                "worker_token",
                &self.worker_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("max_concurrency", &self.max_concurrency)
            .field("kill_grace_seconds", &self.kill_grace_seconds)
            .field("allow_local_mock_lab", &self.allow_local_mock_lab)
            .field("log_format", &self.log_format)
            .finish()
    }
}

impl WorkerConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let api_url = std::env::var("ASI_WORKER_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let worker_name =
            std::env::var("ASI_WORKER_NAME").unwrap_or_else(|_| "wsl-dev-worker".to_string());
        let segment_tag = std::env::var("ASI_WORKER_SEGMENT_TAG")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let worker_token = std::env::var("ASI_WORKER_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());

        let max_concurrency = std::env::var("ASI_WORKER_MAX_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|&v| v >= 1)
            .unwrap_or(2);

        let kill_grace_seconds = std::env::var("ASI_KILL_GRACE_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.clamp(1, 10))
            .unwrap_or(3);

        let allow_local_mock_lab = std::env::var("ASI_ALLOW_LOCAL_MOCK_LAB")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        let log_format = match std::env::var("ASI_LOG_FORMAT")
            .unwrap_or_else(|_| "json".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "pretty" => WorkerLogFormat::Pretty,
            _ => WorkerLogFormat::Json,
        };

        Self {
            api_url,
            worker_name,
            segment_tag,
            worker_token,
            max_concurrency,
            kill_grace_seconds,
            allow_local_mock_lab,
            log_format,
        }
    }
}
