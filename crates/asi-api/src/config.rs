use std::fmt;
use std::net::SocketAddr;

use anyhow::{Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

/// Konfiguracja źródła sygnatur FingerprintHub (repo GitHub lub lokalny katalog dla środowisk air-gapped).
#[derive(Debug, Clone)]
pub struct SignatureSyncConfig {
    pub repo: String,
    pub git_ref: String,
    pub dir: String,
    pub local_dir: Option<String>,
    pub sync_on_startup: bool,
}

impl Default for SignatureSyncConfig {
    fn default() -> Self {
        Self {
            repo: "0x727/FingerprintHub".to_string(),
            git_ref: "main".to_string(),
            dir: "web-fingerprint".to_string(),
            local_dir: None,
            sync_on_startup: true,
        }
    }
}

#[derive(Clone)]
pub struct ApiConfig {
    pub bind_addr: SocketAddr,
    pub database_url: Option<String>,
    pub auto_migrate: bool,
    pub cors_origin: String,
    pub log_format: LogFormat,
    pub jwt_secret: String,
    pub master_key: String,
    pub cookie_secure: bool,
    pub bootstrap_admin_username: String,
    pub bootstrap_admin_email: String,
    pub bootstrap_admin_password: Option<String>,
    pub sig_sync: SignatureSyncConfig,
}

impl fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiConfig")
            .field("bind_addr", &self.bind_addr)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("auto_migrate", &self.auto_migrate)
            .field("cors_origin", &self.cors_origin)
            .field("log_format", &self.log_format)
            .field("jwt_secret", &"[REDACTED]")
            .field("master_key", &"[REDACTED]")
            .field("cookie_secure", &self.cookie_secure)
            .field("bootstrap_admin_username", &self.bootstrap_admin_username)
            .field("bootstrap_admin_email", &self.bootstrap_admin_email)
            .field(
                "bootstrap_admin_password",
                &self.bootstrap_admin_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("sig_sync", &self.sig_sync)
            .finish()
    }
}

impl ApiConfig {
    pub fn from_env() -> Result<Self> {
        let bind_raw =
            std::env::var("ASI_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let bind_addr: SocketAddr = bind_raw
            .parse()
            .with_context(|| format!("invalid ASI_BIND_ADDR: {bind_raw}"))?;

        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());

        let auto_migrate = std::env::var("ASI_AUTO_MIGRATE")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);

        let cors_origin = std::env::var("ASI_CORS_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:5173".to_string());

        let log_format = match std::env::var("ASI_LOG_FORMAT")
            .unwrap_or_else(|_| "json".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "pretty" => LogFormat::Pretty,
            _ => LogFormat::Json,
        };

        let jwt_secret = std::env::var("ASI_JWT_SECRET")
            .unwrap_or_else(|_| "dev-only-change-me-at-least-32-bytes-long-secret".to_string());
        let master_key = std::env::var("ASI_MASTER_KEY").unwrap_or_else(|_| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });

        let cookie_secure = std::env::var("ASI_COOKIE_SECURE")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);

        let bootstrap_admin_username =
            std::env::var("ASI_BOOTSTRAP_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
        let bootstrap_admin_email = std::env::var("ASI_BOOTSTRAP_ADMIN_EMAIL")
            .unwrap_or_else(|_| "admin@agh.local".to_string());
        let bootstrap_admin_password = std::env::var("ASI_BOOTSTRAP_ADMIN_PASSWORD")
            .ok()
            .filter(|v| !v.trim().is_empty());

        let sig_sync = SignatureSyncConfig {
            repo: std::env::var("ASI_FINGERPRINTHUB_REPO")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "0x727/FingerprintHub".to_string()),
            git_ref: std::env::var("ASI_FINGERPRINTHUB_REF")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "main".to_string()),
            dir: std::env::var("ASI_FINGERPRINTHUB_DIR")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "web-fingerprint".to_string()),
            local_dir: std::env::var("ASI_FINGERPRINTHUB_LOCAL_DIR")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            sync_on_startup: std::env::var("ASI_FINGERPRINTHUB_SYNC_ON_STARTUP")
                .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
        };

        Ok(Self {
            bind_addr,
            database_url,
            auto_migrate,
            cors_origin,
            log_format,
            jwt_secret,
            master_key,
            cookie_secure,
            bootstrap_admin_username,
            bootstrap_admin_email,
            bootstrap_admin_password,
            sig_sync,
        })
    }
}
