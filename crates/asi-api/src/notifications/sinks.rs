use std::time::Duration;

use asi_common::diff::{BulletItem, DiffOp};
use asi_common::error::{DomainError, FieldViolation};
use asi_common::notification::{NotificationChannelType, NotificationMessage, NotificationSink};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Computes RFC 2104 HMAC-SHA256 hex digest using pure-Rust `sha2`.
#[must_use]
pub fn hmac_sha256_hex(secret: &[u8], message: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0_u8; BLOCK_SIZE];
    if secret.len() > BLOCK_SIZE {
        let digest = Sha256::digest(secret);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut ipad = [0x36_u8; BLOCK_SIZE];
    let mut opad = [0x5c_u8; BLOCK_SIZE];
    for idx in 0..BLOCK_SIZE {
        ipad[idx] ^= key_block[idx];
        opad[idx] ^= key_block[idx];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

#[must_use]
pub fn render_plain_bullet(item: &BulletItem) -> String {
    let op = match item.op {
        DiffOp::Added => "+",
        DiffOp::Removed => "-",
        DiffOp::Changed => "~",
    };
    let port = item.params.get("port").and_then(|v| v.as_u64());
    let detail = match item.key.as_str() {
        "host_discovered" => format!(
            "Host discovered ({} open ports)",
            item.params
                .get("open_ports")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        ),
        "host_inactive" => "Host became inactive".to_string(),
        "probable_tarpit_detected" => format!(
            "Probable tarpit detected ({} ports)",
            item.params
                .get("open_port_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        ),
        "service_added" => format!(
            "Service added: {}/{}",
            port.unwrap_or(0),
            item.params
                .get("proto")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp")
        ),
        "service_removed" => format!(
            "Service removed: {}/{}",
            port.unwrap_or(0),
            item.params
                .get("proto")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp")
        ),
        "admin_panel_detected" => format!(
            "Admin panel {} on port {} ({})",
            item.params
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("/admin"),
            port.unwrap_or(0),
            item.params
                .get("vhost")
                .and_then(|v| v.as_str())
                .unwrap_or("")
        ),
        "diurnal_variance" => format!(
            "Diurnal variance (active: {})",
            item.params
                .get("active_hours")
                .and_then(|v| v.as_str())
                .unwrap_or("intermittent")
        ),
        other => format!("{other}: {}", item.params),
    };
    format!("{op} {detail}")
}

#[must_use]
pub fn render_notification_summary(msg: &NotificationMessage) -> (String, Vec<String>) {
    let kind_label = match msg.event_kind {
        asi_common::diff::DiffEventKind::ConfirmedChange => "Confirmed Change",
        asi_common::diff::DiffEventKind::ActiveVariance => "Active Variance",
    };
    let title = format!(
        "[ASI] {kind_label} ({:?}) — {} [{}]",
        msg.severity, msg.ip_addr, msg.asset_group_name
    );
    let lines = msg.bullet_items.iter().map(render_plain_bullet).collect();
    (title, lines)
}

fn build_http_client() -> Result<Client, DomainError> {
    Client::builder()
        .use_rustls_tls()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|err| DomainError::Internal(format!("http client init failed: {err}")))
}

async fn post_json_webhook(
    client: &Client,
    url: &str,
    payload: &serde_json::Value,
) -> Result<(), DomainError> {
    let resp = client
        .post(url)
        .json(payload)
        .send()
        .await
        .map_err(|err| DomainError::Internal(format!("webhook send failed: {err}")))?;

    if !resp.status().is_success() {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(DomainError::Internal(format!(
            "webhook endpoint returned HTTP {code}: {}",
            body.chars().take(200).collect::<String>()
        )));
    }
    Ok(())
}

pub struct WebhookJsonSink {
    url: String,
    secret: Option<String>,
    http: Client,
}

#[async_trait]
impl NotificationSink for WebhookJsonSink {
    async fn send(&self, message: &NotificationMessage) -> Result<(), DomainError> {
        let timestamp = message.detected_at.timestamp().to_string();
        let payload = serde_json::json!({
            "event": "diff.detected",
            "delivery_id": message.delivery_id,
            "diff_event_id": message.diff_event_id,
            "asset_group_name": message.asset_group_name,
            "host_id": message.host_id,
            "ip_addr": message.ip_addr,
            "event_kind": message.event_kind,
            "severity": message.severity,
            "bullet_items": message.bullet_items,
            "detected_at": message.detected_at,
        });
        let raw_body = serde_json::to_string(&payload)
            .map_err(|err| DomainError::Internal(format!("json serialize failed: {err}")))?;

        let mut req = self
            .http
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("X-ASI-Event", "diff.detected")
            .header("X-ASI-Delivery-Id", message.delivery_id.to_string())
            .header("X-ASI-Timestamp", &timestamp);

        if let Some(secret) = self.secret.as_deref().filter(|s| !s.is_empty()) {
            let signed_payload = format!("{timestamp}.{raw_body}");
            let sig = hmac_sha256_hex(secret.as_bytes(), signed_payload.as_bytes());
            req = req.header("X-ASI-Signature-256", format!("sha256={sig}"));
        }

        let resp = req
            .body(raw_body)
            .send()
            .await
            .map_err(|err| DomainError::Internal(format!("webhook POST failed: {err}")))?;

        if !resp.status().is_success() {
            return Err(DomainError::Internal(format!(
                "webhook HTTP status {}",
                resp.status()
            )));
        }
        Ok(())
    }
}

pub struct SlackSink {
    url: String,
    http: Client,
}

#[async_trait]
impl NotificationSink for SlackSink {
    async fn send(&self, message: &NotificationMessage) -> Result<(), DomainError> {
        let (title, lines) = render_notification_summary(message);
        let body_text = format!("*{title}*\n{}", lines.join("\n"));
        let payload = serde_json::json!({
            "text": body_text,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": body_text
                    }
                }
            ]
        });
        post_json_webhook(&self.http, &self.url, &payload).await
    }
}

pub struct TeamsSink {
    url: String,
    http: Client,
}

#[async_trait]
impl NotificationSink for TeamsSink {
    async fn send(&self, message: &NotificationMessage) -> Result<(), DomainError> {
        let (title, lines) = render_notification_summary(message);
        let theme_color = match message.severity {
            asi_common::diff::DiffSeverity::High => "D92D20",
            asi_common::diff::DiffSeverity::Medium => "F79009",
            asi_common::diff::DiffSeverity::Low => "1570EF",
            asi_common::diff::DiffSeverity::Info => "667085",
        };
        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": title,
            "title": title,
            "text": lines.join("<br/>"),
        });
        post_json_webhook(&self.http, &self.url, &payload).await
    }
}

pub struct MattermostSink {
    url: String,
    http: Client,
}

#[async_trait]
impl NotificationSink for MattermostSink {
    async fn send(&self, message: &NotificationMessage) -> Result<(), DomainError> {
        let (title, lines) = render_notification_summary(message);
        let markdown = format!("#### {title}\n{}", lines.join("\n"));
        let payload = serde_json::json!({
            "username": "ASI",
            "text": markdown,
        });
        post_json_webhook(&self.http, &self.url, &payload).await
    }
}

pub struct SmtpSink {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    from: String,
    to: String,
}

async fn read_smtp_reply(
    reader: &mut BufReader<tokio::net::tcp::ReadHalf<'_>>,
    expected_prefix: &str,
) -> Result<(), DomainError> {
    let mut line = String::new();
    loop {
        line.clear();
        let read_res = tokio::time::timeout(REQUEST_TIMEOUT, reader.read_line(&mut line))
            .await
            .map_err(|_| DomainError::Internal("smtp read timeout".to_string()))?
            .map_err(|err| DomainError::Internal(format!("smtp read failed: {err}")))?;
        if read_res == 0 {
            return Err(DomainError::Internal("smtp unexpected EOF".to_string()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() >= 4 && trimmed.as_bytes()[3] == b'-' {
            continue;
        }
        if trimmed.starts_with(expected_prefix) {
            return Ok(());
        }
        return Err(DomainError::Internal(format!(
            "smtp expected {expected_prefix}, got: {trimmed}"
        )));
    }
}

#[async_trait]
impl NotificationSink for SmtpSink {
    async fn send(&self, message: &NotificationMessage) -> Result<(), DomainError> {
        let (subject, lines) = render_notification_summary(message);
        let mut stream = tokio::time::timeout(
            REQUEST_TIMEOUT,
            TcpStream::connect((self.host.as_str(), self.port)),
        )
        .await
        .map_err(|_| DomainError::Internal("smtp connect timeout".to_string()))?
        .map_err(|err| DomainError::Internal(format!("smtp connect failed: {err}")))?;

        let (read_half, mut write_half) = stream.split();
        let mut reader = BufReader::new(read_half);

        read_smtp_reply(&mut reader, "220").await?;
        write_half
            .write_all(b"EHLO asi.agh.edu.pl\r\n")
            .await
            .map_err(|e| DomainError::Internal(format!("smtp write EHLO failed: {e}")))?;
        read_smtp_reply(&mut reader, "250").await?;

        if let (Some(user), Some(pass)) = (
            self.username.as_deref().filter(|s| !s.is_empty()),
            self.password.as_deref().filter(|s| !s.is_empty()),
        ) {
            let raw_auth = format!("\0{user}\0{pass}");
            let encoded = STANDARD.encode(raw_auth.as_bytes());
            let cmd = format!("AUTH PLAIN {encoded}\r\n");
            write_half
                .write_all(cmd.as_bytes())
                .await
                .map_err(|e| DomainError::Internal(format!("smtp write AUTH failed: {e}")))?;
            read_smtp_reply(&mut reader, "235").await?;
        }

        let mail_from = format!("MAIL FROM:<{}>\r\n", self.from);
        write_half
            .write_all(mail_from.as_bytes())
            .await
            .map_err(|e| DomainError::Internal(format!("smtp MAIL FROM failed: {e}")))?;
        read_smtp_reply(&mut reader, "250").await?;

        let rcpt_to = format!("RCPT TO:<{}>\r\n", self.to);
        write_half
            .write_all(rcpt_to.as_bytes())
            .await
            .map_err(|e| DomainError::Internal(format!("smtp RCPT TO failed: {e}")))?;
        read_smtp_reply(&mut reader, "250").await?;

        write_half
            .write_all(b"DATA\r\n")
            .await
            .map_err(|e| DomainError::Internal(format!("smtp DATA failed: {e}")))?;
        read_smtp_reply(&mut reader, "354").await?;

        let escaped_body = lines
            .into_iter()
            .map(|l| {
                if l.starts_with('.') {
                    format!(".{l}")
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n");

        let msg_data = format!(
            "From: <{}>\r\nTo: <{}>\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{escaped_body}\r\n.\r\n",
            self.from, self.to
        );
        write_half
            .write_all(msg_data.as_bytes())
            .await
            .map_err(|e| DomainError::Internal(format!("smtp body write failed: {e}")))?;
        read_smtp_reply(&mut reader, "250").await?;

        let _ = write_half.write_all(b"QUIT\r\n").await;
        Ok(())
    }
}

fn require_http_url(config: &serde_json::Value) -> Result<String, DomainError> {
    let url = config
        .get("url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(DomainError::Validation {
            detail: "Notification channel config validation failed.".to_string(),
            violations: vec![FieldViolation {
                field: "config_public.url".to_string(),
                code: "INVALID_URL".to_string(),
                message: "Expected an http:// or https:// webhook URL.".to_string(),
            }],
        });
    }
    Ok(url.to_string())
}

fn require_non_empty_str(config: &serde_json::Value, key: &str) -> Result<String, DomainError> {
    let val = config
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if val.is_empty() {
        return Err(DomainError::Validation {
            detail: "Notification channel config validation failed.".to_string(),
            violations: vec![FieldViolation {
                field: format!("config_public.{key}"),
                code: "REQUIRED".to_string(),
                message: format!("Field '{key}' is required."),
            }],
        });
    }
    Ok(val.to_string())
}

pub fn build_sink(
    channel_type: NotificationChannelType,
    config_public: &serde_json::Value,
    decrypted_secret: Option<&str>,
) -> Result<Box<dyn NotificationSink>, DomainError> {
    match channel_type {
        NotificationChannelType::WebhookJson => {
            let url = require_http_url(config_public)?;
            Ok(Box::new(WebhookJsonSink {
                url,
                secret: decrypted_secret.map(ToString::to_string),
                http: build_http_client()?,
            }))
        }
        NotificationChannelType::Slack => Ok(Box::new(SlackSink {
            url: require_http_url(config_public)?,
            http: build_http_client()?,
        })),
        NotificationChannelType::Teams => Ok(Box::new(TeamsSink {
            url: require_http_url(config_public)?,
            http: build_http_client()?,
        })),
        NotificationChannelType::Mattermost => Ok(Box::new(MattermostSink {
            url: require_http_url(config_public)?,
            http: build_http_client()?,
        })),
        NotificationChannelType::Smtp => {
            let host = require_non_empty_str(config_public, "host")?;
            let from = require_non_empty_str(config_public, "from")?;
            let to = require_non_empty_str(config_public, "to")?;
            let port_u64 = config_public
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(587);
            let port = u16::try_from(port_u64).unwrap_or(587);
            let username = config_public
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            Ok(Box::new(SmtpSink {
                host,
                port,
                username,
                password: decrypted_secret.map(ToString::to_string),
                from,
                to,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc4231_vector() {
        let sig = hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            sig,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn builds_and_validates_sink_configs() {
        assert!(build_sink(
            NotificationChannelType::WebhookJson,
            &serde_json::json!({ "url": "https://hooks.agh.local/asi" }),
            Some("top-secret")
        )
        .is_ok());

        assert!(build_sink(
            NotificationChannelType::Slack,
            &serde_json::json!({ "url": "ftp://invalid" }),
            None
        )
        .is_err());

        assert!(build_sink(
            NotificationChannelType::Teams,
            &serde_json::json!({ "url": "https://outlook.office.com/webhook/abc" }),
            None
        )
        .is_ok());

        assert!(build_sink(
            NotificationChannelType::Mattermost,
            &serde_json::json!({ "url": "https://mm.agh.local/hooks/xyz" }),
            None
        )
        .is_ok());

        assert!(build_sink(
            NotificationChannelType::Smtp,
            &serde_json::json!({ "host": "smtp.agh.local", "port": 2525, "from": "asi@agh.local", "to": "soc@agh.local" }),
            None
        )
        .is_ok());

        assert!(build_sink(
            NotificationChannelType::Smtp,
            &serde_json::json!({ "host": "" }),
            None
        )
        .is_err());
    }
}
