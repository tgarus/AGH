//! Klient REST API v2 DefectDojo + mapowanie encji ASI -> DD (ADR-0008).
//!
//! ASI -> DD:  asset_group = Product, scan_run = Engagement + Test,
//!             diff_event = Finding (upsert po `unique_id_from_tool`).
//! DD -> ASI:  pull statusow/tagow findingow do `dd_links`.
//!
//! Celowo NIE uzywamy `reimport-scan` (pułapka przy mikro-paczkach — ADR-0007):
//! kazdy diff_event jest osobnym findingiem zarzadzanym przez `unique_id_from_tool`.

use asi_common::defectdojo::{
    DdEngagement, DdEngagementCreate, DdFinding, DdFindingUpsert, DdPaginated, DdProduct, DdTest,
    DdTestCreate, DdTestType,
};
use chrono::{DateTime, Utc};

pub const DD_TEST_TYPE_NAME: &str = "ASI Attack Surface Scan";
pub const DD_PRODUCT_PREFIX: &str = "ASI: ";

#[derive(Clone)]
pub struct DdClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl DdClient {
    pub fn new(base_url: &str, api_key: &str) -> Result<Self, String> {
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err("DefectDojo base_url is empty".to_string());
        }
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            // uWSGI (DefectDojo) szybko zamyka bezczynne połączenia keep-alive; ponowne
            // użycie takiego połączenia daje „error sending request” na POST — bez puli.
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|e| format!("failed to build DefectDojo HTTP client: {e}"))?;
        Ok(Self {
            http,
            base_url,
            api_key: api_key.to_string(),
        })
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}/api/v2{}", self.base_url, path);
        self.http
            .request(method, url)
            .header("Authorization", format!("Token {}", self.api_key))
            .header("Accept", "application/json")
    }

    async fn get_paginated<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<DdPaginated<T>, String> {
        let resp = self
            .req(reqwest::Method::GET, path)
            .send()
            .await
            .map_err(|e| format_dd_transport_error("GET", path, &e))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format_dd_http_error("GET", path, status, &body));
        }
        serde_json::from_str(&body)
            .map_err(|e| format!("Invalid JSON from DefectDojo GET {path}: {e}"))
    }

    async fn post_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        payload: &T,
    ) -> Result<R, String> {
        let resp = self
            .req(reqwest::Method::POST, path)
            .json(payload)
            .send()
            .await
            .map_err(|e| format_dd_transport_error("POST", path, &e))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format_dd_http_error("POST", path, status, &body));
        }
        serde_json::from_str(&body)
            .map_err(|e| format!("Invalid JSON from DefectDojo POST {path}: {e}"))
    }

    async fn patch_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        payload: &T,
    ) -> Result<R, String> {
        let resp = self
            .req(reqwest::Method::PATCH, path)
            .json(payload)
            .send()
            .await
            .map_err(|e| format_dd_transport_error("PATCH", path, &e))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format_dd_http_error("PATCH", path, status, &body));
        }
        serde_json::from_str(&body)
            .map_err(|e| format!("Invalid JSON from DefectDojo PATCH {path}: {e}"))
    }

    /// Liczba produktow w DD — prosty test polaczenia i autoryzacji.
    pub async fn ping(&self) -> Result<i64, String> {
        let page: DdPaginated<DdProduct> = self.get_paginated("/products/?limit=1").await?;
        Ok(page.count)
    }

    pub async fn ensure_product(
        &self,
        group_name: &str,
        group_description: &str,
    ) -> Result<i32, String> {
        let name = format!("{DD_PRODUCT_PREFIX}{group_name}");
        let path = format!("/products/?name={}", urlencode(&name));
        let page: DdPaginated<DdProduct> = self.get_paginated(&path).await?;
        if let Some(p) = page.results.into_iter().find(|p| p.name == name) {
            return Ok(p.id);
        }
        // prod_type jest wymagany w starszych wersjach DD — bierzemy pierwszy dostepny.
        let prod_type_id: Option<i32> = self
            .get_paginated::<DdProductType>("/product_types/?limit=1")
            .await
            .ok()
            .and_then(|page| page.results.into_iter().next().map(|t| t.id));
        let mut payload = serde_json::json!({
            "name": name,
            "description": format!("Attack surface asset group '{group_name}' — {group_description}"),
            "tags": ["asi", "attack-surface"],
        });
        if let Some(pt) = prod_type_id {
            payload["prod_type"] = serde_json::json!(pt);
        }
        #[derive(serde::Deserialize)]
        struct Created {
            id: i32,
        }
        let created: Created = self.post_json("/products/", &payload).await?;
        Ok(created.id)
    }

    /// Test type "ASI Attack Surface Scan" (create-once).
    pub async fn ensure_test_type(&self) -> Result<i32, String> {
        let path = format!("/test_types/?name={}", urlencode(DD_TEST_TYPE_NAME));
        let page: DdPaginated<DdTestType> = self.get_paginated(&path).await?;
        if let Some(t) = page
            .results
            .into_iter()
            .find(|t| t.name == DD_TEST_TYPE_NAME)
        {
            return Ok(t.id);
        }
        #[derive(serde::Deserialize)]
        struct Created {
            id: i32,
        }
        let created: Created = self
            .post_json(
                "/test_types/",
                &serde_json::json!({ "name": DD_TEST_TYPE_NAME }),
            )
            .await?;
        Ok(created.id)
    }

    /// Engagement per scan_run, idempotentnie po nazwie.
    pub async fn ensure_engagement(
        &self,
        product_id: i32,
        run_label: &str,
        started_at: DateTime<Utc>,
        finished_at: Option<DateTime<Utc>>,
    ) -> Result<i32, String> {
        let name = format!("ASI scan {run_label}");
        let path = format!("/engagements/?name={}", urlencode(&name));
        let page: DdPaginated<DdEngagement> = self.get_paginated(&path).await?;
        if let Some(e) = page
            .results
            .into_iter()
            .find(|e| e.name == name && e.product == product_id)
        {
            return Ok(e.id);
        }
        let target_start = started_at.format("%Y-%m-%d").to_string();
        let target_end = finished_at
            .unwrap_or_else(chrono::Utc::now)
            .format("%Y-%m-%d")
            .to_string();
        let payload = DdEngagementCreate {
            name,
            product: product_id,
            target_start,
            target_end,
            status: "In Progress".to_string(),
            description: Some(format!(
                "Automatyczny engagement ASI dla scan run {run_label}"
            )),
        };
        let created: DdEngagement = self.post_json("/engagements/", &payload).await?;
        Ok(created.id)
    }

    pub async fn close_engagement(&self, engagement_id: i32) -> Result<(), String> {
        self.patch_json::<_, serde_json::Value>(
            &format!("/engagements/{engagement_id}/"),
            &serde_json::json!({ "status": "Completed" }),
        )
        .await?;
        Ok(())
    }

    /// Test per scan_run w danym engagement.
    pub async fn ensure_test(
        &self,
        engagement_id: i32,
        test_type_id: i32,
        run_label: &str,
        started_at: DateTime<Utc>,
        finished_at: Option<DateTime<Utc>>,
    ) -> Result<i32, String> {
        let title = format!("ASI run {run_label}");
        let path = format!("/tests/?title={}", urlencode(&title));
        let page: DdPaginated<DdTest> = self.get_paginated(&path).await?;
        if let Some(t) = page
            .results
            .into_iter()
            .find(|t| t.title == title && t.engagement == engagement_id)
        {
            return Ok(t.id);
        }
        let target_start = started_at.format("%Y-%m-%d").to_string();
        let target_end = finished_at
            .unwrap_or_else(chrono::Utc::now)
            .format("%Y-%m-%d")
            .to_string();
        let payload = DdTestCreate {
            title,
            test_type: test_type_id,
            engagement: engagement_id,
            target_start,
            target_end,
            description: Some("Attack surface diff publish przez ASI".to_string()),
        };
        let created: DdTest = self.post_json("/tests/", &payload).await?;
        Ok(created.id)
    }

    /// Upsert findinga: jesli istnieje po `unique_id_from_tool` -> PATCH, inaczej POST.
    pub async fn upsert_finding(&self, payload: &DdFindingUpsert) -> Result<i32, String> {
        let path = format!(
            "/findings/?unique_id_from_tool={}",
            urlencode(&payload.unique_id_from_tool)
        );
        let page: DdPaginated<DdFinding> = self.get_paginated(&path).await?;
        let wire_body = payload.to_wire_json();
        if let Some(existing) = page.results.into_iter().find(|f| {
            f.unique_id_from_tool.as_deref() == Some(payload.unique_id_from_tool.as_str())
        }) {
            let id = existing.id;
            let _: DdFinding = self
                .patch_json(&format!("/findings/{id}/"), &wire_body)
                .await?;
            return Ok(id);
        }
        #[derive(serde::Deserialize)]
        struct Created {
            id: i32,
        }
        let created: Created = self.post_json("/findings/", &wire_body).await?;
        Ok(created.id)
    }

    /// Pull statusow findingow po id (batch `id__in`).
    pub async fn findings_by_ids(&self, ids: &[i32]) -> Result<Vec<DdFinding>, String> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let joined = ids.iter().map(i32::to_string).collect::<Vec<_>>().join(",");
        let mut all = Vec::new();
        let mut offset = 0_i64;
        loop {
            let path = format!("/findings/?id__in={joined}&limit=100&offset={offset}");
            let page: DdPaginated<DdFinding> = self.get_paginated(&path).await?;
            let n = page.results.len() as i64;
            all.extend(page.results);
            if n < 100 || offset + n >= page.count {
                break;
            }
            offset += n;
        }
        Ok(all)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct DdProductType {
    id: i32,
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn format_dd_transport_error(method: &str, path: &str, err: &reqwest::Error) -> String {
    if err.is_timeout() {
        format!("DefectDojo {method} {path}: przekroczono limit czasu połączenia (timeout): {err}")
    } else if err.is_connect() {
        format!("DefectDojo {method} {path}: nie można nawiązać połączenia z serwerem (sprawdź Base URL i sieć): {err}")
    } else {
        format!("DefectDojo {method} {path}: błąd HTTP: {err}")
    }
}

fn format_dd_http_error(
    method: &str,
    path: &str,
    status: reqwest::StatusCode,
    body: &str,
) -> String {
    let snippet = truncate(body.trim(), 300);
    match status.as_u16() {
        401 | 403 => format!(
            "DefectDojo {method} {path} -> {status} (błąd autoryzacji: sprawdź API Token i uprawnienia konta): {snippet}"
        ),
        400 => format!(
            "DefectDojo {method} {path} -> 400 Bad Request (niepoprawne pola findinga/konfiguracji): {snippet}"
        ),
        404 => format!(
            "DefectDojo {method} {path} -> 404 Not Found (sprawdź czy Base URL nie zawiera /api/v2 ani zbędnego prefiksu): {snippet}"
        ),
        _ => format!("DefectDojo {method} {path} -> {status}: {snippet}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_escapes_polish_and_spaces() {
        assert_eq!(urlencode("ASI: Sieć Kampus"), "ASI%3A%20Sie%C4%87%20Kampus");
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn client_rejects_empty_base_url() {
        assert!(DdClient::new("   ", "key").is_err());
        assert!(DdClient::new("https://dd.example/", "key").is_ok());
    }
}
