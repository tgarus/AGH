use std::time::Duration;

use anyhow::{Context, Result};
use asi_common::worker::{
    ChunkLeaseRequest, ChunkLeaseResponse, ChunkReleaseRequest, ChunkResultsResponse,
    ChunkResultsSubmission, HeartbeatRequest, HeartbeatResponse, WorkerControlEvent,
    WorkerRegisterRequest, WorkerRegisterResponse, WorkerSignaturesResponse,
};
use futures_util::StreamExt;
use reqwest::Client;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone)]
pub struct WorkerApiClient {
    base_url: String,
    token: Option<String>,
    http: Client,
}

impl WorkerApiClient {
    pub fn new(base_url: impl Into<String>, token: Option<String>) -> Result<Self> {
        let http = Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build reqwest rustls client")?;

        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token,
            http,
        })
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(tok) => req.bearer_auth(tok),
            None => req,
        }
    }

    pub async fn register(
        &self,
        payload: &WorkerRegisterRequest,
    ) -> Result<WorkerRegisterResponse> {
        let url = format!("{}/internal/v1/worker/register", self.base_url);
        let resp = self
            .apply_auth(self.http.post(url).json(payload))
            .send()
            .await
            .context("worker register request failed")?
            .error_for_status()
            .context("worker register returned error status")?;
        resp.json().await.context("invalid register response JSON")
    }

    pub async fn fetch_signatures(&self) -> Result<WorkerSignaturesResponse> {
        let url = format!("{}/internal/v1/worker/signatures", self.base_url);
        let resp = self
            .apply_auth(self.http.get(url))
            .send()
            .await
            .context("worker signatures request failed")?
            .error_for_status()
            .context("worker signatures returned error status")?;
        resp.json()
            .await
            .context("invalid signatures response JSON")
    }

    pub async fn lease_chunk(
        &self,
        payload: &ChunkLeaseRequest,
    ) -> Result<Option<ChunkLeaseResponse>> {
        let url = format!("{}/internal/v1/worker/chunks/lease", self.base_url);
        let resp = self
            .apply_auth(self.http.post(url).json(payload))
            .send()
            .await
            .context("chunk lease request failed")?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        let resp = resp
            .error_for_status()
            .context("chunk lease returned error status")?;
        Ok(Some(
            resp.json().await.context("invalid lease response JSON")?,
        ))
    }

    pub async fn heartbeat(
        &self,
        chunk_id: Uuid,
        payload: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse> {
        let url = format!(
            "{}/internal/v1/worker/chunks/{chunk_id}/heartbeat",
            self.base_url
        );
        let resp = self
            .apply_auth(self.http.post(url).json(payload))
            .send()
            .await
            .context("heartbeat request failed")?
            .error_for_status()
            .context("heartbeat returned error status")?;
        resp.json().await.context("invalid heartbeat response JSON")
    }

    pub async fn submit_results(
        &self,
        chunk_id: Uuid,
        payload: &ChunkResultsSubmission,
    ) -> Result<ChunkResultsResponse> {
        let url = format!(
            "{}/internal/v1/worker/chunks/{chunk_id}/results",
            self.base_url
        );
        let resp = self
            .apply_auth(self.http.post(url).json(payload))
            .send()
            .await
            .context("submit results request failed")?
            .error_for_status()
            .context("submit results returned error status")?;
        resp.json().await.context("invalid results response JSON")
    }

    pub async fn release_chunk(&self, chunk_id: Uuid, payload: &ChunkReleaseRequest) -> Result<()> {
        let url = format!(
            "{}/internal/v1/worker/chunks/{chunk_id}/release",
            self.base_url
        );
        self.apply_auth(self.http.post(url).json(payload))
            .send()
            .await
            .context("release chunk request failed")?
            .error_for_status()
            .context("release chunk returned error status")?;
        Ok(())
    }

    /// Streams immediate Hard Kill Switch directives over /internal/v1/worker/control/stream.
    pub async fn stream_control_events(
        &self,
        tx: mpsc::Sender<WorkerControlEvent>,
        shutdown: CancellationToken,
    ) {
        let url = format!("{}/internal/v1/worker/control/stream", self.base_url);
        let stream_client = Client::builder().use_rustls_tls().build().ok();
        let Some(stream_client) = stream_client else {
            return;
        };

        while !shutdown.is_cancelled() {
            let req = self.apply_auth(stream_client.get(&url));
            let resp = tokio::select! {
                () = shutdown.cancelled() => break,
                res = req.send() => res,
            };

            let Ok(resp) = resp.and_then(|r| r.error_for_status()) else {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(3)) => {}
                }
                continue;
            };

            let mut bytes_stream = resp.bytes_stream();
            let mut buffer = String::new();

            loop {
                let next_chunk = tokio::select! {
                    () = shutdown.cancelled() => break,
                    item = bytes_stream.next() => item,
                };
                let Some(Ok(bytes)) = next_chunk else {
                    break;
                };
                buffer.push_str(&String::from_utf8_lossy(&bytes));
                while let Some(pos) = buffer.find('\n') {
                    let line = buffer[..pos].trim().to_string();
                    buffer.drain(..=pos);
                    if let Some(json_str) = line.strip_prefix("data:") {
                        if let Ok(event) =
                            serde_json::from_str::<WorkerControlEvent>(json_str.trim())
                        {
                            let _ = tx.send(event).await;
                        }
                    }
                }
            }
        }
    }
}
