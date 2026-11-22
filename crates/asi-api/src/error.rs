use asi_common::error::DomainError;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use uuid::Uuid;

#[derive(Debug)]
pub struct AppError {
    pub domain: DomainError,
    pub request_id: Option<Uuid>,
    pub instance: Option<String>,
}

impl AppError {
    #[must_use]
    pub fn new(domain: DomainError, request_id: Option<Uuid>, instance: Option<String>) -> Self {
        Self {
            domain,
            request_id,
            instance,
        }
    }
}

impl From<DomainError> for AppError {
    fn from(domain: DomainError) -> Self {
        Self {
            domain,
            request_id: None,
            instance: None,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match &self.domain {
            DomainError::Internal(msg) => {
                tracing::error!(
                    request_id = ?self.request_id,
                    instance = ?self.instance,
                    error = %msg,
                    "internal server error"
                );
            }
            other => {
                tracing::warn!(
                    request_id = ?self.request_id,
                    instance = ?self.instance,
                    error_code = other.error_code(),
                    error = %other,
                    "request failed"
                );
            }
        }

        let status = StatusCode::from_u16(self.domain.status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let problem = self
            .domain
            .to_problem_details(self.instance, self.request_id);

        let mut response = (status, Json(problem)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}
