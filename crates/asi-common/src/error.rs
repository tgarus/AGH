use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct FieldViolation {
    pub field: String,
    pub code: String,
    pub message: String,
}

/// RFC 9457 Problem Details payload returned on all 4xx/5xx API responses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    pub error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<FieldViolation>,
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("validation failed: {detail}")]
    Validation {
        detail: String,
        violations: Vec<FieldViolation>,
    },

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("too many requests: {0}")]
    TooManyRequests(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("not implemented: {0}")]
    NotImplemented(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl DomainError {
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Validation { .. } => 422,
            Self::BadRequest(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::TooManyRequests(_) => 429,
            Self::ServiceUnavailable(_) => 503,
            Self::NotImplemented(_) => 501,
            Self::Internal(_) => 500,
        }
    }

    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Validation { .. } => "VALIDATION_ERROR",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::TooManyRequests(_) => "TOO_MANY_REQUESTS",
            Self::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            Self::NotImplemented(_) => "NOT_IMPLEMENTED",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    #[must_use]
    pub fn title(&self) -> &'static str {
        match self {
            Self::Validation { .. } => "Validation Failed",
            Self::BadRequest(_) => "Bad Request",
            Self::Unauthorized(_) => "Unauthorized",
            Self::Forbidden(_) => "Forbidden",
            Self::NotFound(_) => "Resource Not Found",
            Self::Conflict(_) => "Conflict",
            Self::TooManyRequests(_) => "Too Many Requests",
            Self::ServiceUnavailable(_) => "Service Unavailable",
            Self::NotImplemented(_) => "Not Implemented",
            Self::Internal(_) => "Internal Server Error",
        }
    }

    #[must_use]
    pub fn problem_type(&self) -> &'static str {
        match self {
            Self::Validation { .. } => "https://asi.agh.edu.pl/errors/validation-failed",
            Self::BadRequest(_) => "https://asi.agh.edu.pl/errors/bad-request",
            Self::Unauthorized(_) => "https://asi.agh.edu.pl/errors/unauthorized",
            Self::Forbidden(_) => "https://asi.agh.edu.pl/errors/forbidden",
            Self::NotFound(_) => "https://asi.agh.edu.pl/errors/not-found",
            Self::Conflict(_) => "https://asi.agh.edu.pl/errors/conflict",
            Self::TooManyRequests(_) => "https://asi.agh.edu.pl/errors/too-many-requests",
            Self::ServiceUnavailable(_) => "https://asi.agh.edu.pl/errors/service-unavailable",
            Self::NotImplemented(_) => "https://asi.agh.edu.pl/errors/not-implemented",
            Self::Internal(_) => "https://asi.agh.edu.pl/errors/internal-error",
        }
    }

    #[must_use]
    pub fn to_problem_details(
        &self,
        instance: Option<String>,
        request_id: Option<Uuid>,
    ) -> ProblemDetails {
        let (detail, violations) = match self {
            Self::Validation { detail, violations } => (detail.clone(), violations.clone()),
            Self::Internal(_) => (
                "An unexpected internal error occurred.".to_string(),
                Vec::new(),
            ),
            Self::BadRequest(msg)
            | Self::Unauthorized(msg)
            | Self::Forbidden(msg)
            | Self::NotFound(msg)
            | Self::Conflict(msg)
            | Self::TooManyRequests(msg)
            | Self::ServiceUnavailable(msg)
            | Self::NotImplemented(msg) => (msg.clone(), Vec::new()),
        };

        ProblemDetails {
            problem_type: self.problem_type().to_string(),
            title: self.title().to_string(),
            status: self.status_code(),
            detail,
            instance,
            error_code: self.error_code().to_string(),
            request_id,
            violations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_details_sanitizes_internal_error() {
        let err = DomainError::Internal("db password leak detail".to_string());
        let problem = err.to_problem_details(Some("/api/v1/hosts".to_string()), None);

        assert_eq!(problem.status, 500);
        assert_eq!(problem.error_code, "INTERNAL_ERROR");
        assert_eq!(problem.detail, "An unexpected internal error occurred.");
        assert!(!problem.detail.contains("password"));
    }

    #[test]
    fn validation_error_preserves_violations() {
        let err = DomainError::Validation {
            detail: "Invalid target".to_string(),
            violations: vec![FieldViolation {
                field: "targets[0].value".to_string(),
                code: "INVALID_CIDR".to_string(),
                message: "Expected valid CIDR".to_string(),
            }],
        };
        let req_id = Uuid::new_v4();
        let problem =
            err.to_problem_details(Some("/api/v1/asset-groups".to_string()), Some(req_id));

        assert_eq!(problem.status, 422);
        assert_eq!(problem.error_code, "VALIDATION_ERROR");
        assert_eq!(problem.request_id, Some(req_id));
        assert_eq!(problem.violations.len(), 1);
    }
}
