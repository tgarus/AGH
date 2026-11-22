use asi_common::auth::{AuthUser, LoginRequest, LoginResponse};
use asi_common::error::{DomainError, ProblemDetails};
use asi_common::rbac::Role;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, Duration, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::routes::common::{
    extract_request_id, extract_source_ip, extract_user_agent, map_db_err, require_db,
};
use crate::security::auth_extractor::AuthenticatedUser;
use crate::security::jwt::ACCESS_TOKEN_TTL_SECONDS;
use crate::security::password::{verify_dummy_password, verify_password};
use crate::security::tokens::{generate_opaque_token, hash_token};

const REFRESH_COOKIE_NAME: &str = "asi_refresh_token";
const REFRESH_TTL_DAYS: i64 = 7;

#[derive(FromRow)]
struct UserAuthRow {
    id: Uuid,
    username: String,
    email: String,
    password_hash: String,
    role: String,
    is_active: bool,
    preferred_locale: String,
}

#[derive(FromRow)]
struct RefreshSessionRow {
    id: Uuid,
    user_id: Uuid,
    family_id: Uuid,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

fn build_refresh_cookie(raw_token: String, secure: bool) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME, raw_token))
        .path("/api/v1/auth")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::days(REFRESH_TTL_DAYS))
        .build()
}

fn clear_refresh_cookie(secure: bool) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME, ""))
        .path("/api/v1/auth")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::ZERO)
        .build()
}

fn build_auth_user(
    row: &UserAuthRow,
    instance: &str,
    request_id: Option<Uuid>,
) -> Result<AuthUser, AppError> {
    let role = Role::from_db_str(&row.role).ok_or_else(|| {
        AppError::new(
            DomainError::Internal(format!("unknown database role '{}'", row.role)),
            request_id,
            Some(instance.to_string()),
        )
    })?;

    Ok(AuthUser {
        id: row.id,
        username: row.username.clone(),
        email: row.email.clone(),
        role,
        preferred_locale: row.preferred_locale.clone(),
        permissions: role.permissions().to_vec(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "Auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Authenticated successfully; refresh token issued in HttpOnly cookie", body = LoginResponse),
        (status = 401, description = "Invalid credentials", body = ProblemDetails),
        (status = 429, description = "Too many failed login attempts", body = ProblemDetails)
    )
)]
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), AppError> {
    let instance = "/api/v1/auth/login";
    let request_id = extract_request_id(&headers);
    let source_ip = extract_source_ip(&headers);
    let user_agent = extract_user_agent(&headers);
    let pool = require_db(&state, request_id, instance)?;

    let username = payload.username.trim();
    if username.is_empty() || payload.password.is_empty() {
        return Err(AppError::new(
            DomainError::Unauthorized("Invalid username or password.".to_string()),
            request_id,
            Some(instance.to_string()),
        ));
    }

    let rate_key = format!(
        "{}:{username}",
        source_ip
            .map(|ip| ip.ip().to_string())
            .unwrap_or_else(|| "local".to_string())
    );
    state
        .login_limiter
        .check_and_record(&rate_key)
        .map_err(|err| AppError::new(err, request_id, Some(instance.to_string())))?;

    let maybe_user: Option<UserAuthRow> = sqlx::query_as(
        r#"
        SELECT id, username, email, password_hash, role, is_active, preferred_locale
        FROM users
        WHERE username = $1
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "user lookup conflict", request_id, instance))?;

    let Some(user_row) = maybe_user else {
        verify_dummy_password(&payload.password);
        return Err(AppError::new(
            DomainError::Unauthorized("Invalid username or password.".to_string()),
            request_id,
            Some(instance.to_string()),
        ));
    };

    if !verify_password(&payload.password, &user_row.password_hash) || !user_row.is_active {
        return Err(AppError::new(
            DomainError::Unauthorized("Invalid username or password.".to_string()),
            request_id,
            Some(instance.to_string()),
        ));
    }

    state.login_limiter.reset(&rate_key);
    let auth_user = build_auth_user(&user_row, instance, request_id)?;
    let access_token = state
        .jwt
        .issue_access_token(&auth_user)
        .map_err(|err| AppError::new(err, request_id, Some(instance.to_string())))?;

    let raw_refresh = generate_opaque_token("asir_");
    let refresh_hash = hash_token(&raw_refresh);
    let family_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::days(REFRESH_TTL_DAYS);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", request_id, instance))?;

    sqlx::query(
        r#"
        INSERT INTO refresh_sessions (user_id, family_id, token_hash, expires_at, created_ip, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(auth_user.id)
    .bind(family_id)
    .bind(&refresh_hash)
    .bind(expires_at)
    .bind(source_ip)
    .bind(user_agent)
    .execute(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "refresh session conflict", request_id, instance))?;

    sqlx::query("UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1")
        .bind(auth_user.id)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "user update conflict", request_id, instance))?;

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth_user.id),
            action: "auth.login",
            resource_type: "user",
            resource_id: Some(auth_user.id),
            before_state: None,
            after_state: Some(serde_json::json!({ "family_id": family_id })),
            source_ip,
            request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log error", request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit error", request_id, instance))?;

    let updated_jar = jar.add(build_refresh_cookie(raw_refresh, state.cookie_secure));
    Ok((
        updated_jar,
        Json(LoginResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in_seconds: ACCESS_TOKEN_TTL_SECONDS,
            user: auth_user,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "Auth",
    responses(
        (status = 200, description = "Rotated refresh token cookie and issued fresh JWT access token", body = LoginResponse),
        (status = 401, description = "Missing, expired, or reused refresh token", body = ProblemDetails)
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, Json<LoginResponse>), AppError> {
    let instance = "/api/v1/auth/refresh";
    let request_id = extract_request_id(&headers);
    let source_ip = extract_source_ip(&headers);
    let user_agent = extract_user_agent(&headers);
    let pool = require_db(&state, request_id, instance)?;

    let raw_token = jar
        .get(REFRESH_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            AppError::new(
                DomainError::Unauthorized("Missing refresh token cookie.".to_string()),
                request_id,
                Some(instance.to_string()),
            )
        })?;

    let token_hash = hash_token(&raw_token);
    let session: Option<RefreshSessionRow> = sqlx::query_as(
        r#"
        SELECT id, user_id, family_id, expires_at, revoked_at
        FROM refresh_sessions
        WHERE token_hash = $1
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "refresh session lookup error", request_id, instance))?;

    let Some(session) = session else {
        return Err(AppError::new(
            DomainError::Unauthorized("Invalid refresh token.".to_string()),
            request_id,
            Some(instance.to_string()),
        ));
    };

    if session.revoked_at.is_some() {
        // Refresh token reuse detection: immediately revoke the entire token family.
        let _ = sqlx::query(
            "UPDATE refresh_sessions SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL",
        )
        .bind(session.family_id)
        .execute(pool)
        .await;

        let _ = insert_audit_log(
            pool,
            AuditRecord {
                actor_type: "user",
                actor_id: Some(session.user_id),
                action: "auth.refresh_token_reuse_detected",
                resource_type: "refresh_session",
                resource_id: Some(session.id),
                before_state: None,
                after_state: Some(serde_json::json!({ "family_id": session.family_id })),
                source_ip,
                request_id,
            },
        )
        .await;

        return Err(AppError::new(
            DomainError::Unauthorized(
                "Refresh token reuse detected. Session family revoked.".to_string(),
            ),
            request_id,
            Some(instance.to_string()),
        ));
    }

    if session.expires_at <= Utc::now() {
        return Err(AppError::new(
            DomainError::Unauthorized("Refresh token has expired.".to_string()),
            request_id,
            Some(instance.to_string()),
        ));
    }

    let user_row: Option<UserAuthRow> = sqlx::query_as(
        r#"
        SELECT id, username, email, password_hash, role, is_active, preferred_locale
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(session.user_id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "user lookup error", request_id, instance))?;

    let Some(user_row) = user_row.filter(|u| u.is_active) else {
        return Err(AppError::new(
            DomainError::Unauthorized("User account is inactive or missing.".to_string()),
            request_id,
            Some(instance.to_string()),
        ));
    };

    let auth_user = build_auth_user(&user_row, instance, request_id)?;
    let access_token = state
        .jwt
        .issue_access_token(&auth_user)
        .map_err(|err| AppError::new(err, request_id, Some(instance.to_string())))?;

    let next_raw_refresh = generate_opaque_token("asir_");
    let next_hash = hash_token(&next_raw_refresh);
    let next_expires = Utc::now() + Duration::days(REFRESH_TTL_DAYS);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", request_id, instance))?;

    let next_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO refresh_sessions (user_id, family_id, token_hash, expires_at, created_ip, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
    )
    .bind(auth_user.id)
    .bind(session.family_id)
    .bind(&next_hash)
    .bind(next_expires)
    .bind(source_ip)
    .bind(user_agent)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "refresh rotation error", request_id, instance))?;

    let updated = sqlx::query(
        r#"
        UPDATE refresh_sessions
        SET revoked_at = NOW(), replaced_by_id = $1
        WHERE id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(next_id)
    .bind(session.id)
    .execute(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "refresh revocation error", request_id, instance))?;

    if updated.rows_affected() == 0 {
        return Err(AppError::new(
            DomainError::Unauthorized("Concurrent refresh detected.".to_string()),
            request_id,
            Some(instance.to_string()),
        ));
    }

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit error", request_id, instance))?;

    let updated_jar = jar.add(build_refresh_cookie(next_raw_refresh, state.cookie_secure));
    Ok((
        updated_jar,
        Json(LoginResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in_seconds: ACCESS_TOKEN_TTL_SECONDS,
            user: auth_user,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "Auth",
    responses(
        (status = 204, description = "Session revoked and refresh cookie cleared")
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AppError> {
    let instance = "/api/v1/auth/logout";
    let request_id = extract_request_id(&headers);
    let source_ip = extract_source_ip(&headers);

    if let (Some(pool), Some(cookie)) = (state.db.as_ref(), jar.get(REFRESH_COOKIE_NAME)) {
        if !cookie.value().is_empty() {
            let token_hash = hash_token(cookie.value());
            let revoked_user: Option<Uuid> = sqlx::query_scalar(
                r#"
                UPDATE refresh_sessions
                SET revoked_at = NOW()
                WHERE token_hash = $1 AND revoked_at IS NULL
                RETURNING user_id
                "#,
            )
            .bind(&token_hash)
            .fetch_optional(pool)
            .await
            .map_err(|err| map_db_err(err, "logout error", request_id, instance))?;

            if let Some(uid) = revoked_user {
                let _ = insert_audit_log(
                    pool,
                    AuditRecord {
                        actor_type: "user",
                        actor_id: Some(uid),
                        action: "auth.logout",
                        resource_type: "user",
                        resource_id: Some(uid),
                        before_state: None,
                        after_state: None,
                        source_ip,
                        request_id,
                    },
                )
                .await;
            }
        }
    }

    Ok((
        jar.add(clear_refresh_cookie(state.cookie_secure)),
        StatusCode::NO_CONTENT,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current authenticated user profile", body = AuthUser),
        (status = 401, description = "Unauthorized", body = ProblemDetails)
    )
)]
pub async fn me(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<AuthUser>, AppError> {
    let instance = "/api/v1/auth/me";
    let Some(pool) = state.db.as_ref() else {
        return Ok(Json(auth.user));
    };

    let row: Option<UserAuthRow> = sqlx::query_as(
        r#"
        SELECT id, username, email, password_hash, role, is_active, preferred_locale
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(auth.user.id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "user query failed", auth.request_id, instance))?;

    let Some(row) = row.filter(|u| u.is_active) else {
        return Err(AppError::new(
            DomainError::Unauthorized("Account is disabled or does not exist.".to_string()),
            auth.request_id,
            Some(instance.to_string()),
        ));
    };

    Ok(Json(build_auth_user(&row, instance, auth.request_id)?))
}
