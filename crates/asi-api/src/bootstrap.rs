use anyhow::{anyhow, Context, Result};
use asi_common::rbac::Role;
use asi_common::validation::{validate_email, validate_password_strength, validate_username};
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::{insert_audit_log, AuditRecord};
use crate::config::ApiConfig;
use crate::security::password::hash_password;

pub async fn bootstrap_initial_admin(pool: &PgPool, config: &ApiConfig) -> Result<()> {
    let existing_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .context("failed to count existing users during admin bootstrap")?;

    if existing_count > 0 {
        return Ok(());
    }

    let Some(password) = config.bootstrap_admin_password.as_deref() else {
        tracing::warn!(
            "no users exist in database and ASI_BOOTSTRAP_ADMIN_PASSWORD is not set; skipping initial admin creation"
        );
        return Ok(());
    };

    let username = validate_username(&config.bootstrap_admin_username)
        .map_err(|msg| anyhow!("invalid ASI_BOOTSTRAP_ADMIN_USERNAME: {msg}"))?;
    let email = validate_email(&config.bootstrap_admin_email)
        .map_err(|msg| anyhow!("invalid ASI_BOOTSTRAP_ADMIN_EMAIL: {msg}"))?;
    validate_password_strength(password)
        .map_err(|msg| anyhow!("invalid ASI_BOOTSTRAP_ADMIN_PASSWORD: {msg}"))?;

    let password_hash = hash_password(password)
        .map_err(|err| anyhow!("failed to hash bootstrap admin password: {err}"))?;

    let mut tx = pool
        .begin()
        .await
        .context("failed to start admin bootstrap transaction")?;

    let user_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users (username, email, password_hash, role, is_active, preferred_locale)
        VALUES ($1, $2, $3, $4, TRUE, 'pl')
        RETURNING id
        "#,
    )
    .bind(&username)
    .bind(&email)
    .bind(&password_hash)
    .bind(Role::Admin.as_db_str())
    .fetch_one(&mut *tx)
    .await
    .context("failed to insert bootstrap admin user")?;

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "system",
            actor_id: None,
            action: "user.bootstrapped_admin",
            resource_type: "user",
            resource_id: Some(user_id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "username": username,
                "email": email,
                "role": "Admin",
            })),
            source_ip: None,
            request_id: None,
        },
    )
    .await
    .context("failed to write bootstrap audit log")?;

    tx.commit()
        .await
        .context("failed to commit bootstrap admin transaction")?;

    tracing::info!(user_id = %user_id, username = %username, "created initial Admin user");
    Ok(())
}
