use ipnetwork::IpNetwork;
use sqlx::{Executor, Postgres};
use uuid::Uuid;

pub struct AuditRecord<'a> {
    pub actor_type: &'a str,
    pub actor_id: Option<Uuid>,
    pub action: &'a str,
    pub resource_type: &'a str,
    pub resource_id: Option<Uuid>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub source_ip: Option<IpNetwork>,
    pub request_id: Option<Uuid>,
}

pub async fn insert_audit_log<'e, E>(
    executor: E,
    record: AuditRecord<'_>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO audit_logs (
            actor_type,
            actor_id,
            action,
            resource_type,
            resource_id,
            before_state,
            after_state,
            source_ip,
            request_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(record.actor_type)
    .bind(record.actor_id)
    .bind(record.action)
    .bind(record.resource_type)
    .bind(record.resource_id)
    .bind(record.before_state)
    .bind(record.after_state)
    .bind(record.source_ip)
    .bind(record.request_id)
    .execute(executor)
    .await?;

    Ok(())
}
