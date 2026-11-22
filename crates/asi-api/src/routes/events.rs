use std::collections::BTreeSet;
use std::convert::Infallible;
use std::time::Duration;

use asi_common::rbac::Permission;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;
use crate::security::auth_extractor::AuthenticatedUser;
use crate::sse::UiSseEnvelope;

fn envelope_to_sse(envelope: UiSseEnvelope) -> Option<Event> {
    let data = serde_json::to_string(&envelope.data).ok()?;
    Some(
        Event::default()
            .id(envelope.id.to_string())
            .event(envelope.event_name)
            .data(data),
    )
}

pub async fn ui_events_stream(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    auth.require(Permission::ViewInventoryAndDiffs, "/api/v1/events/stream")?;

    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| Uuid::parse_str(raw.trim()).ok());

    // Subscribe before inspecting replay buffer so events emitted concurrently are never missed.
    let rx = state.events.subscribe_ui();
    let replay_events = last_event_id
        .map(|id| state.events.replay_since(id))
        .unwrap_or_default();
    let replayed_ids: BTreeSet<Uuid> = replay_events.iter().map(|e| e.id).collect();

    let replay_stream =
        tokio_stream::iter(replay_events).filter_map(|env| envelope_to_sse(env).map(Ok));

    let live_stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(env) if !replayed_ids.contains(&env.id) => envelope_to_sse(env).map(Ok),
        _ => None,
    });

    Ok(Sse::new(replay_stream.chain(live_stream)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    ))
}
