use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use asi_common::worker::WorkerControlEvent;
use tokio::sync::broadcast;
use uuid::Uuid;

const UI_EVENT_HISTORY_CAPACITY: usize = 200;

#[derive(Debug, Clone)]
pub struct UiSseEnvelope {
    pub event_name: &'static str,
    pub id: Uuid,
    pub data: serde_json::Value,
}

#[derive(Clone)]
pub struct EventHub {
    ui_tx: broadcast::Sender<UiSseEnvelope>,
    worker_ctrl_tx: broadcast::Sender<WorkerControlEvent>,
    ui_history: Arc<Mutex<VecDeque<UiSseEnvelope>>>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    #[must_use]
    pub fn new() -> Self {
        let (ui_tx, _) = broadcast::channel(512);
        let (worker_ctrl_tx, _) = broadcast::channel(256);
        Self {
            ui_tx,
            worker_ctrl_tx,
            ui_history: Arc::new(Mutex::new(VecDeque::with_capacity(
                UI_EVENT_HISTORY_CAPACITY,
            ))),
        }
    }

    pub fn emit_ui(&self, event_name: &'static str, id: Uuid, data: serde_json::Value) {
        let envelope = UiSseEnvelope {
            event_name,
            id,
            data,
        };
        if let Ok(mut history) = self.ui_history.lock() {
            if history.len() >= UI_EVENT_HISTORY_CAPACITY {
                history.pop_front();
            }
            history.push_back(envelope.clone());
        }
        let _ = self.ui_tx.send(envelope);
    }

    #[must_use]
    pub fn replay_since(&self, last_event_id: Uuid) -> Vec<UiSseEnvelope> {
        let Ok(history) = self.ui_history.lock() else {
            return Vec::new();
        };
        if let Some(pos) = history.iter().position(|e| e.id == last_event_id) {
            history.iter().skip(pos + 1).cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn emit_worker_control(&self, event: WorkerControlEvent) {
        let _ = self.worker_ctrl_tx.send(event);
    }

    #[must_use]
    pub fn subscribe_ui(&self) -> broadcast::Receiver<UiSseEnvelope> {
        self.ui_tx.subscribe()
    }

    #[must_use]
    pub fn subscribe_worker_control(&self) -> broadcast::Receiver<WorkerControlEvent> {
        self.worker_ctrl_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replays_events_after_last_event_id() {
        let hub = EventHub::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        hub.emit_ui("scan.progress", id1, serde_json::json!({"n": 1}));
        hub.emit_ui("diff.detected", id2, serde_json::json!({"n": 2}));
        hub.emit_ui("host.anomaly", id3, serde_json::json!({"n": 3}));

        let replayed = hub.replay_since(id1);
        assert_eq!(replayed.len(), 2);
        assert_eq!(replayed[0].id, id2);
        assert_eq!(replayed[1].id, id3);
        assert!(hub.replay_since(Uuid::new_v4()).is_empty());
    }
}
