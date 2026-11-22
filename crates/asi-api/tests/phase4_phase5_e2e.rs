#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asi_api::app::{build_router, AppState};
use asi_api::config::ApiConfig;
use asi_api::diff_engine::evaluator::{
    evaluate_host_diff, CurrentHostObservation, CurrentPortObservation, PreviousHostState,
    PreviousPortState, WebSnapshot,
};
use asi_api::diff_engine::instability::{
    assess_instability, compute_open_ports_hash, AvailabilitySample,
};
use asi_api::notifications::sinks::{build_sink, hmac_sha256_hex};
use asi_common::auth::AuthUser;
use asi_common::diff::{BulletItem, DiffEventKind, DiffOp, DiffSeverity, TimeSlot};
use asi_common::inventory::{HostStatus, PortState};
use asi_common::notification::{NotificationChannelType, NotificationMessage};
use asi_common::rbac::Role;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use chrono::Utc;
use http_body_util::BodyExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct CapturedRequest {
    endpoint: String,
    headers: BTreeMap<String, String>,
    body: String,
}

#[tokio::test]
async fn notification_sinks_deliver_hmac_webhook_slack_teams_mattermost_and_smtp() {
    let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let state_cap = Arc::clone(&captured);

    let receiver = Router::new()
        .route(
            "/:endpoint",
            post(
                |Path(endpoint): Path<String>,
                 State(store): State<Arc<Mutex<Vec<CapturedRequest>>>>,
                 headers: HeaderMap,
                 body: String| async move {
                    let mut hdrs = BTreeMap::new();
                    for (k, v) in &headers {
                        if let Ok(vs) = v.to_str() {
                            hdrs.insert(k.as_str().to_ascii_lowercase(), vs.to_string());
                        }
                    }
                    store.lock().unwrap().push(CapturedRequest {
                        endpoint,
                        headers: hdrs,
                        body,
                    });
                    StatusCode::OK
                },
            ),
        )
        .with_state(state_cap);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let http_srv = tokio::spawn(async move {
        let _ = axum::serve(listener, receiver).await;
    });

    let msg = NotificationMessage {
        delivery_id: Uuid::new_v4(),
        diff_event_id: Uuid::new_v4(),
        asset_group_name: "AGH Lab".to_string(),
        host_id: Uuid::new_v4(),
        ip_addr: "172.28.0.10".parse().unwrap(),
        event_kind: DiffEventKind::ConfirmedChange,
        severity: DiffSeverity::High,
        bullet_items: vec![BulletItem {
            op: DiffOp::Added,
            key: "admin_panel_detected".to_string(),
            params: serde_json::json!({
                "port": 443,
                "vhost": "app1.lab.local",
                "path": "/admin"
            }),
        }],
        detected_at: Utc::now(),
    };

    let webhook_secret = "super-hmac-secret";
    let webhook = build_sink(
        NotificationChannelType::WebhookJson,
        &serde_json::json!({ "url": format!("http://127.0.0.1:{http_port}/webhook") }),
        Some(webhook_secret),
    )
    .unwrap();
    webhook.send(&msg).await.unwrap();

    let slack = build_sink(
        NotificationChannelType::Slack,
        &serde_json::json!({ "url": format!("http://127.0.0.1:{http_port}/slack") }),
        None,
    )
    .unwrap();
    slack.send(&msg).await.unwrap();

    let teams = build_sink(
        NotificationChannelType::Teams,
        &serde_json::json!({ "url": format!("http://127.0.0.1:{http_port}/teams") }),
        None,
    )
    .unwrap();
    teams.send(&msg).await.unwrap();

    let mattermost = build_sink(
        NotificationChannelType::Mattermost,
        &serde_json::json!({ "url": format!("http://127.0.0.1:{http_port}/mattermost") }),
        None,
    )
    .unwrap();
    mattermost.send(&msg).await.unwrap();

    http_srv.abort();

    let reqs = captured.lock().unwrap().clone();
    assert_eq!(reqs.len(), 4);

    let wh = reqs.iter().find(|r| r.endpoint == "webhook").unwrap();
    assert_eq!(
        wh.headers.get("x-asi-event").map(String::as_str),
        Some("diff.detected")
    );
    assert_eq!(
        wh.headers.get("x-asi-delivery-id").map(String::as_str),
        Some(msg.delivery_id.to_string().as_str())
    );
    let ts = msg.detected_at.timestamp().to_string();
    assert_eq!(
        wh.headers.get("x-asi-timestamp").map(String::as_str),
        Some(ts.as_str())
    );
    let expected_sig = format!(
        "sha256={}",
        hmac_sha256_hex(
            webhook_secret.as_bytes(),
            format!("{ts}.{}", wh.body).as_bytes()
        )
    );
    assert_eq!(
        wh.headers.get("x-asi-signature-256").map(String::as_str),
        Some(expected_sig.as_str())
    );

    let slack_json: serde_json::Value =
        serde_json::from_str(&reqs.iter().find(|r| r.endpoint == "slack").unwrap().body).unwrap();
    assert!(slack_json.get("blocks").is_some());

    let teams_json: serde_json::Value =
        serde_json::from_str(&reqs.iter().find(|r| r.endpoint == "teams").unwrap().body).unwrap();
    assert_eq!(teams_json["@type"], "MessageCard");
    assert_eq!(teams_json["themeColor"], "D92D20");

    let mm_json: serde_json::Value = serde_json::from_str(
        &reqs
            .iter()
            .find(|r| r.endpoint == "mattermost")
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(mm_json["username"], "ASI");

    // Local mock SMTP session check
    let smtp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtp_port = smtp_listener.local_addr().unwrap().port();
    let smtp_transcript = Arc::new(Mutex::new(Vec::<String>::new()));
    let smtp_cap = Arc::clone(&smtp_transcript);

    let smtp_srv = tokio::spawn(async move {
        let Ok((mut stream, _)) = smtp_listener.accept().await else {
            return;
        };
        let (rh, mut wh) = stream.split();
        let mut reader = BufReader::new(rh);
        let _ = wh.write_all(b"220 mock-smtp.local ESMTP\r\n").await;
        let mut in_data = false;
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
            smtp_cap.lock().unwrap().push(trimmed.clone());
            if in_data {
                if trimmed == "." {
                    in_data = false;
                    let _ = wh.write_all(b"250 2.0.0 Ok: queued\r\n").await;
                }
            } else if trimmed.starts_with("EHLO ") {
                let _ = wh
                    .write_all(b"250-mock-smtp.local\r\n250 AUTH PLAIN\r\n")
                    .await;
            } else if trimmed.starts_with("AUTH PLAIN ") {
                let _ = wh
                    .write_all(b"235 2.7.0 Authentication successful\r\n")
                    .await;
            } else if trimmed.starts_with("MAIL FROM:") || trimmed.starts_with("RCPT TO:") {
                let _ = wh.write_all(b"250 2.1.0 Ok\r\n").await;
            } else if trimmed == "DATA" {
                in_data = true;
                let _ = wh
                    .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .await;
            } else if trimmed == "QUIT" {
                let _ = wh.write_all(b"221 2.0.0 Bye\r\n").await;
                break;
            }
            line.clear();
        }
    });

    let smtp = build_sink(
        NotificationChannelType::Smtp,
        &serde_json::json!({
            "host": "127.0.0.1",
            "port": smtp_port,
            "username": "asi-mailer",
            "from": "asi@agh.local",
            "to": "soc@agh.local"
        }),
        Some("smtp-pass"),
    )
    .unwrap();
    smtp.send(&msg).await.unwrap();
    let _ = smtp_srv.await;

    let transcript = smtp_transcript.lock().unwrap();
    assert!(transcript.iter().any(|l| l.starts_with("AUTH PLAIN ")));
    assert!(transcript.iter().any(|l| l == "MAIL FROM:<asi@agh.local>"));
    assert!(transcript.iter().any(|l| l == "RCPT TO:<soc@agh.local>"));
    assert!(transcript.iter().any(|l| l.contains("Subject: [ASI]")));
}

#[tokio::test]
async fn sse_stream_replays_missed_events_via_last_event_id_and_enforces_auth() {
    let config = ApiConfig::from_env().unwrap();
    let state = AppState::from_config(None, &config).unwrap();
    let app = build_router(state.clone(), "http://localhost:5173");

    let unauth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events/stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    let viewer = AuthUser {
        id: Uuid::new_v4(),
        username: "viewer".to_string(),
        email: "viewer@agh.local".to_string(),
        role: Role::ReadOnly,
        preferred_locale: "pl".to_string(),
        permissions: Role::ReadOnly.permissions().to_vec(),
    };
    let token = state.jwt.issue_access_token(&viewer).unwrap();

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let id3 = Uuid::new_v4();
    state
        .events
        .emit_ui("scan.progress", id1, serde_json::json!({ "seq": 1 }));
    state
        .events
        .emit_ui("diff.detected", id2, serde_json::json!({ "seq": 2 }));
    state
        .events
        .emit_ui("host.anomaly", id3, serde_json::json!({ "seq": 3 }));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/events/stream")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("Last-Event-ID", id1.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let id1_str = id1.to_string();
    let id2_str = id2.to_string();
    let id3_str = id3.to_string();

    let mut body = resp.into_body();
    let mut text = String::new();
    let read_res = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(chunk) = frame.into_data() {
                text.push_str(&String::from_utf8_lossy(&chunk));
                if text.contains(&id2_str) && text.contains(&id3_str) {
                    break;
                }
            }
        }
    })
    .await;

    assert!(read_res.is_ok(), "timed out reading replayed SSE events");
    assert!(!text.contains(&id1_str));
    let pos2 = text.find(&id2_str).unwrap();
    let pos3 = text.find(&id3_str).unwrap();
    assert!(pos2 < pos3);
}

#[test]
fn diurnal_flapping_host_suppresses_confirmed_noise_but_alerts_on_admin_panel() {
    let up_hash = compute_open_ports_hash(true, &[(80, "tcp")]);
    let mut samples: Vec<AvailabilitySample> = Vec::new();
    let mut prev = PreviousHostState {
        exists: false,
        status: HostStatus::MissingPending,
        consecutive_misses: 0,
        is_unstable: false,
        is_probable_tarpit: false,
        last_seen_at_present: false,
        ports: BTreeMap::new(),
    };

    let cycle = [
        (TimeSlot::Slot0612, true),
        (TimeSlot::Slot1218, true),
        (TimeSlot::Slot1824, false),
        (TimeSlot::Slot0006, false),
    ];

    let mut seen_variance_events = 0_usize;
    let mut confirmed_after_unstable = 0_usize;

    for run_idx in 0..12_usize {
        let (slot, is_alive) = cycle[run_idx % cycle.len()];
        let is_initial = run_idx == 0;

        let mut open_ports = BTreeMap::new();
        if is_alive {
            let mut webs = BTreeMap::new();
            webs.insert(
                ("mock-flapping.lab.local".to_string(), "http".to_string()),
                WebSnapshot {
                    http_status: Some(200),
                    redirect_target: None,
                    title: Some("Daytime Service".to_string()),
                    headers_filtered: BTreeMap::new(),
                    cookies_meta: BTreeMap::new(),
                    favicon_mmh3: Some(777),
                    matched_technologies: BTreeSet::from(["Nginx".to_string()]),
                    detected_paths: BTreeSet::new(),
                },
            );
            open_ports.insert(
                (80, "tcp".to_string()),
                CurrentPortObservation {
                    service_name: Some("http".to_string()),
                    product: Some("nginx".to_string()),
                    version: None,
                    tunnel: None,
                    tls: None,
                    webs,
                },
            );
        }

        let curr = CurrentHostObservation {
            is_alive,
            is_probable_tarpit: false,
            open_ports,
        };

        samples.push(AvailabilitySample {
            time_slot: slot,
            is_alive,
            open_ports_hash: if is_alive {
                up_hash.clone()
            } else {
                "down".to_string()
            },
        });

        let instability = assess_instability(prev.is_unstable, &samples);
        let eval = evaluate_host_diff(&prev, &curr, &instability, 3, is_initial);

        for diff in &eval.diffs {
            match diff.event_kind {
                DiffEventKind::ActiveVariance => seen_variance_events += 1,
                DiffEventKind::ConfirmedChange if instability.is_unstable => {
                    confirmed_after_unstable += 1;
                }
                DiffEventKind::ConfirmedChange => {}
            }
        }

        prev.exists = true;
        prev.status = eval.next_host_status;
        prev.consecutive_misses = eval.next_host_misses;
        prev.is_unstable = instability.is_unstable;
        if is_alive {
            prev.last_seen_at_present = true;
            if let Some(cp) = curr.open_ports.get(&(80, "tcp".to_string())) {
                prev.ports.insert(
                    (80, "tcp".to_string()),
                    PreviousPortState {
                        state: PortState::Active,
                        consecutive_misses: 0,
                        service_name: cp.service_name.clone(),
                        product: cp.product.clone(),
                        version: cp.version.clone(),
                        tunnel: cp.tunnel.clone(),
                        tls: None,
                        webs: cp.webs.clone(),
                    },
                );
            }
        }
        for tr in eval.missing_port_transitions {
            if let Some(pp) = prev.ports.get_mut(&(tr.port, tr.protocol)) {
                pp.state = tr.next_state;
                pp.consecutive_misses = tr.next_misses;
            }
        }
    }

    let final_instability = assess_instability(prev.is_unstable, &samples);
    assert!(final_instability.is_unstable);
    assert_eq!(final_instability.availability_profile["06_12"]["up"], 3);
    assert_eq!(final_instability.availability_profile["12_18"]["up"], 3);
    assert_eq!(final_instability.availability_profile["18_24"]["up"], 0);
    assert_eq!(final_instability.availability_profile["00_06"]["up"], 0);
    assert!(seen_variance_events >= 2);
    assert_eq!(confirmed_after_unstable, 0);

    // Real exposure change (/admin appears) MUST still trigger High ConfirmedChange
    samples.push(AvailabilitySample {
        time_slot: TimeSlot::Slot1218,
        is_alive: true,
        open_ports_hash: up_hash,
    });
    let instability_with_admin = assess_instability(prev.is_unstable, &samples);
    let mut admin_webs = BTreeMap::new();
    admin_webs.insert(
        ("mock-flapping.lab.local".to_string(), "http".to_string()),
        WebSnapshot {
            http_status: Some(200),
            redirect_target: None,
            title: Some("Daytime Service".to_string()),
            headers_filtered: BTreeMap::new(),
            cookies_meta: BTreeMap::new(),
            favicon_mmh3: Some(777),
            matched_technologies: BTreeSet::from(["Nginx".to_string()]),
            detected_paths: BTreeSet::from(["/admin".to_string()]),
        },
    );
    let mut admin_ports = BTreeMap::new();
    admin_ports.insert(
        (80, "tcp".to_string()),
        CurrentPortObservation {
            service_name: Some("http".to_string()),
            product: Some("nginx".to_string()),
            version: None,
            tunnel: None,
            tls: None,
            webs: admin_webs,
        },
    );
    let curr_admin = CurrentHostObservation {
        is_alive: true,
        is_probable_tarpit: false,
        open_ports: admin_ports,
    };

    let admin_eval = evaluate_host_diff(&prev, &curr_admin, &instability_with_admin, 3, false);
    assert_eq!(admin_eval.diffs.len(), 1);
    assert_eq!(
        admin_eval.diffs[0].event_kind,
        DiffEventKind::ConfirmedChange
    );
    assert_eq!(admin_eval.diffs[0].severity, DiffSeverity::High);
    assert!(admin_eval.diffs[0]
        .bullet_items
        .iter()
        .any(|b| b.key == "admin_panel_detected"));
}
