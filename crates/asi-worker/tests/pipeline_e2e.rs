#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use asi_common::signatures::builtin_default_signatures_yaml;
use asi_common::worker::{
    ChunkLeaseResponse, ChunkTarget, DiscoveryTool, PolicySnapshot, WorkerCapabilities,
};
use asi_worker::guard::TargetGuard;
use asi_worker::pipeline::run_chunk_pipeline;
use asi_worker::pipeline::stage3::compile_templates;
use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

async fn spawn_mock_http_server<F>(handler: F) -> (u16, tokio::task::JoinHandle<()>)
where
    F: Fn(&str, &str, &str) -> (u16, Vec<(&'static str, &'static str)>, Vec<u8>)
        + Send
        + Sync
        + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handler = Arc::new(handler);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(4096);
                let mut tmp = [0_u8; 1024];
                loop {
                    match stream.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 8192 {
                                break;
                            }
                        }
                    }
                }
                if buf.is_empty() {
                    return;
                }

                let raw = String::from_utf8_lossy(&buf);
                let mut lines = raw.split("\r\n");
                let request_line = lines.next().unwrap_or("GET / HTTP/1.1");
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("GET");
                let path = parts.next().unwrap_or("/");
                let mut host_header = "";
                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("host") {
                            host_header = v.trim();
                        }
                    }
                }

                let (status, extra_headers, body) = h(method, path, host_header);
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Response",
                };
                let mut resp_head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (k, v) in extra_headers {
                    resp_head.push_str(&format!("{k}: {v}\r\n"));
                }
                resp_head.push_str("\r\n");

                let _ = stream.write_all(resp_head.as_bytes()).await;
                if !method.eq_ignore_ascii_case("HEAD") && !body.is_empty() {
                    let _ = stream.write_all(&body).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });

    (port, handle)
}

#[tokio::test]
async fn full_three_stage_pipeline_vhosts_fingerprinthub_and_secret_stripping() {
    let (port1, server1) = spawn_mock_http_server(|_method, path, _host| match path {
        "/" => (
            200,
            vec![
                ("Content-Type", "text/html"),
                ("Server", "nginx/1.27"),
                (
                    "Set-Cookie",
                    "ADMIN_SESSION=topsecret_cookie_val; Path=/; SameSite=Lax",
                ),
                ("Authorization", "Bearer supersecret_auth_val"),
                ("Proxy-Authorization", "Basic c2VjcmV0"),
                ("Cookie", "raw_req_cookie=secret"),
                ("X-Request-Id", "noise-999"),
            ],
            b"<html><head><title>Faculty Main</title></head><body>OK</body></html>".to_vec(),
        ),
        "/admin" => (
            200,
            vec![("Content-Type", "text/html")],
            b"<html><head><title>Admin Panel</title></head><body><h1>Administration</h1></body></html>"
                .to_vec(),
        ),
        "/favicon.ico" => (
            200,
            vec![("Content-Type", "image/x-icon")],
            b"ASI_MOCK_FAVICON_BYTES_V1".to_vec(),
        ),
        _ => (404, vec![], Vec::new()),
    })
    .await;

    let (port2, server2) = spawn_mock_http_server(|method, path, host| {
        if method.eq_ignore_ascii_case("HEAD") {
            return (200, vec![("Content-Type", "text/html")], Vec::new());
        }
        let host_lc = host.to_ascii_lowercase();
        if path == "/" && host_lc.starts_with("app1.lab.local") {
            (
                200,
                vec![("Content-Type", "text/html")],
                b"<html><head><title>App One</title></head><body>Portal 1</body></html>".to_vec(),
            )
        } else if path == "/" && host_lc.starts_with("app2.lab.local") {
            (
                200,
                vec![("Content-Type", "text/html")],
                b"<html><head><title>Staging Two</title></head><body><h1>Staging</h1></body></html>"
                    .to_vec(),
            )
        } else {
            (404, vec![], Vec::new())
        }
    })
    .await;

    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let lease = ChunkLeaseResponse {
        chunk_id: Uuid::new_v4(),
        scan_run_id: Uuid::new_v4(),
        attempt_no: 1,
        targets: vec![ChunkTarget {
            ip_addr: loopback,
            vhosts: vec!["app1.lab.local".to_string(), "app2.lab.local".to_string()],
        }],
        excluded_cidrs: Vec::new(),
        policy: PolicySnapshot {
            port_spec: format!("{port1},{port2}"),
            discovery_tool: DiscoveryTool::Naabu,
            rate_pps: 100,
            per_ip_cooldown_ms: 0,
            subnet_concurrency: 2,
            kill_grace_seconds: 1,
            inactivity_threshold: 3,
            tarpit_port_threshold: 200,
            enable_nuclei: false,
            force_sv_ips: Vec::new(),
        },
        lease_expires_at: Utc::now() + chrono::Duration::seconds(60),
    };

    let caps = WorkerCapabilities {
        naabu_version: None,
        masscan_version: None,
        nmap_version: None,
        nuclei_version: None,
        os_arch: "linux-x86_64".to_string(),
    };
    let compiled = compile_templates(&builtin_default_signatures_yaml());

    let submission = run_chunk_pipeline(
        Uuid::new_v4(),
        &lease,
        &caps,
        &compiled,
        true,
        CancellationToken::new(),
    )
    .await
    .unwrap();

    server1.abort();
    server2.abort();

    assert!(submission.stage1_ports.iter().any(|p| p.port == port1));
    assert!(submission.stage1_ports.iter().any(|p| p.port == port2));
    assert!(submission
        .stage2_services
        .iter()
        .any(|s| s.port == port1 && s.is_web_candidate));
    assert!(submission
        .stage2_services
        .iter()
        .any(|s| s.port == port2 && s.is_web_candidate));

    let obs1 = submission
        .stage3_observations
        .iter()
        .find(|o| o.port == port1)
        .unwrap();
    assert!(obs1.favicon_mmh3.is_some());
    assert!(obs1.detected_paths.contains(&"/admin".to_string()));
    assert!(obs1.matched_technologies.contains(&"Nginx".to_string()));
    assert!(obs1
        .matched_technologies
        .contains(&"Admin Panel".to_string()));

    let cookie = obs1
        .cookies_meta
        .iter()
        .find(|c| c.name == "ADMIN_SESSION")
        .unwrap();
    assert!(!cookie.http_only);
    assert!(!cookie.secure);
    assert_eq!(cookie.same_site.as_deref(), Some("lax"));

    assert_eq!(
        obs1.headers_filtered.get("server").map(String::as_str),
        Some("nginx/1.27")
    );
    assert!(!obs1.headers_filtered.contains_key("authorization"));
    assert!(!obs1.headers_filtered.contains_key("proxy-authorization"));
    assert!(!obs1.headers_filtered.contains_key("cookie"));
    assert!(!obs1.headers_filtered.contains_key("set-cookie"));
    assert!(!obs1.headers_filtered.contains_key("x-request-id"));

    let obs2_a1 = submission
        .stage3_observations
        .iter()
        .find(|o| o.port == port2 && o.vhost == "app1.lab.local")
        .unwrap();
    assert_eq!(obs2_a1.title.as_deref(), Some("App One"));

    let obs2_a2 = submission
        .stage3_observations
        .iter()
        .find(|o| o.port == port2 && o.vhost == "app2.lab.local")
        .unwrap();
    assert_eq!(obs2_a2.title.as_deref(), Some("Staging Two"));
    assert!(obs2_a2
        .matched_technologies
        .contains(&"Staging Environment".to_string()));

    let serialized = serde_json::to_string(&submission).unwrap();
    assert!(!serialized.contains("topsecret_cookie_val"));
    assert!(!serialized.contains("supersecret_auth_val"));
    assert!(!serialized.contains("raw_req_cookie"));
    assert!(!serialized.contains("noise-999"));
}

#[tokio::test]
async fn guard_enforces_exclusions_and_hard_kill_switch_cancels_promptly() {
    let guard = TargetGuard::new(&["172.28.0.12/30".to_string()], false);
    assert!(!guard.is_allowed("127.0.0.1".parse().unwrap()));
    assert!(!guard.is_allowed("172.28.0.13".parse().unwrap()));
    assert!(guard.is_allowed("172.28.0.10".parse().unwrap()));

    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let lease = ChunkLeaseResponse {
        chunk_id: Uuid::new_v4(),
        scan_run_id: Uuid::new_v4(),
        attempt_no: 1,
        targets: vec![ChunkTarget {
            ip_addr: loopback,
            vhosts: Vec::new(),
        }],
        excluded_cidrs: Vec::new(),
        policy: PolicySnapshot {
            port_spec: "80".to_string(),
            discovery_tool: DiscoveryTool::Naabu,
            rate_pps: 50,
            per_ip_cooldown_ms: 0,
            subnet_concurrency: 1,
            kill_grace_seconds: 1,
            inactivity_threshold: 3,
            tarpit_port_threshold: 200,
            enable_nuclei: false,
            force_sv_ips: Vec::new(),
        },
        lease_expires_at: Utc::now() + chrono::Duration::seconds(60),
    };
    let caps = WorkerCapabilities {
        naabu_version: None,
        masscan_version: None,
        nmap_version: None,
        nuclei_version: None,
        os_arch: "linux-x86_64".to_string(),
    };

    // With allow_local_mock_lab = false, TargetGuard blocks 127.0.0.1 completely
    let blocked_res = run_chunk_pipeline(
        Uuid::new_v4(),
        &lease,
        &caps,
        &[],
        false,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(blocked_res.stage1_ports.is_empty());
    assert!(blocked_res.stage3_observations.is_empty());

    // Pre-cancelled token triggers Hard Kill Switch promptly
    let cancel = CancellationToken::new();
    cancel.cancel();
    let started = Instant::now();
    let res = run_chunk_pipeline(Uuid::new_v4(), &lease, &caps, &[], true, cancel).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(res.is_err());
}
