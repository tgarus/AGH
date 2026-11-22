use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use asi_common::diff::is_ignored_http_header;
use asi_common::signatures::{
    parse_fingerprinthub_v4_yaml, ConditionOp, FingerprintTemplate, MatcherPart, MatcherType,
    TemplateMatcher,
};
use asi_common::worker::{
    ChunkTarget, PolicySnapshot, Stage2ServiceFinding, Stage3WebObservation, WebCookieMeta,
    WorkerCapabilities,
};
use regex::Regex;
use reqwest::redirect::Policy;
use reqwest::Client;
use tokio_util::sync::CancellationToken;

use crate::pipeline::favicon::mmh3_favicon_hash;
use crate::pipeline::stage2::collect_vhosts;
use crate::process::run_cancellable_command;

const PASSIVE_PROBE_PATHS: &[&str] = &["/admin", "/login", "/version"];

#[derive(Debug, Clone)]
pub struct CompiledTemplate {
    pub template: FingerprintTemplate,
    pub regex_cache: HashMap<String, Regex>,
}

#[must_use]
pub fn compile_templates(yaml_rules: &[String]) -> Vec<CompiledTemplate> {
    let mut compiled = Vec::new();
    for raw in yaml_rules {
        let Ok(template) = parse_fingerprinthub_v4_yaml(raw) else {
            continue;
        };
        let mut regex_cache = HashMap::new();
        for probe in &template.http {
            for matcher in &probe.matchers {
                for pat in &matcher.regex {
                    if !regex_cache.contains_key(pat) {
                        if let Ok(re) = Regex::new(pat) {
                            regex_cache.insert(pat.clone(), re);
                        }
                    }
                }
            }
        }
        compiled.push(CompiledTemplate {
            template,
            regex_cache,
        });
    }
    compiled
}

#[derive(Debug, Clone)]
pub struct HttpProbeSnapshot {
    pub path: String,
    pub status: u16,
    pub headers_raw: String,
    pub title: Option<String>,
    pub body: String,
    pub favicon_mmh3: Option<i64>,
}

#[must_use]
pub fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start_tag = lower.find("<title")?;
    let after_open = lower[start_tag..].find('>')? + start_tag + 1;
    let end_tag = lower[after_open..].find("</title>")? + after_open;
    let raw = body.get(after_open..end_tag)?.trim();
    if raw.is_empty() {
        None
    } else {
        Some(raw.chars().take(256).collect())
    }
}

/// Extracts strictly cookie name and security flags, discarding session values.
#[must_use]
pub fn parse_set_cookie_meta(header_value: &str) -> Option<WebCookieMeta> {
    let mut parts = header_value.split(';');
    let name_val = parts.next()?.trim();
    let name = name_val.split('=').next()?.trim();
    if name.is_empty() {
        return None;
    }

    let mut http_only = false;
    let mut secure = false;
    let mut same_site = None;

    for attr in parts {
        let trimmed = attr.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower == "httponly" {
            http_only = true;
        } else if lower == "secure" {
            secure = true;
        } else if let Some(val) = lower.strip_prefix("samesite=") {
            same_site = Some(val.trim().to_string());
        }
    }

    Some(WebCookieMeta {
        name: name.to_string(),
        http_only,
        secure,
        same_site,
    })
}

fn eval_single_matcher(
    matcher: &TemplateMatcher,
    snap: &HttpProbeSnapshot,
    regex_cache: &HashMap<String, Regex>,
) -> bool {
    let haystack = match matcher.part {
        MatcherPart::Body => snap.body.as_str(),
        MatcherPart::Header => snap.headers_raw.as_str(),
        MatcherPart::Title => snap.title.as_deref().unwrap_or(""),
        MatcherPart::All => "",
    };

    let combined_all;
    let target_text = if matcher.part == MatcherPart::All {
        combined_all = format!(
            "{}\n{}\n{}",
            snap.headers_raw,
            snap.title.as_deref().unwrap_or(""),
            snap.body
        );
        combined_all.as_str()
    } else {
        haystack
    };

    let matched = match matcher.matcher_type {
        MatcherType::Status => matcher.status.contains(&snap.status),
        MatcherType::Word => {
            if matcher.words.is_empty() {
                false
            } else if matcher.condition == ConditionOp::And {
                matcher.words.iter().all(|w| target_text.contains(w))
            } else {
                matcher.words.iter().any(|w| target_text.contains(w))
            }
        }
        MatcherType::Regex => {
            if matcher.regex.is_empty() {
                false
            } else if matcher.condition == ConditionOp::And {
                matcher.regex.iter().all(|p| {
                    regex_cache
                        .get(p)
                        .is_some_and(|re| re.is_match(target_text))
                })
            } else {
                matcher.regex.iter().any(|p| {
                    regex_cache
                        .get(p)
                        .is_some_and(|re| re.is_match(target_text))
                })
            }
        }
        MatcherType::Favicon => snap.favicon_mmh3.is_some_and(|h| {
            matcher
                .hash
                .iter()
                .any(|expected| expected.trim() == h.to_string())
        }),
    };

    if matcher.negative {
        !matched
    } else {
        matched
    }
}

#[must_use]
pub fn evaluate_compiled_template(
    compiled: &CompiledTemplate,
    snapshots: &[HttpProbeSnapshot],
) -> bool {
    for probe in &compiled.template.http {
        for snap in snapshots {
            if !probe.path.is_empty() {
                let path_matches = probe.path.iter().any(|p| {
                    let clean = p.replace("{{BaseURL}}", "");
                    clean == snap.path || (clean.is_empty() && snap.path == "/")
                });
                if !path_matches {
                    continue;
                }
            }

            if probe.matchers.is_empty() {
                continue;
            }
            let ok = match probe.matchers_condition {
                ConditionOp::And => probe
                    .matchers
                    .iter()
                    .all(|m| eval_single_matcher(m, snap, &compiled.regex_cache)),
                ConditionOp::Or => probe
                    .matchers
                    .iter()
                    .any(|m| eval_single_matcher(m, snap, &compiled.regex_cache)),
            };
            if ok {
                return true;
            }
        }
    }
    false
}

pub async fn run_stage3(
    targets: &[ChunkTarget],
    stage2_services: &[Stage2ServiceFinding],
    compiled_templates: &[CompiledTemplate],
    policy: &PolicySnapshot,
    caps: &WorkerCapabilities,
    cancel: CancellationToken,
) -> Vec<Stage3WebObservation> {
    let mut user_vhosts_map: HashMap<IpAddr, Vec<String>> = HashMap::new();
    for t in targets {
        user_vhosts_map.insert(t.ip_addr, t.vhosts.clone());
    }

    let mut observations = Vec::new();

    for svc in stage2_services {
        if cancel.is_cancelled() {
            break;
        }
        if !svc.is_web_candidate {
            continue;
        }

        let scheme = if svc.tunnel.as_deref() == Some("ssl")
            || svc.service_name.as_deref() == Some("https")
        {
            "https"
        } else {
            "http"
        };

        let user_vhosts = user_vhosts_map
            .get(&svc.ip_addr)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let vhosts = collect_vhosts(
            svc.ip_addr,
            user_vhosts,
            &svc.rdns_hostnames,
            &svc.tls_san_dns,
        );

        for vhost in vhosts {
            if cancel.is_cancelled() {
                break;
            }
            if let Some(obs) = fingerprint_single_vhost(
                svc.ip_addr,
                svc.port,
                scheme,
                &vhost,
                compiled_templates,
                policy,
                caps,
                &cancel,
            )
            .await
            {
                observations.push(obs);
            }
        }
    }

    observations
}

#[allow(clippy::too_many_arguments)]
async fn fingerprint_single_vhost(
    ip: IpAddr,
    port: u16,
    scheme: &str,
    vhost: &str,
    compiled_templates: &[CompiledTemplate],
    policy: &PolicySnapshot,
    caps: &WorkerCapabilities,
    cancel: &CancellationToken,
) -> Option<Stage3WebObservation> {
    let mut builder = Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .redirect(Policy::none())
        .timeout(Duration::from_secs(5));

    if vhost.parse::<IpAddr>().is_err() {
        builder = builder.resolve(vhost, SocketAddr::new(ip, port));
    }
    let client = builder.build().ok()?;

    let host_authority = if let Ok(parsed_ip) = vhost.parse::<IpAddr>() {
        match parsed_ip {
            IpAddr::V4(_) => format!("{vhost}:{port}"),
            IpAddr::V6(_) => format!("[{vhost}]:{port}"),
        }
    } else {
        format!("{vhost}:{port}")
    };
    let base_url = format!("{scheme}://{host_authority}");

    let root_resp = tokio::select! {
        () = cancel.cancelled() => return None,
        res = client.get(format!("{base_url}/")).send() => res.ok()?,
    };

    let http_status = root_resp.status().as_u16();
    let final_url = Some(root_resp.url().to_string());
    let redirect_target = root_resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

    let mut headers_filtered = HashMap::new();
    let mut headers_raw = String::new();
    let mut cookies_meta = Vec::new();
    let mut seen_cookies = BTreeSet::new();

    for (name, val) in root_resp.headers() {
        let Ok(val_str) = val.to_str() else {
            continue;
        };
        let key_str = name.as_str();
        if key_str.eq_ignore_ascii_case("set-cookie") {
            if let Some(meta) = parse_set_cookie_meta(val_str) {
                if seen_cookies.insert(meta.name.clone()) {
                    cookies_meta.push(meta);
                }
            }
            continue;
        }
        if key_str.eq_ignore_ascii_case("authorization")
            || key_str.eq_ignore_ascii_case("proxy-authorization")
            || key_str.eq_ignore_ascii_case("cookie")
        {
            continue;
        }
        headers_raw.push_str(&format!("{key_str}: {val_str}\n"));
        if !is_ignored_http_header(key_str) {
            headers_filtered.insert(key_str.to_ascii_lowercase(), val_str.to_string());
        }
    }

    let body = root_resp.text().await.unwrap_or_default();
    let title = extract_html_title(&body);

    // Passive /favicon.ico fetch for in-memory MurmurHash3
    let favicon_mmh3 = match client.get(format!("{base_url}/favicon.ico")).send().await {
        Ok(fav_resp) if fav_resp.status().is_success() => fav_resp
            .bytes()
            .await
            .ok()
            .filter(|b| !b.is_empty())
            .map(|b| mmh3_favicon_hash(&b)),
        _ => None,
    };

    let mut snapshots = vec![HttpProbeSnapshot {
        path: "/".to_string(),
        status: http_status,
        headers_raw,
        title: title.clone(),
        body,
        favicon_mmh3,
    }];

    // Passive path presence checks (zero authentication/login attempts)
    let mut detected_paths = Vec::new();
    for path in PASSIVE_PROBE_PATHS {
        if cancel.is_cancelled() {
            break;
        }
        let Ok(resp) = client.get(format!("{base_url}{path}")).send().await else {
            continue;
        };
        let st = resp.status().as_u16();
        let mut p_headers = String::new();
        for (k, v) in resp.headers() {
            let key_str = k.as_str();
            if key_str.eq_ignore_ascii_case("set-cookie")
                || key_str.eq_ignore_ascii_case("authorization")
                || key_str.eq_ignore_ascii_case("proxy-authorization")
                || key_str.eq_ignore_ascii_case("cookie")
            {
                continue;
            }
            if let Ok(vs) = v.to_str() {
                p_headers.push_str(&format!("{key_str}: {vs}\n"));
            }
        }
        let p_body = resp.text().await.unwrap_or_default();
        let p_title = extract_html_title(&p_body);
        if matches!(st, 200 | 401 | 403) {
            detected_paths.push((*path).to_string());
        }
        snapshots.push(HttpProbeSnapshot {
            path: (*path).to_string(),
            status: st,
            headers_raw: p_headers,
            title: p_title,
            body: p_body,
            favicon_mmh3,
        });
    }

    let mut matched_set = BTreeSet::new();
    for compiled in compiled_templates {
        if evaluate_compiled_template(compiled, &snapshots) {
            matched_set.insert(compiled.template.info.name.clone());
        }
    }

    if policy.enable_nuclei && caps.nuclei_version.is_some() && !cancel.is_cancelled() {
        let rate_str = policy.rate_pps.max(1).to_string();
        let grace = Duration::from_secs(policy.kill_grace_seconds.clamp(1, 10));
        let args = [
            "-u",
            base_url.as_str(),
            "-rl",
            rate_str.as_str(),
            "-silent",
            "-json",
        ];
        if let Ok(out) = run_cancellable_command("nuclei", &args, cancel.clone(), grace).await {
            for line in out.stdout.lines() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(name) = val
                        .get("info")
                        .and_then(|i| i.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        matched_set.insert(name.to_string());
                    }
                }
            }
        }
    }

    Some(Stage3WebObservation {
        ip_addr: ip,
        port,
        vhost: vhost.to_string(),
        scheme: scheme.to_string(),
        http_status: Some(http_status),
        final_url,
        redirect_target,
        title,
        headers_filtered,
        cookies_meta,
        favicon_mmh3,
        matched_technologies: matched_set.into_iter().collect(),
        detected_paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use asi_common::signatures::builtin_default_signatures_yaml;

    #[test]
    fn cookie_parser_strips_secret_values() {
        let meta = parse_set_cookie_meta(
            "ADMIN_SESSION=super_secret_token_123; Path=/; HttpOnly; SameSite=Lax",
        )
        .unwrap();
        assert_eq!(meta.name, "ADMIN_SESSION");
        assert!(meta.http_only);
        assert!(!meta.secure);
        assert_eq!(meta.same_site.as_deref(), Some("lax"));
        let serialized = serde_json::to_string(&meta).unwrap();
        assert!(!serialized.contains("super_secret_token_123"));
    }

    #[test]
    fn extracts_html_title_case_insensitively() {
        let html = "<html><HEAD><Title>  AGH Portal Test  </Title></HEAD></html>";
        assert_eq!(extract_html_title(html).as_deref(), Some("AGH Portal Test"));
    }

    #[test]
    fn evaluates_fingerprinthub_v4_templates() {
        let compiled = compile_templates(&builtin_default_signatures_yaml());
        let snaps = vec![
            HttpProbeSnapshot {
                path: "/".to_string(),
                status: 200,
                headers_raw: "server: nginx/1.27\n".to_string(),
                title: Some("Staging Faculty App".to_string()),
                body: "<h1>Faculty Staging</h1>".to_string(),
                favicon_mmh3: Some(12345),
            },
            HttpProbeSnapshot {
                path: "/admin".to_string(),
                status: 200,
                headers_raw: String::new(),
                title: Some("Admin Panel".to_string()),
                body: "<h1>Administration Login</h1>".to_string(),
                favicon_mmh3: Some(12345),
            },
        ];

        let matched: Vec<String> = compiled
            .iter()
            .filter(|c| evaluate_compiled_template(c, &snaps))
            .map(|c| c.template.info.name.clone())
            .collect();

        assert!(matched.contains(&"Nginx".to_string()));
        assert!(matched.contains(&"Staging Environment".to_string()));
        assert!(matched.contains(&"Admin Panel".to_string()));
    }
}
