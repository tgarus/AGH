use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use asi_common::worker::{
    ChunkTarget, PolicySnapshot, Stage1PortFinding, Stage2ServiceFinding, WorkerCapabilities,
};
use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use x509_parser::extensions::GeneralName;

use crate::process::run_cancellable_command;

#[derive(Debug, Clone)]
pub struct TlsProbeInfo {
    pub sha256: String,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub san_dns: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub is_self_signed: bool,
}

#[derive(Debug)]
struct NoVerifyCertVerifier;

impl ServerCertVerifier for NoVerifyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[must_use]
pub fn is_web_service(service_name: Option<&str>, tunnel: Option<&str>, port: u16) -> bool {
    if let Some(svc) = service_name {
        let lower = svc.to_ascii_lowercase();
        if lower.contains("http") || lower == "https" {
            return true;
        }
    }
    if tunnel.is_some_and(|t| t.eq_ignore_ascii_case("ssl"))
        && matches!(port, 443 | 8443 | 9443 | 4443 | 7443)
    {
        return true;
    }
    matches!(port, 80 | 443 | 8000 | 8080 | 8081 | 8443 | 8888 | 9443)
}

#[must_use]
pub fn parse_nmap_xml(xml: &str, ip_addr: IpAddr) -> Vec<Stage2ServiceFinding> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut findings = Vec::new();
    let mut current_port: Option<u16> = None;
    let mut current_proto = String::from("tcp");
    let mut is_open = false;
    let mut service_name: Option<String> = None;
    let mut product: Option<String> = None;
    let mut version: Option<String> = None;
    let mut extra_info: Option<String> = None;
    let mut tunnel: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => match e.name().as_ref() {
                b"port" => {
                    current_port = None;
                    current_proto = String::from("tcp");
                    is_open = false;
                    service_name = None;
                    product = None;
                    version = None;
                    extra_info = None;
                    tunnel = None;

                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"portid" => {
                                if let Ok(val) = attr.unescape_value() {
                                    current_port = val.parse::<u16>().ok();
                                }
                            }
                            b"protocol" => {
                                if let Ok(val) = attr.unescape_value() {
                                    current_proto = val.to_ascii_lowercase();
                                }
                            }
                            _ => {}
                        }
                    }

                    // Handle self-closing empty <port/>
                }
                b"state" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"state" {
                            if let Ok(val) = attr.unescape_value() {
                                is_open = val == "open";
                            }
                        }
                    }
                }
                b"service" => {
                    for attr in e.attributes().flatten() {
                        let Ok(val) = attr.unescape_value() else {
                            continue;
                        };
                        let val_str = val.into_owned();
                        match attr.key.as_ref() {
                            b"name" => service_name = Some(val_str),
                            b"product" => product = Some(val_str),
                            b"version" => version = Some(val_str),
                            b"extrainfo" => extra_info = Some(val_str),
                            b"tunnel" => tunnel = Some(val_str),
                            _ => {}
                        }
                    }

                    if is_open {
                        if let Some(port) = current_port.take() {
                            let is_web_candidate =
                                is_web_service(service_name.as_deref(), tunnel.as_deref(), port);
                            findings.push(Stage2ServiceFinding {
                                ip_addr,
                                port,
                                protocol: current_proto.clone(),
                                service_name: service_name.take(),
                                product: product.take(),
                                version: version.take(),
                                extra_info: extra_info.take(),
                                tunnel: tunnel.take(),
                                is_web_candidate,
                                rdns_hostnames: Vec::new(),
                                tls_sha256: None,
                                tls_subject_cn: None,
                                tls_issuer_cn: None,
                                tls_san_dns: Vec::new(),
                                tls_not_before: None,
                                tls_not_after: None,
                                tls_is_self_signed: None,
                            });
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::End(ref e)) if e.name().as_ref() == b"port" => {
                if is_open {
                    if let Some(port) = current_port.take() {
                        let is_web_candidate =
                            is_web_service(service_name.as_deref(), tunnel.as_deref(), port);
                        findings.push(Stage2ServiceFinding {
                            ip_addr,
                            port,
                            protocol: current_proto.clone(),
                            service_name: service_name.take(),
                            product: product.take(),
                            version: version.take(),
                            extra_info: extra_info.take(),
                            tunnel: tunnel.take(),
                            is_web_candidate,
                            rdns_hostnames: Vec::new(),
                            tls_sha256: None,
                            tls_subject_cn: None,
                            tls_issuer_cn: None,
                            tls_san_dns: Vec::new(),
                            tls_not_before: None,
                            tls_not_after: None,
                            tls_is_self_signed: None,
                        });
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    findings
}

pub async fn probe_tls_certificate(
    ip: IpAddr,
    port: u16,
    sni_host: Option<&str>,
    cancel: &CancellationToken,
) -> Option<TlsProbeInfo> {
    if cancel.is_cancelled() {
        return None;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifyCertVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let sni_str = sni_host
        .map(ToString::to_string)
        .unwrap_or_else(|| ip.to_string());
    let server_name = ServerName::try_from(sni_str).ok()?;

    let tcp = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    .ok()?
    .ok()?;

    let tls_stream =
        tokio::time::timeout(Duration::from_secs(3), connector.connect(server_name, tcp))
            .await
            .ok()?
            .ok()?;

    let (_, conn) = tls_stream.get_ref();
    let end_entity = conn.peer_certificates()?.first()?;
    let sha256 = hex::encode(Sha256::digest(end_entity.as_ref()));

    let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref()).ok()?;
    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(ToString::to_string);
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(ToString::to_string);
    let is_self_signed = cert.subject() == cert.issuer();
    let not_before = DateTime::<Utc>::from_timestamp(cert.validity().not_before.timestamp(), 0);
    let not_after = DateTime::<Utc>::from_timestamp(cert.validity().not_after.timestamp(), 0);

    let mut san_set = BTreeSet::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for gn in &san_ext.value.general_names {
            if let GeneralName::DNSName(name) = gn {
                let norm = name.trim().trim_end_matches('.').to_ascii_lowercase();
                if !norm.is_empty() && !norm.starts_with("*.") {
                    san_set.insert(norm);
                }
            }
        }
    }

    Some(TlsProbeInfo {
        sha256,
        subject_cn,
        issuer_cn,
        san_dns: san_set.into_iter().collect(),
        not_before,
        not_after,
        is_self_signed,
    })
}

pub async fn lookup_rdns(ip: IpAddr) -> Vec<String> {
    let res = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip))
        .await
        .ok()
        .and_then(Result::ok);

    match res {
        Some(name) => {
            let norm = name.trim().trim_end_matches('.').to_ascii_lowercase();
            if norm.is_empty() || norm == ip.to_string() {
                Vec::new()
            } else {
                vec![norm]
            }
        }
        None => Vec::new(),
    }
}

#[must_use]
pub fn collect_vhosts(
    ip: IpAddr,
    user_vhosts: &[String],
    rdns: &[String],
    tls_san: &[String],
) -> Vec<String> {
    let mut set = BTreeSet::new();
    for h in user_vhosts.iter().chain(rdns.iter()).chain(tls_san.iter()) {
        let norm = h.trim().trim_end_matches('.').to_ascii_lowercase();
        if !norm.is_empty() && !norm.starts_with("*.") {
            set.insert(norm);
        }
    }
    let mut out: Vec<String> = set.into_iter().collect();
    if out.is_empty() {
        out.push(ip.to_string());
    }
    out
}

pub async fn run_stage2(
    targets: &[ChunkTarget],
    stage1_ports: &[Stage1PortFinding],
    probable_tarpit_ips: &[IpAddr],
    policy: &PolicySnapshot,
    caps: &WorkerCapabilities,
    cancel: CancellationToken,
) -> Vec<Stage2ServiceFinding> {
    let tarpit_set: BTreeSet<IpAddr> = probable_tarpit_ips.iter().copied().collect();
    let force_sv_set: BTreeSet<IpAddr> = policy.force_sv_ips.iter().copied().collect();

    let mut ports_by_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for finding in stage1_ports {
        ports_by_ip
            .entry(finding.ip_addr)
            .or_default()
            .push(finding.port);
    }

    let grace = Duration::from_secs(policy.kill_grace_seconds.clamp(1, 10));
    let mut all_services = Vec::new();

    for target in targets {
        if cancel.is_cancelled() {
            break;
        }
        let ip = target.ip_addr;
        if tarpit_set.contains(&ip) && !force_sv_set.contains(&ip) {
            tracing::warn!(target_ip = %ip, "skipping Stage 2 nmap -sV due to probable-tarpit guard");
            continue;
        }

        let Some(ports) = ports_by_ip.get(&ip) else {
            continue;
        };
        if ports.is_empty() {
            continue;
        }

        let mut unique_ports: Vec<u16> = ports.clone();
        unique_ports.sort_unstable();
        unique_ports.dedup();
        let port_list = unique_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");

        let mut host_services = if caps.nmap_version.is_some() {
            let ip_str = ip.to_string();
            let rate_str = policy.rate_pps.max(1).to_string();
            let delay_str = format!("{}ms", policy.per_ip_cooldown_ms.min(5000));
            let args = [
                "-Pn",
                "-n",
                "-sV",
                "--version-intensity",
                "2",
                "--max-rate",
                rate_str.as_str(),
                "--scan-delay",
                delay_str.as_str(),
                "-p",
                port_list.as_str(),
                "-oX",
                "-",
                ip_str.as_str(),
            ];

            match run_cancellable_command("nmap", &args, cancel.clone(), grace).await {
                Ok(out) if !out.cancelled => parse_nmap_xml(&out.stdout, ip),
                Ok(_) => break,
                Err(err) => {
                    tracing::warn!(target_ip = %ip, error = %err, "nmap execution failed, using heuristic fallback");
                    fallback_stage2_for_ports(ip, &unique_ports, &cancel).await
                }
            }
        } else {
            fallback_stage2_for_ports(ip, &unique_ports, &cancel).await
        };

        let rdns = lookup_rdns(ip).await;
        let primary_sni = target.vhosts.first().map(String::as_str);

        for svc in &mut host_services {
            svc.rdns_hostnames = rdns.clone();
            let should_probe_tls = svc.tunnel.as_deref() == Some("ssl")
                || svc.service_name.as_deref() == Some("https")
                || matches!(svc.port, 443 | 8443 | 9443 | 4443 | 7443);

            if should_probe_tls {
                if let Some(tls) = probe_tls_certificate(ip, svc.port, primary_sni, &cancel).await {
                    svc.tunnel = Some("ssl".to_string());
                    svc.is_web_candidate = true;
                    svc.tls_sha256 = Some(tls.sha256);
                    svc.tls_subject_cn = tls.subject_cn;
                    svc.tls_issuer_cn = tls.issuer_cn;
                    svc.tls_san_dns = tls.san_dns;
                    svc.tls_not_before = tls.not_before;
                    svc.tls_not_after = tls.not_after;
                    svc.tls_is_self_signed = Some(tls.is_self_signed);
                }
            }
        }

        all_services.extend(host_services);
    }

    all_services
}

async fn probe_unknown_tcp_banner(
    ip: IpAddr,
    port: u16,
    cancel: &CancellationToken,
) -> (Option<String>, Option<String>, bool) {
    if cancel.is_cancelled() {
        return (None, None, false);
    }

    let addr = SocketAddr::new(ip, port);
    let conn_res = tokio::select! {
        () = cancel.cancelled() => return (None, None, false),
        res = tokio::time::timeout(Duration::from_millis(800), TcpStream::connect(addr)) => res,
    };
    let Ok(Ok(mut stream)) = conn_res else {
        return (None, None, false);
    };

    let probe_req = format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n");
    let _ = tokio::select! {
        () = cancel.cancelled() => return (None, None, false),
        res = tokio::time::timeout(Duration::from_millis(800), stream.write_all(probe_req.as_bytes())) => res,
    };

    let mut buf = [0_u8; 256];
    let read_res = tokio::select! {
        () = cancel.cancelled() => return (None, None, false),
        res = tokio::time::timeout(Duration::from_millis(800), stream.read(&mut buf)) => res,
    };
    let Ok(Ok(n)) = read_res else {
        return (None, None, false);
    };
    if n == 0 {
        return (None, None, false);
    }

    let preview = String::from_utf8_lossy(&buf[..n]);
    let first_line = preview.lines().next().unwrap_or("").trim().to_string();
    if preview.starts_with("HTTP/") {
        (Some("http".to_string()), None, true)
    } else if preview.starts_with("SSH-") {
        (
            Some("ssh".to_string()),
            (!first_line.is_empty()).then_some(first_line),
            false,
        )
    } else {
        (None, None, false)
    }
}

async fn fallback_stage2_for_ports(
    ip: IpAddr,
    ports: &[u16],
    cancel: &CancellationToken,
) -> Vec<Stage2ServiceFinding> {
    let mut findings = Vec::with_capacity(ports.len());
    for &port in ports {
        if cancel.is_cancelled() {
            break;
        }
        let is_https = matches!(port, 443 | 8443 | 9443 | 4443 | 7443);
        let known_web = is_web_service(None, None, port);
        let (service_name, extra_info, is_web) = if is_https {
            (Some("https".to_string()), None, true)
        } else if known_web {
            (Some("http".to_string()), None, true)
        } else {
            probe_unknown_tcp_banner(ip, port, cancel).await
        };

        findings.push(Stage2ServiceFinding {
            ip_addr: ip,
            port,
            protocol: "tcp".to_string(),
            service_name,
            product: None,
            version: None,
            extra_info,
            tunnel: is_https.then(|| "ssl".to_string()),
            is_web_candidate: is_web,
            rdns_hostnames: Vec::new(),
            tls_sha256: None,
            tls_subject_cn: None,
            tls_issuer_cn: None,
            tls_san_dns: Vec::new(),
            tls_not_before: None,
            tls_not_after: None,
            tls_is_self_signed: None,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nmap_xml_including_nonstandard_http_ports() {
        let sample_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
      <port protocol="tcp" portid="8888"><state state="open"/><service name="http" product="nginx" version="1.27.0"/></port>
      <port protocol="tcp" portid="9443"><state state="open"/><service name="http" product="nginx" tunnel="ssl"/></port>
    </ports>
  </host>
</nmaprun>"#;

        let ip: IpAddr = "172.28.0.11".parse().unwrap();
        let parsed = parse_nmap_xml(sample_xml, ip);
        assert_eq!(parsed.len(), 3);
        assert!(!parsed[0].is_web_candidate);
        assert_eq!(parsed[0].service_name.as_deref(), Some("ssh"));
        assert!(parsed[1].is_web_candidate);
        assert_eq!(parsed[1].port, 8888);
        assert!(parsed[2].is_web_candidate);
        assert_eq!(parsed[2].tunnel.as_deref(), Some("ssl"));
    }

    #[test]
    fn collects_and_deduplicates_vhosts_with_ip_fallback() {
        let ip: IpAddr = "172.28.0.12".parse().unwrap();
        let vhosts = collect_vhosts(
            ip,
            &["App1.Lab.Local.".to_string()],
            &["app1.lab.local".to_string()],
            &["*.lab.local".to_string(), "staging.lab.local".to_string()],
        );
        assert_eq!(vhosts, vec!["app1.lab.local", "staging.lab.local"]);

        let fallback = collect_vhosts(ip, &[], &[], &[]);
        assert_eq!(fallback, vec!["172.28.0.12"]);
    }
}
