use std::net::IpAddr;

use ipnetwork::IpNetwork;

use crate::assets::{IgnoredTargetType, TargetType};
use crate::error::FieldViolation;

pub fn validate_target_value(
    field_name: &str,
    target_type: TargetType,
    raw: &str,
) -> Result<String, FieldViolation> {
    let trimmed = raw.trim();
    match target_type {
        TargetType::Ip => trimmed
            .parse::<IpAddr>()
            .map(|ip| ip.to_string())
            .map_err(|_| FieldViolation {
                field: field_name.to_string(),
                code: "INVALID_IP".to_string(),
                message: "Expected valid IPv4 or IPv6 address.".to_string(),
            }),
        TargetType::Cidr | TargetType::ExcludeCidr => trimmed
            .parse::<IpNetwork>()
            .map(|net| net.network().to_string() + "/" + &net.prefix().to_string())
            .map_err(|_| FieldViolation {
                field: field_name.to_string(),
                code: "INVALID_CIDR".to_string(),
                message: "Expected valid IPv4 or IPv6 CIDR block.".to_string(),
            }),
        TargetType::Domain => validate_domain(trimmed).map_err(|message| FieldViolation {
            field: field_name.to_string(),
            code: "INVALID_DOMAIN".to_string(),
            message,
        }),
    }
}

pub fn validate_ignored_target_value(
    field_name: &str,
    target_type: IgnoredTargetType,
    raw: &str,
) -> Result<String, FieldViolation> {
    let mapped = match target_type {
        IgnoredTargetType::Ip => TargetType::Ip,
        IgnoredTargetType::Cidr => TargetType::Cidr,
        IgnoredTargetType::Domain => TargetType::Domain,
    };
    validate_target_value(field_name, mapped, raw)
}

pub fn validate_domain(raw: &str) -> Result<String, String> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return Err("Domain length must be between 1 and 253 characters.".to_string());
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err("Domain must contain at least two dot-separated labels.".to_string());
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err("Each domain label must be 1..63 characters.".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Domain labels cannot start or end with a hyphen.".to_string());
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("Domain contains invalid characters.".to_string());
        }
    }
    if let Some(tld) = labels.last() {
        if tld.bytes().all(|b| b.is_ascii_digit()) {
            return Err("Top-level domain cannot be purely numeric.".to_string());
        }
    }
    Ok(domain)
}

pub fn validate_port_spec(raw: &str) -> Result<String, String> {
    let spec = raw.trim().to_ascii_lowercase();
    if spec.is_empty() {
        return Err("Port specification cannot be empty.".to_string());
    }
    if matches!(spec.as_str(), "top-100" | "top-1000") {
        return Ok(spec);
    }

    for part in spec.split(',') {
        let token = part.trim();
        if token.is_empty() {
            return Err("Empty segment in port specification.".to_string());
        }
        if let Some((start_s, end_s)) = token.split_once('-') {
            let start: u16 = start_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range start: '{start_s}'"))?;
            let end: u16 = end_s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range end: '{end_s}'"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!(
                    "Invalid port range '{token}' (must satisfy 1 <= start <= end <= 65535)."
                ));
            }
        } else {
            let port: u16 = token
                .parse()
                .map_err(|_| format!("Invalid port number: '{token}'"))?;
            if port == 0 {
                return Err("Port 0 is not valid.".to_string());
            }
        }
    }

    Ok(spec)
}

pub fn validate_username(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.len() < 3 || trimmed.len() > 64 {
        return Err("Username must be between 3 and 64 characters.".to_string());
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(
            "Username may contain only ASCII letters, digits, '.', '_', or '-'.".to_string(),
        );
    }
    Ok(trimmed.to_string())
}

pub fn validate_email(raw: &str) -> Result<String, String> {
    let email = raw.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > 254 || email.contains(char::is_whitespace) {
        return Err("Invalid email format.".to_string());
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err("Email must contain '@'.".to_string());
    };
    if local.is_empty() || local.len() > 64 || domain.contains('@') {
        return Err("Invalid email address.".to_string());
    }
    validate_domain(domain).map_err(|_| "Email domain is invalid.".to_string())?;
    Ok(email)
}

pub fn validate_password_strength(raw: &str) -> Result<(), String> {
    if raw.len() < 12 {
        return Err("Password must be at least 12 characters long.".to_string());
    }
    let has_upper = raw.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = raw.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = raw.chars().any(|c| c.is_ascii_digit());
    let has_special = raw.chars().any(|c| !c.is_ascii_alphanumeric());
    let classes = [has_upper, has_lower, has_digit, has_special]
        .into_iter()
        .filter(|b| *b)
        .count();
    if classes < 3 {
        return Err(
            "Password must include at least 3 character classes (upper, lower, digit, symbol)."
                .to_string(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn validate_scan_policy_bounds(
    port_spec: &str,
    rate_pps: i32,
    per_ip_cooldown_ms: i32,
    subnet_concurrency: i32,
    kill_grace_seconds: i32,
    inactivity_threshold: i32,
    tarpit_port_threshold: i32,
) -> Vec<FieldViolation> {
    let mut violations = Vec::new();
    if let Err(msg) = validate_port_spec(port_spec) {
        violations.push(FieldViolation {
            field: "port_spec".to_string(),
            code: "INVALID_PORT_SPEC".to_string(),
            message: msg,
        });
    }
    if rate_pps <= 0 {
        violations.push(FieldViolation {
            field: "rate_pps".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "rate_pps must be > 0.".to_string(),
        });
    }
    if per_ip_cooldown_ms < 0 {
        violations.push(FieldViolation {
            field: "per_ip_cooldown_ms".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "per_ip_cooldown_ms must be >= 0.".to_string(),
        });
    }
    if subnet_concurrency <= 0 {
        violations.push(FieldViolation {
            field: "subnet_concurrency".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "subnet_concurrency must be > 0.".to_string(),
        });
    }
    if !(1..=10).contains(&kill_grace_seconds) {
        violations.push(FieldViolation {
            field: "kill_grace_seconds".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "kill_grace_seconds must be between 1 and 10.".to_string(),
        });
    }
    if inactivity_threshold < 1 {
        violations.push(FieldViolation {
            field: "inactivity_threshold".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "inactivity_threshold must be >= 1.".to_string(),
        });
    }
    if tarpit_port_threshold < 1 {
        violations.push(FieldViolation {
            field: "tarpit_port_threshold".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "tarpit_port_threshold must be >= 1.".to_string(),
        });
    }
    violations
}

const CURATED_TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 500, 514,
    515, 587, 631, 636, 873, 902, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082,
    2083, 2086, 2087, 2181, 2222, 2375, 2376, 2379, 3000, 3128, 3306, 3389, 4000, 4200, 4443, 4500,
    4848, 5000, 5001, 5060, 5432, 5601, 5672, 5900, 5984, 5985, 6000, 6379, 6443, 7001, 7002, 7077,
    7443, 7474, 8000, 8001, 8008, 8080, 8081, 8082, 8088, 8090, 8161, 8200, 8443, 8500, 8888, 9000,
    9001, 9042, 9090, 9092, 9099, 9100, 9200, 9300, 9443, 9999, 10000, 11211, 15672, 27017, 50000,
];

/// Expands a validated port specification into sorted unique TCP port numbers.
/// Note: for `"top-1000"` in dev fallback mode, expands 1..=1024 plus curated high ports.
pub fn expand_port_spec(raw: &str) -> Result<Vec<u16>, String> {
    let spec = validate_port_spec(raw)?;
    let mut ports = std::collections::BTreeSet::new();

    if spec == "top-100" {
        ports.extend(CURATED_TOP_PORTS.iter().copied());
        return Ok(ports.into_iter().collect());
    }
    if spec == "top-1000" {
        ports.extend(1_u16..=1024);
        ports.extend(CURATED_TOP_PORTS.iter().copied());
        return Ok(ports.into_iter().collect());
    }

    for part in spec.split(',') {
        let token = part.trim();
        if let Some((start_s, end_s)) = token.split_once('-') {
            let start: u16 = start_s
                .trim()
                .parse()
                .map_err(|_| "Invalid port range".to_string())?;
            let end: u16 = end_s
                .trim()
                .parse()
                .map_err(|_| "Invalid port range".to_string())?;
            ports.extend(start..=end);
        } else {
            let port: u16 = token.parse().map_err(|_| "Invalid port".to_string())?;
            ports.insert(port);
        }
    }

    Ok(ports.into_iter().collect())
}

#[must_use]
pub fn estimate_port_count(raw: &str) -> u32 {
    let norm = raw.trim().to_ascii_lowercase();
    if norm == "top-100" {
        return 100;
    }
    if norm == "top-1000" {
        return 1000;
    }
    expand_port_spec(&norm)
        .map(|v| u32::try_from(v.len()).unwrap_or(65_535))
        .unwrap_or(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_targets() {
        assert_eq!(
            validate_target_value("v", TargetType::Ip, " 172.28.0.10 ").unwrap(),
            "172.28.0.10"
        );
        assert_eq!(
            validate_target_value("v", TargetType::Cidr, "172.28.0.5/24").unwrap(),
            "172.28.0.0/24"
        );
        assert_eq!(
            validate_target_value("v", TargetType::Domain, "Portal.AGH.edu.pl.").unwrap(),
            "portal.agh.edu.pl"
        );
        assert!(validate_target_value("v", TargetType::Cidr, "not-a-cidr").is_err());
        assert!(validate_target_value("v", TargetType::Domain, "localhost").is_err());
    }

    #[test]
    fn validates_port_specs() {
        assert_eq!(validate_port_spec("top-1000").unwrap(), "top-1000");
        assert_eq!(
            validate_port_spec("80,443,8000-8100").unwrap(),
            "80,443,8000-8100"
        );
        assert!(validate_port_spec("0").is_err());
        assert!(validate_port_spec("9000-8000").is_err());
        assert!(validate_port_spec("abc").is_err());
    }

    #[test]
    fn expands_and_estimates_port_specs() {
        assert_eq!(
            expand_port_spec("80,443,8080-8082").unwrap(),
            vec![80, 443, 8080, 8081, 8082]
        );
        assert_eq!(estimate_port_count("80,443,8080-8082"), 5);
        assert_eq!(estimate_port_count("1-65535"), 65_535);
        assert_eq!(estimate_port_count("top-1000"), 1000);
        assert!(expand_port_spec("top-100").unwrap().contains(&8888));
    }

    #[test]
    fn validates_user_credentials() {
        assert_eq!(validate_username("admin_agh-01").unwrap(), "admin_agh-01");
        assert!(validate_username("ab").is_err());
        assert_eq!(
            validate_email("Admin@AGH.edu.pl").unwrap(),
            "admin@agh.edu.pl"
        );
        assert!(validate_email("bad-email").is_err());
        assert!(validate_password_strength("ChangeMeNow_Admin123!").is_ok());
        assert!(validate_password_strength("weakpass").is_err());
    }
}
