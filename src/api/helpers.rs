//! Helper functions for API modules — extracted common patterns to reduce duplication.

use std::net::IpAddr;
use std::str::FromStr;
use crate::error::Result;

/// Default timeout for all API requests (in seconds). Centralized to enable single-point policy changes.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Verdict engine for determining threat/trust levels from scores.
pub struct VerdictEngine;

impl VerdictEngine {
    /// Determine threat verdict from flag count and risk score.
    /// - flagged_count >= 2: "malicious" (multiple sources agree)
    /// - flagged_count == 1 || risk_score > 70: "suspicious" (one source or high score)
    /// - else: "clean" (no flags)
    pub fn determine_threat_verdict(flagged_count: u8, risk_score: u8) -> String {
        if flagged_count >= 2 {
            "malicious".to_string()
        } else if flagged_count == 1 || risk_score > 70 {
            "suspicious".to_string()
        } else {
            "clean".to_string()
        }
    }
}

/// Resolve a hostname to an IP address using DNS.
pub async fn resolve_hostname_to_ip(hostname: &str, timeout_secs: u64) -> Result<IpAddr> {
    let dns_req = crate::api::DnsCheckRequest {
        domain: hostname.to_string(),
        record_types: vec!["A".to_string()],
        timeout_secs,
        ..Default::default()
    };

    let results = crate::api::check_dns(&dns_req).await?;
    if results.is_empty() || results[0].answers.is_empty() {
        return Err(crate::error::ShoheError::DnsResolution(format!(
            "No DNS records for {}",
            hostname
        )));
    }

    // Extract first A record
    for record in &results[0].answers {
        if let crate::api::RecordData::A(ip_str) = &record.data {
            return Ok(std::net::IpAddr::from_str(ip_str)
                .map_err(|_| crate::error::ShoheError::Parse(format!(
                    "Invalid IP address: {}",
                    ip_str
                )))?);
        }
    }

    Err(crate::error::ShoheError::DnsResolution(format!(
        "No A records found for {}",
        hostname
    )))
}

/// Validate a URL for SSRF safety: scheme must be http/https, host must not be a private/loopback/link-local IP.
///
/// Returns `Err` with a descriptive message if the URL is unsafe.
pub fn validate_url_safety(url: &str) -> std::result::Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    // Allow only http and https
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("Disallowed URL scheme '{}' — only http/https allowed", scheme)),
    }

    // Check the host
    let host = parsed.host_str().ok_or("URL has no host")?;

    // If host is an IP address, check for private ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_or_special_ip(&ip) {
            return Err(format!("Host IP '{}' is a private/reserved address — blocked for security", ip));
        }
    } else {
        // For hostnames, block obvious internal names
        let lower = host.to_lowercase();
        if lower == "localhost"
            || lower.ends_with(".local")
            || lower.ends_with(".internal")
            || lower.ends_with(".intranet")
        {
            return Err(format!("Host '{}' appears to be an internal hostname — blocked for security", host));
        }
    }

    Ok(())
}

fn is_private_or_special_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // Loopback: 127.0.0.0/8
            o[0] == 127
            // RFC1918: 10.0.0.0/8
            || o[0] == 10
            // RFC1918: 172.16.0.0/12
            || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
            // RFC1918: 192.168.0.0/16
            || (o[0] == 192 && o[1] == 168)
            // Link-local: 169.254.0.0/16 (includes IMDS)
            || (o[0] == 169 && o[1] == 254)
            // Unspecified: 0.0.0.0/8
            || o[0] == 0
            // CGNAT: 100.64.0.0/10
            || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique local: fc00::/7
                || (v6.segments()[0] & 0xfe00 == 0xfc00)
                // Link-local: fe80::/10
                || (v6.segments()[0] & 0xffc0 == 0xfe80)
        }
    }
}

/// Build a DnsCheckRequest for a single record type query.
pub fn dns_request_for_record_type(
    domain: String,
    record_type: &str,
    timeout_secs: u64,
) -> crate::api::DnsCheckRequest {
    crate::api::DnsCheckRequest {
        domain,
        record_types: vec![record_type.to_string()],
        timeout_secs,
        ..Default::default()
    }
}
