//! Helper functions for API modules — extracted common patterns to reduce duplication.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::Result;

/// Default timeout for all API requests (in seconds). Centralized to enable single-point policy changes.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

// ── Chrono replacements ────────────────────────────────────────────────────

/// Current Unix timestamp in seconds (UTC).
pub fn now_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Format a Unix timestamp (seconds) as an RFC 3339 UTC string (e.g. "2026-06-13T12:34:56Z").
pub fn format_rfc3339(secs: u64) -> String {
    // Days since 1970-01-01, with Gregorian calendar arithmetic.
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let mut days = secs / 86400;

    let mut year = 1970u32;
    while year < 9999 {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let months = if is_leap(year) { &[31,29,31,30,31,30,31,31,30,31,30,31] }
                 else              { &[31,28,31,30,31,30,31,31,30,31,30,31] };
    let mut month = 1u32;
    for &ml in months.iter() {
        if days < ml { break; }
        days -= ml;
        month += 1;
    }
    let day = days + 1;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, h, m, s)
}

fn is_leap(y: u32) -> bool { y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) }

/// Current time as RFC 3339 UTC string (replaces `chrono::Local::now().to_rfc3339()`).
pub fn now_rfc3339() -> String {
    format_rfc3339(now_timestamp())
}

/// Current time as "%Y-%m-%d %H:%M:%S" UTC string (replaces `chrono::Local::now().format(...)`).
pub fn now_formatted() -> String {
    // "2026-06-13 12:34:56" — reuse format_rfc3339 to avoid duplicated calendar logic
    format_rfc3339(now_timestamp())
        .replacen('T', " ", 1)
        .trim_end_matches('Z')
        .to_string()
}

/// RFC 3339 string N days from now (replaces `chrono::Local::now() + Duration::days(N)`).
pub fn rfc3339_days_from_now(days: u64) -> String {
    format_rfc3339(now_timestamp().saturating_add(days.saturating_mul(86400)))
}

/// RFC 3339 string N hours from now.
pub fn rfc3339_hours_from_now(hours: u64) -> String {
    format_rfc3339(now_timestamp().saturating_add(hours.saturating_mul(3600)))
}

/// Parse an RFC 3339 string to Unix seconds, handling UTC and ±HH:MM offsets.
/// Returns None if parsing fails.
pub fn parse_rfc3339_secs(s: &str) -> Option<u64> {
    // Separate the datetime part and optional timezone offset
    // Formats: "2024-01-15T10:30:00Z" | "2024-01-15T10:30:00+09:00" | "2024-01-15T10:30:00-05:30"
    let (datetime_part, offset_secs) = if s.ends_with('Z') {
        (&s[..s.len()-1], 0i64)
    } else if s.len() >= 25 && s.is_ascii() {
        let tz = &s[19..];
        // Skip fractional seconds (.NNN) before the ±HH:MM offset
        let tz = if tz.starts_with('.') {
            match tz.find(['+', '-']) {
                Some(idx) => &tz[idx..],
                None => return None,
            }
        } else {
            tz
        };
        // Parse ±HH:MM offset using safe slice access
        let sign: i64 = match tz.chars().next()? { '+' => 1, '-' => -1, _ => return None };
        let oh: i64 = tz.get(1..3)?.parse().ok()?;
        let om: i64 = tz.get(4..6)?.parse().ok()?;
        (&s[..19], -sign * (oh * 3600 + om * 60))  // subtract offset to get UTC
    } else {
        (s, 0i64)  // assume UTC
    };
    let s = if datetime_part.len() >= 19 { &datetime_part[..19] } else { return None; };
    let year: u32  = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32   = s[8..10].parse().ok()?;
    let hour: u64  = s[11..13].parse().ok()?;
    let min: u64   = s[14..16].parse().ok()?;
    let sec: u64   = s[17..19].parse().ok()?;
    if month < 1 || month > 12 || day < 1 || day > 31 { return None; }
    // Days from epoch to start of year
    let mut days = 0u64;
    for y in 1970..year { days += if is_leap(y) { 366 } else { 365 }; }
    let months_days: &[u32] = if is_leap(year) { &[0,31,29,31,30,31,30,31,31,30,31,30,31] }
                              else              { &[0,31,28,31,30,31,30,31,31,30,31,30,31] };
    for mi in 1..month { days += months_days[mi as usize] as u64; }
    days += (day - 1) as u64;
    let utc_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    // Apply timezone offset (negative means ahead of UTC, e.g. +09:00 → subtract 9h)
    let result = utc_secs as i64 + offset_secs;
    if result < 0 { None } else { Some(result as u64) }
}

/// Parse "%Y-%m-%dT%H:%M:%S" (no timezone) as UTC seconds.
pub fn parse_naive_datetime_secs(s: &str) -> Option<u64> {
    parse_rfc3339_secs(&format!("{}Z", s))
}

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
/// Uses the `url` crate (WHATWG spec) to normalise alternative IPv4 representations
/// (decimal integer `2130706433`, short-form `127.1`, hex `0x7f.0.0.1`, trailing-dot `127.0.0.1.`)
/// before checking against the private-IP block list.
///
/// Returns `Err` with a descriptive message if the URL is unsafe.
pub fn validate_url_safety(url: &str) -> std::result::Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    match parsed.scheme() {
        "http" | "https" => {}
        s => return Err(format!("Disallowed URL scheme '{}' — only http/https allowed", s)),
    }

    match parsed.host() {
        None => return Err("URL has no host".to_string()),
        Some(url::Host::Ipv4(v4)) => {
            // The url crate normalises 127.1, 2130706433, 0x7f.0.0.1 → Ipv4 here
            if is_private_or_special_ip(&std::net::IpAddr::V4(v4)) {
                return Err(format!("Host IP '{}' is a private/reserved address — blocked for security", v4));
            }
        }
        Some(url::Host::Ipv6(v6)) => {
            if is_private_or_special_ip(&std::net::IpAddr::V6(v6)) {
                return Err(format!("Host IP '{}' is a private/reserved address — blocked for security", v6));
            }
        }
        Some(url::Host::Domain(domain)) => {
            // Strip trailing dot and re-attempt IP parse (e.g. "127.0.0.1.")
            let trimmed = domain.trim_end_matches('.');
            if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                if is_private_or_special_ip(&ip) {
                    return Err(format!("Host IP '{}' is a private/reserved address — blocked for security", ip));
                }
            }
            // Block obvious internal hostnames
            let lower = trimmed.to_lowercase();
            if lower == "localhost"
                || lower.ends_with(".local")
                || lower.ends_with(".internal")
                || lower.ends_with(".intranet")
            {
                return Err(format!("Host '{}' appears to be an internal hostname — blocked for security", trimmed));
            }
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
            // IPv4-mapped (::ffff:x.x.x.x) — check the embedded IPv4 address
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_or_special_ip(&std::net::IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique local: fc00::/7
                || (v6.segments()[0] & 0xfe00 == 0xfc00)
                // Link-local: fe80::/10
                || (v6.segments()[0] & 0xffc0 == 0xfe80)
        }
    }
}

/// Hex-encode bytes using a lookup table (replaces the `hex` crate).
pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Percent-encode a string for use in URLs (replaces the `urlencoding` crate).
/// Leaves ASCII alphanumerics and `-_.~` unencoded per RFC 3986.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{:02X}", byte);
            }
        }
    }
    out
}

/// Generate a unique ID string using monotonic system time (replaces the `uuid` crate for stub implementations).
/// Format: `{prefix}_{nanos_hex}` — not a real UUID but unique within a process.
pub fn generate_id(prefix: &str) -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}_{:x}{:08x}", prefix, dur.as_secs(), dur.subsec_nanos())
}

/// Resolve the first CNAME record for a domain. Used by cloud exposure detection modules.
pub async fn resolve_first_cname(domain: &str, timeout_secs: u64) -> Option<String> {
    crate::api::check_dns(&dns_request_for_record_type(domain.to_string(), "CNAME", timeout_secs))
        .await
        .ok()?
        .into_iter()
        .flat_map(|r| r.answers)
        .find_map(|rec| {
            if let crate::api::RecordData::Cname(c) = rec.data { Some(c) } else { None }
        })
}

/// Build a reqwest HTTP client with a timeout. Centralises the 32+ call sites that repeat
/// `reqwest::Client::builder().timeout(...).build().map_err(...)`.
pub fn build_http_client(timeout_secs: u64) -> crate::error::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))
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
