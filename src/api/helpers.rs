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
