//! Helper functions for API modules — extracted common patterns to reduce duplication.

use std::net::IpAddr;
use std::str::FromStr;
use crate::error::Result;

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
