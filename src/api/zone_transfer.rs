//! Zone Transfer (AXFR) attempt detection — critical misconfiguration check.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use crate::error::Result;

/// Request to attempt a DNS zone transfer (AXFR).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransferRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// Result of zone transfer attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransferResult {
    pub domain: String,
    pub nameservers_tried: Vec<String>,
    pub transfer_allowed: bool,
    pub records: Vec<crate::api::DnsRecord>,
    pub record_count: usize,
    pub error: Option<String>,
}

/// Attempt DNS zone transfer against all authoritative nameservers.
pub async fn check_zone_transfer(req: &ZoneTransferRequest) -> Result<ZoneTransferResult> {
    let domain = req.domain.clone();
    let timeout_secs = req.timeout_secs;

    // Step 1: Get NS records for the domain
    let ns_req = crate::api::helpers::dns_request_for_record_type(
        domain.clone(),
        "NS",
        timeout_secs,
    );

    let dns_results = match crate::api::check_dns(&ns_req).await {
        Ok(results) => results,
        Err(e) => {
            return Ok(ZoneTransferResult {
                domain,
                nameservers_tried: vec![],
                transfer_allowed: false,
                records: vec![],
                record_count: 0,
                error: Some(format!("Failed to get NS records: {}", e)),
            });
        }
    };

    let mut nameservers = Vec::new();
    for result in &dns_results {
        for record in &result.answers {
            if let crate::api::RecordData::Ns(ns_name) = &record.data {
                nameservers.push(ns_name.clone());
            }
        }
    }

    if nameservers.is_empty() {
        return Ok(ZoneTransferResult {
            domain,
            nameservers_tried: vec![],
            transfer_allowed: false,
            records: vec![],
            record_count: 0,
            error: Some("No NS records found".to_string()),
        });
    }

    // Step 2: Attempt AXFR against each NS
    let mut nameservers_tried = Vec::new();
    let mut zone_records = Vec::new();
    let mut transfer_allowed = false;

    for ns_name in nameservers {
        nameservers_tried.push(ns_name.clone());

        // Resolve NS hostname to IP
        let ns_ip = match crate::api::helpers::resolve_hostname_to_ip(&ns_name, timeout_secs).await {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        let server_addr = SocketAddr::new(ns_ip, 53);

        // Attempt AXFR
        match crate::resolver::zone_transfer::axfr(&domain, server_addr, timeout_secs).await {
            Ok(query_result) => {
                transfer_allowed = true;
                zone_records = query_result.answers.clone();
                break;
            }
            Err(_) => {
                continue;
            }
        }
    }

    Ok(ZoneTransferResult {
        domain,
        nameservers_tried,
        transfer_allowed,
        records: zone_records.clone(),
        record_count: zone_records.len(),
        error: None,
    })
}
