//! DNS delegation audit — check SOA consistency and NS reachability.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest};
use crate::resolver::RecordData;


/// Check DNS delegation consistency (SOA serial alignment, NS reachability).
pub async fn check_delegation(req: &DelegationCheckRequest) -> Result<DelegationCheckResult> {
    // Step 1: Get NS records for the domain
    let ns_req = DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["NS".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    let ns_records = match check_dns(&ns_req).await {
        Ok(results) => {
            if !results.is_empty() && !results[0].answers.is_empty() {
                results[0]
                    .answers
                    .iter()
                    .filter_map(|record| {
                        if let RecordData::Ns(ns_name) = &record.data {
                            Some(ns_name.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    if ns_records.is_empty() {
        return Ok(DelegationCheckResult {
            domain: req.domain.clone(),
            ns_servers: vec![],
            soa_serials_match: false,
            is_lame_delegation: true,
            error: Some("No NS records found for domain".to_string()),
        });
    }

    // Step 2: Query SOA record from each NS in parallel
    let soa_futures = ns_records.iter().map(|ns_server| {
        let domain = req.domain.clone();
        let ns_name = ns_server.clone();
        let timeout = req.timeout_secs;
        async move {
            let soa_req = DnsCheckRequest {
                domain: domain.clone(),
                record_types: vec!["SOA".to_string()],
                timeout_secs: timeout,
                ..Default::default()
            };

            let serial = match check_dns(&soa_req).await {
                Ok(results) => {
                    if !results.is_empty() && !results[0].answers.is_empty() {
                        results[0]
                            .answers
                            .iter()
                            .find_map(|record| {
                                if let RecordData::Soa { serial, .. } = &record.data {
                                    Some(*serial)
                                } else {
                                    None
                                }
                            })
                    } else {
                        None
                    }
                }
                Err(_) => None,
            };

            DelegationNsResult {
                ns_server: ns_name,
                reachable: serial.is_some(),
                soa_serial: serial,
            }
        }
    });

    let spawned_del: Vec<_> = soa_futures.map(tokio::spawn).collect();
    let mut ns_results = Vec::with_capacity(spawned_del.len());
    for h in spawned_del { if let Ok(v) = h.await { ns_results.push(v); } }

    // Step 3: Check for consistency
    let reachable_count = ns_results.iter().filter(|r| r.reachable).count();
    let is_lame_delegation = reachable_count == 0;

    // Check if SOA serials match across all reachable servers
    let serial_values: Vec<_> = ns_results
        .iter()
        .filter_map(|r| r.soa_serial)
        .collect();

    let soa_serials_match = if serial_values.is_empty() {
        false
    } else {
        let first_serial = serial_values[0];
        serial_values.iter().all(|&s| s == first_serial)
    };

    Ok(DelegationCheckResult {
        domain: req.domain.clone(),
        ns_servers: ns_results,
        soa_serials_match,
        is_lame_delegation,
        error: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCheckRequest {
    /// Domain to audit
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCheckResult {
    pub domain: String,
    /// SOA records from each NS server
    pub ns_servers: Vec<DelegationNsResult>,
    /// True if SOA serial matches across all reachable NS servers
    pub soa_serials_match: bool,
    /// True if no NS servers are reachable (lame delegation)
    pub is_lame_delegation: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationNsResult {
    pub ns_server: String,
    /// True if this NS server responded to SOA query
    pub reachable: bool,
    /// SOA serial if available
    pub soa_serial: Option<u32>,
}
