//! DNS hijacking/poisoning detection — compare authoritative vs public resolver answers.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to check for DNS hijacking or poisoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHijackingRequest {
    pub domain: String,
    #[serde(default = "default_record_type")]
    pub record_type: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_record_type() -> String { "A".to_string() }
fn default_timeout() -> u64 { 10 }

/// Answer from a specific resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverAnswer {
    pub resolver_name: String,
    pub resolver_ip: String,
    pub answers: Vec<String>,  // sorted
}

/// DNS hijacking check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHijackingResult {
    pub domain: String,
    pub record_type: String,
    pub is_consistent: bool,
    pub authoritative_answers: Vec<String>,
    pub resolver_answers: Vec<ResolverAnswer>,
    pub discrepancies: Vec<String>,
    pub risk_level: String,  // "none" | "possible_hijacking" | "confirmed_discrepancy"
    pub error: Option<String>,
}

/// Check for DNS hijacking by comparing authoritative vs public resolvers.
pub async fn check_dns_hijacking(req: &DnsHijackingRequest) -> Result<DnsHijackingResult> {
    // Validate record type to prevent DNS protocol violations
    const ALLOWED_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "TXT", "NS"];
    if !ALLOWED_TYPES.contains(&req.record_type.as_str()) {
        return Ok(DnsHijackingResult {
            domain: req.domain.clone(),
            record_type: req.record_type.clone(),
            is_consistent: false,
            authoritative_answers: vec![],
            resolver_answers: vec![],
            discrepancies: vec![format!("Invalid record type: {}", req.record_type)],
            risk_level: "error".to_string(),
            error: Some(format!("Invalid record type: {}", req.record_type)),
        });
    }

    // Step 1: Get authoritative NS for domain
    let ns_req = crate::api::DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["NS".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    let ns_results = match crate::api::check_dns(&ns_req).await {
        Ok(results) => results,
        Err(e) => {
            return Ok(DnsHijackingResult {
                domain: req.domain.clone(),
                record_type: req.record_type.clone(),
                is_consistent: false,
                authoritative_answers: vec![],
                resolver_answers: vec![],
                discrepancies: vec![format!("Failed to resolve NS records: {}", e)],
                risk_level: "unknown".to_string(),
                error: Some(format!("NS lookup failed: {}", e)),
            });
        }
    };

    // Collect all resolvable NS servers (up to 3 for redundancy)
    let mut ns_ips = Vec::new();
    for result in &ns_results {
        for answer in &result.answers {
            if let crate::resolver::RecordData::Ns(ns_domain) = &answer.data {
                if let Ok(ip) = crate::api::helpers::resolve_hostname_to_ip(ns_domain, req.timeout_secs).await {
                    ns_ips.push(ip.to_string());
                    if ns_ips.len() >= 3 {  // Try up to 3 NSs for redundancy
                        break;
                    }
                }
            }
        }
        if ns_ips.len() >= 3 {
            break;
        }
    }

    // If we couldn't get any authoritative NS, return unable to verify state
    if ns_ips.is_empty() {
        return Ok(DnsHijackingResult {
            domain: req.domain.clone(),
            record_type: req.record_type.clone(),
            is_consistent: false,
            authoritative_answers: vec![],
            resolver_answers: vec![],
            discrepancies: vec!["Unable to resolve authoritative nameserver".to_string()],
            risk_level: "unable_to_verify".to_string(),
            error: Some("No authoritative NS resolved".to_string()),
        });
    }

    // Step 2: Query authoritative nameserver(s) — try first one that responds
    let mut auth_req_result: Option<crate::api::DnsQueryResult> = None;
    for ns_ip in &ns_ips {
        let auth_req = crate::api::DnsCheckRequest {
            domain: req.domain.clone(),
            record_types: vec![req.record_type.clone()],
            transport: crate::api::Transport::Server(ns_ip.clone()),
            timeout_secs: req.timeout_secs,
            ..Default::default()
        };

        if let Ok(mut results) = crate::api::check_dns(&auth_req).await {
            if !results.is_empty() {
                auth_req_result = Some(results.remove(0));
                break;
            }
        }
    }

    const MAX_ANSWERS_PER_RESOLVER: usize = 100;  // Prevent unbounded collection
    let mut authoritative_answers = Vec::with_capacity(10);
    if let Some(result) = &auth_req_result {
        for answer in result.answers.iter().take(MAX_ANSWERS_PER_RESOLVER) {
            match &answer.data {
                crate::resolver::RecordData::A(ip) => authoritative_answers.push(ip.clone()),
                crate::resolver::RecordData::Aaaa(ip) => authoritative_answers.push(ip.clone()),
                crate::resolver::RecordData::Cname(cname) => authoritative_answers.push(cname.clone()),
                crate::resolver::RecordData::Txt(txt) => {
                    authoritative_answers.push(txt.join(" "));
                }
                _ => {}
            }
        }
    }
    authoritative_answers.sort();
    authoritative_answers.dedup();

    // Step 3: Query public resolvers
    let public_resolvers = vec![
        ("Cloudflare", "1.1.1.1"),
        ("Google", "8.8.8.8"),
        ("Quad9", "9.9.9.9"),
    ];

    let mut resolver_answers = Vec::new();
    let mut discrepancies = Vec::new();

    for (name, ip) in public_resolvers {
        let pub_req = crate::api::DnsCheckRequest {
            domain: req.domain.clone(),
            record_types: vec![req.record_type.clone()],
            transport: crate::api::Transport::Server(ip.to_string()),
            timeout_secs: req.timeout_secs,
            ..Default::default()
        };

        let mut answers = Vec::with_capacity(10);
        if let Ok(results) = crate::api::check_dns(&pub_req).await {
            for result in results {
                for answer in result.answers.iter().take(MAX_ANSWERS_PER_RESOLVER - answers.len()) {
                    match &answer.data {
                        crate::resolver::RecordData::A(addr) => answers.push(addr.clone()),
                        crate::resolver::RecordData::Aaaa(addr) => answers.push(addr.clone()),
                        crate::resolver::RecordData::Cname(cname) => answers.push(cname.clone()),
                        crate::resolver::RecordData::Txt(txt) => {
                            answers.push(txt.join(" "));
                        }
                        _ => {}
                    }
                }
            }
        }
        answers.sort();
        answers.dedup();

        // Check for discrepancies
        if answers != authoritative_answers {
            discrepancies.push(format!("{}: authoritative={:?}, public={:?}", name, authoritative_answers, answers));
        }

        resolver_answers.push(ResolverAnswer {
            resolver_name: name.to_string(),
            resolver_ip: ip.to_string(),
            answers,
        });
    }

    let is_consistent = discrepancies.is_empty();
    let risk_level = if is_consistent {
        "none".to_string()
    } else if authoritative_answers.is_empty() && resolver_answers.iter().all(|r| r.answers.is_empty()) {
        "no_data".to_string()  // Both auth and resolvers returned no data
    } else if authoritative_answers.is_empty() {
        "no_authoritative_data".to_string()  // Auth returned nothing but resolvers have data
    } else {
        "confirmed_discrepancy".to_string()  // Actual inconsistency detected
    };

    Ok(DnsHijackingResult {
        domain: req.domain.clone(),
        record_type: req.record_type.clone(),
        is_consistent,
        authoritative_answers,
        resolver_answers,
        discrepancies,
        risk_level,
        error: None,
    })
}
