//! DNS propagation checker — verify domain consistency across resolvers.

use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest, Transport};

/// Check DNS propagation across specified resolvers.
pub async fn check_propagation(req: &PropagationRequest) -> Result<PropagationResult> {
    // Validate record type allowlist (consistent with check_dns_hijacking)
    const ALLOWED_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "TXT", "NS"];
    if !ALLOWED_TYPES.contains(&req.record_type.as_str()) {
        return Err(crate::error::ShoheError::Parse(
            format!("Invalid record type: {}", req.record_type)
        ));
    }

    // Spawn parallel tasks for all resolvers (cap at 50 to prevent DoS)
    let mut handles = vec![];
    let mut early_errors: Vec<ResolverCheckResult> = vec![];
    let resolvers: Vec<_> = req.resolvers.iter().take(50).cloned().collect();

    for resolver in resolvers {
        // Reject private/reserved IP addresses to prevent SSRF via DNS server
        let ip_check = std::net::IpAddr::from_str(&resolver.address);
        match ip_check {
            Ok(ip) if crate::api::helpers::is_private_or_special_ip(&ip) => {
                early_errors.push(ResolverCheckResult {
                    resolver,
                    status: PropagationStatus::Error("Resolver address is a private or reserved IP".to_string()),
                    answers: vec![],
                    duration_ms: 0,
                    ttl_seconds: None,
                });
                continue;
            }
            Err(_) => {
                early_errors.push(ResolverCheckResult {
                    resolver,
                    status: PropagationStatus::Error("Invalid resolver IP address".to_string()),
                    answers: vec![],
                    duration_ms: 0,
                    ttl_seconds: None,
                });
                continue;
            }
            Ok(_) => {}
        }

        let resolver = resolver.clone();
        let domain = req.domain.clone();
        let record_type = req.record_type.clone();
        let timeout_secs = req.timeout_secs;

        let handle = tokio::spawn(async move {
            let dns_req = DnsCheckRequest {
                domain,
                record_types: vec![record_type],
                transport: Transport::Server(resolver.address.clone()),
                timeout_secs,
                ..Default::default()
            };

            let dns_results = check_dns(&dns_req).await;
            let (status, answers, duration_ms, ttl) = match dns_results {
                Ok(results) if !results.is_empty() && !results[0].answers.is_empty() => {
                    let ans: Vec<String> = results[0].answers.iter()
                        .map(|r| format_record_data(&r.data))
                        .collect();
                    let ttl = results[0].answers.first().map(|r| r.ttl as u64);
                    (PropagationStatus::Live, ans, results[0].duration_ms, ttl)
                }
                Ok(_) => (PropagationStatus::NoAnswer, vec![], 0, None),
                Err(e) => (PropagationStatus::Error(e.to_string()), vec![], 0, None),
            };

            ResolverCheckResult {
                resolver,
                status,
                answers,
                duration_ms,
                ttl_seconds: ttl,
            }
        });

        handles.push(handle);
    }

    // Collect results from all parallel tasks
    let mut results: Vec<ResolverCheckResult> = early_errors;
    for handle in handles {
        let result = handle.await.map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;
        results.push(result);
    }

    // Improved consistency check: normalize answers for comparison
    let consistent = if results.is_empty() {
        false
    } else if !matches!(results[0].status, PropagationStatus::Live) {
        false
    } else if results[0].answers.is_empty() {
        false
    } else {
        let first_answers_normalized: Vec<String> = results[0].answers.iter()
            .map(|a| a.to_lowercase())
            .collect();
        let mut first_answers_sorted = first_answers_normalized.clone();
        first_answers_sorted.sort();

        results.iter().all(|r| {
            if !matches!(r.status, PropagationStatus::Live) {
                return false;
            }
            let ans_normalized: Vec<String> = r.answers.iter()
                .map(|a| a.to_lowercase())
                .collect();
            let mut ans_sorted = ans_normalized.clone();
            ans_sorted.sort();
            ans_sorted == first_answers_sorted
        })
    };

    Ok(PropagationResult {
        domain: req.domain.clone(),
        record_type: req.record_type.clone(),
        consistent,
        results,
    })
}

// Helper function to normalize record data for consistent comparison
fn format_record_data(data: &crate::resolver::RecordData) -> String {
    use crate::resolver::RecordData;

    match data {
        RecordData::A(ip) => ip.to_string(),
        RecordData::Aaaa(ip) => ip.to_string(),
        RecordData::Cname(name) => name.clone(),
        RecordData::Mx { priority, exchange } => format!("{} {}", priority, exchange),
        RecordData::Txt(texts) => texts.join(" "),
        RecordData::Ns(ns) => ns.clone(),
        RecordData::Ptr(ptr) => ptr.clone(),
        RecordData::Soa { .. } => format!("{:?}", data),
        RecordData::Srv { .. } => format!("{:?}", data),
        RecordData::Https { .. } => format!("{:?}", data),
        RecordData::Svcb { .. } => format!("{:?}", data),
        RecordData::Naptr { .. } => format!("{:?}", data),
        RecordData::Caa { .. } => format!("{:?}", data),
        RecordData::Tlsa { .. } => format!("{:?}", data),
        RecordData::Sshfp { .. } => format!("{:?}", data),
        RecordData::Dnskey { .. } => format!("{:?}", data),
        RecordData::Ds { .. } => format!("{:?}", data),
        RecordData::Rrsig { .. } => format!("{:?}", data),
        RecordData::Unknown(s) => s.clone(),
    }
}

/// Convenience: check propagation against 6 global resolvers.
pub async fn check_propagation_global(domain: &str) -> Result<PropagationResult> {
    let req = PropagationRequest {
        domain: domain.to_string(),
        record_type: "A".to_string(),
        resolvers: vec![
            PropagationResolver { name: "Google".to_string(), address: "8.8.8.8".to_string(), region: None },
            PropagationResolver { name: "Cloudflare".to_string(), address: "1.1.1.1".to_string(), region: None },
            PropagationResolver { name: "Quad9".to_string(), address: "9.9.9.9".to_string(), region: None },
            PropagationResolver { name: "OpenDNS".to_string(), address: "208.67.222.222".to_string(), region: None },
            PropagationResolver { name: "CleanBrowsing".to_string(), address: "185.228.168.168".to_string(), region: None },
            PropagationResolver { name: "Comodo".to_string(), address: "8.26.56.26".to_string(), region: None },
        ],
        timeout_secs: 5,
    };
    check_propagation(&req).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationRequest {
    pub domain: String,
    pub record_type: String,
    pub resolvers: Vec<PropagationResolver>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationResolver {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub region: Option<String>,  // NEW: geographic region (US-East, EU, etc.)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationResult {
    pub domain: String,
    pub record_type: String,
    pub consistent: bool,
    pub results: Vec<ResolverCheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverCheckResult {
    pub resolver: PropagationResolver,
    pub status: PropagationStatus,
    pub answers: Vec<String>,
    pub duration_ms: u64,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,  // NEW: TTL from response
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropagationStatus {
    Live,
    NoAnswer,
    Error(String),
}
