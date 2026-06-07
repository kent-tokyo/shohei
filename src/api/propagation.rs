//! DNS propagation checker — verify domain consistency across resolvers.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest, Transport};

/// Check DNS propagation across specified resolvers.
pub async fn check_propagation(req: &PropagationRequest) -> Result<PropagationResult> {
    let mut results = Vec::new();

    for resolver in &req.resolvers {
        let dns_req = DnsCheckRequest {
            domain: req.domain.clone(),
            record_types: vec![req.record_type.clone()],
            transport: Transport::Server(resolver.address.clone()),
            timeout_secs: req.timeout_secs,
            ..Default::default()
        };

        let dns_results = check_dns(&dns_req).await;
        let (status, answers, duration_ms) = match dns_results {
            Ok(results) if !results.is_empty() && !results[0].answers.is_empty() => {
                let ans: Vec<String> = results[0].answers.iter()
                    .map(|r| format!("{:?}", r.data))
                    .collect();
                (PropagationStatus::Live, ans, results[0].duration_ms)
            }
            Ok(_) => (PropagationStatus::NoAnswer, vec![], 0),
            Err(e) => (PropagationStatus::Error(e.to_string()), vec![], 0),
        };

        results.push(ResolverCheckResult {
            resolver: resolver.clone(),
            status,
            answers,
            duration_ms,
        });
    }

    let consistent = if results.is_empty() {
        false
    } else {
        let first_answers = &results[0].answers;
        results.iter().all(|r| &r.answers == first_answers && matches!(r.status, PropagationStatus::Live))
    };

    Ok(PropagationResult {
        domain: req.domain.clone(),
        record_type: req.record_type.clone(),
        consistent,
        results,
    })
}

/// Convenience: check propagation against 6 global resolvers.
pub async fn check_propagation_global(domain: &str) -> Result<PropagationResult> {
    let req = PropagationRequest {
        domain: domain.to_string(),
        record_type: "A".to_string(),
        resolvers: vec![
            PropagationResolver { name: "Google".to_string(), address: "8.8.8.8".to_string() },
            PropagationResolver { name: "Cloudflare".to_string(), address: "1.1.1.1".to_string() },
            PropagationResolver { name: "Quad9".to_string(), address: "9.9.9.9".to_string() },
            PropagationResolver { name: "OpenDNS".to_string(), address: "208.67.222.222".to_string() },
            PropagationResolver { name: "CleanBrowsing".to_string(), address: "185.228.168.168".to_string() },
            PropagationResolver { name: "Comodo".to_string(), address: "8.26.56.26".to_string() },
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropagationStatus {
    Live,
    NoAnswer,
    Error(String),
}
