//! Wildcard DNS detection — check if `*.domain` is configured.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Check for wildcard DNS configuration.
pub async fn check_wildcard_dns(req: &WildcardDnsRequest) -> Result<WildcardDnsResult> {
    let domain = &req.domain;
    let timeout_secs = req.timeout_secs;

    // Generate random subdomain labels to probe
    let random_labels = vec![
        "randomtest123456789",
        "nonexistentsubdomain",
        "xyzabc987654321test",
    ];

    let mut wildcard_detected = false;
    let mut responses = Vec::new();

    for label in random_labels {
        let test_domain = format!("{}.{}", label, domain);

        let dns_req = crate::api::DnsCheckRequest {
            domain: test_domain.clone(),
            record_types: vec!["A".to_string()],
            timeout_secs,
            ..Default::default()
        };

        match crate::api::check_dns(&dns_req).await {
            Ok(results) => {
                // Check if we got any answers (indicates wildcard or explicit record)
                let has_answers = results.iter().any(|r| !r.answers.is_empty());
                if has_answers {
                    wildcard_detected = true;
                    // Collect the IPs returned
                    let ips: Vec<String> = results
                        .iter()
                        .flat_map(|r| {
                            r.answers.iter().filter_map(|record| {
                                if let crate::api::RecordData::A(ip) = &record.data {
                                    Some(ip.clone())
                                } else {
                                    None
                                }
                            })
                        })
                        .collect();

                    responses.push(WildcardProbeResult {
                        label: label.to_string(),
                        responded: true,
                        ips,
                        error: None,
                    });
                } else {
                    responses.push(WildcardProbeResult {
                        label: label.to_string(),
                        responded: false,
                        ips: vec![],
                        error: None,
                    });
                }
            }
            Err(e) => {
                responses.push(WildcardProbeResult {
                    label: label.to_string(),
                    responded: false,
                    ips: vec![],
                    error: Some(e.to_string()),
                });
            }
        }
    }

    // Determine if wildcard is confirmed (all probes respond) or potential (some respond)
    let confirmed_responses = responses.iter().filter(|r| r.responded).count();
    let wildcard_status = match confirmed_responses {
        3 => "confirmed".to_string(),
        1..=2 => "potential".to_string(),
        _ => "not-detected".to_string(),
    };

    Ok(WildcardDnsResult {
        domain: domain.clone(),
        wildcard_detected,
        wildcard_status,
        probes: responses,
        error: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WildcardDnsRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WildcardDnsResult {
    pub domain: String,
    pub wildcard_detected: bool,
    /// "confirmed", "potential", "not-detected"
    pub wildcard_status: String,
    pub probes: Vec<WildcardProbeResult>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WildcardProbeResult {
    pub label: String,
    pub responded: bool,
    pub ips: Vec<String>,
    pub error: Option<String>,
}
