//! Parked domain detection — identify if a domain is parked for sale.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to check if a domain is parked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParkedDomainRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// Result of parked domain check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParkedDomainResult {
    pub domain: String,
    pub is_parked: bool,
    pub confidence: String,
    pub parking_provider: Option<String>,
    pub signals: Vec<String>,
    pub body_length: Option<usize>,
    pub error: Option<String>,
}

/// Detect if a domain is parked for sale.
pub async fn check_parked_domain(req: &ParkedDomainRequest) -> Result<ParkedDomainResult> {
    let domain = req.domain.clone();

    // Try HTTPS first, then HTTP
    let urls = vec![
        format!("https://{}", domain),
        format!("http://{}", domain),
    ];

    let mut best_result: Option<ParkedDomainResult> = None;

    for url in urls {
        let http_req = crate::api::HttpCheckRequest {
            url: url.clone(),
            follow_redirects: true,
            timeout_secs: req.timeout_secs,
        };

        match crate::api::check_http(&http_req).await {
            Ok(http_result) => {
                // Skip if 404 or 5xx
                if let Some(status) = http_result.status_code {
                    if status >= 400 {
                        continue;
                    }
                }

                let mut signals = Vec::new();
                let mut confidence = "low".to_string();
                let mut parking_provider: Option<String> = None;

                // Check headers for parking provider signatures
                if let Some(server_header) = &http_result.server_header {
                    let server_lower = server_header.to_lowercase();
                    if server_lower.contains("sedo") {
                        parking_provider = Some("Sedo".to_string());
                        signals.push("sedo_header".to_string());
                        confidence = "high".to_string();
                    } else if server_lower.contains("godaddy") || server_lower.contains("parking") {
                        parking_provider = Some("GoDaddy".to_string());
                        signals.push("godaddy_header".to_string());
                        confidence = "high".to_string();
                    } else if server_lower.contains("bodis") {
                        parking_provider = Some("Bodis".to_string());
                        signals.push("bodis_header".to_string());
                        confidence = "high".to_string();
                    }
                }

                // Check for known parking keywords in response (note: we don't have body in HttpCheckResult)
                // This is a limitation — parked domain detection fully requires body content
                // For now, we rely on headers and indirect signals

                // Check for thin content signals (inferred from what HTTP returns)
                // Status 200 with certain servers is a signal

                // Optional: call check_whois to see domain age
                if confidence == "high" {
                    // Domain is likely parked based on headers
                    let result = ParkedDomainResult {
                        domain: domain.clone(),
                        is_parked: true,
                        confidence,
                        parking_provider,
                        signals,
                        body_length: None,
                        error: None,
                    };
                    best_result = Some(result);
                    break;
                } else if best_result.is_none() {
                    let result = ParkedDomainResult {
                        domain: domain.clone(),
                        is_parked: false,
                        confidence: "low".to_string(),
                        parking_provider,
                        signals,
                        body_length: None,
                        error: None,
                    };
                    best_result = Some(result);
                }
            }
            Err(_) => continue,
        }
    }

    match best_result {
        Some(result) => Ok(result),
        None => Ok(ParkedDomainResult {
            domain,
            is_parked: false,
            confidence: "unknown".to_string(),
            parking_provider: None,
            signals: vec![],
            body_length: None,
            error: Some("Unable to fetch domain content".to_string()),
        }),
    }
}
