//! URLhaus URL reputation — check URL against URLhaus malware/phishing database.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to check URL reputation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlhausRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// Result of URLhaus check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlhausResult {
    pub url: String,
    pub is_malicious: bool,
    pub url_status: String,        // "online" | "offline" | "unknown"
    pub threat: Option<String>,    // "malware_download" | "phishing" | "exploit" | etc.
    pub tags: Vec<String>,         // e.g. ["emotet", "malspam"]
    pub date_added: Option<String>,
    pub urlhaus_reference: Option<String>,
    pub message: String,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UrlhausApiResponse {
    pub query_status: String,
    pub url_status: Option<String>,
    pub threat: Option<String>,
    pub tags: Option<Vec<String>>,
    pub date_added: Option<String>,
    pub reference: Option<String>,
}

/// Check URL against URLhaus database.
pub async fn check_url_reputation(req: &UrlhausRequest) -> Result<UrlhausResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(format!("Client build failed: {}", e)))?;

    let params = [("url", req.url.as_str())];

    let response = match client
        .post("https://urlhaus-api.abuse.ch/v1/url/")
        .form(&params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Ok(UrlhausResult {
                url: req.url.clone(),
                is_malicious: false,
                url_status: "unknown".to_string(),
                threat: None,
                tags: vec![],
                date_added: None,
                urlhaus_reference: None,
                message: "URLhaus request failed".to_string(),
                error: Some(e.to_string()),
            });
        }
    };

    let status = response.status();

    if status.is_client_error() || status.is_server_error() {
        return Ok(UrlhausResult {
            url: req.url.clone(),
            is_malicious: false,
            url_status: "unknown".to_string(),
            threat: None,
            tags: vec![],
            date_added: None,
            urlhaus_reference: None,
            message: format!("URLhaus HTTP {}", status),
            error: Some(format!("HTTP {}", status)),
        });
    }

    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return Ok(UrlhausResult {
                url: req.url.clone(),
                is_malicious: false,
                url_status: "unknown".to_string(),
                threat: None,
                tags: vec![],
                date_added: None,
                urlhaus_reference: None,
                message: "Failed to parse URLhaus response".to_string(),
                error: Some(e.to_string()),
            });
        }
    };

    let api_response: UrlhausApiResponse = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            return Ok(UrlhausResult {
                url: req.url.clone(),
                is_malicious: false,
                url_status: "unknown".to_string(),
                threat: None,
                tags: vec![],
                date_added: None,
                urlhaus_reference: None,
                message: "Failed to parse URLhaus JSON".to_string(),
                error: Some(e.to_string()),
            });
        }
    };

    let is_malicious = match api_response.query_status.as_str() {
        "ok" => true,
        "no_results" => false,
        "invalid_url" => false,
        "not_found" => false,
        _ => false,
    };

    Ok(UrlhausResult {
        url: req.url.clone(),
        is_malicious,
        url_status: api_response.url_status.unwrap_or("unknown".to_string()),
        threat: api_response.threat,
        tags: api_response.tags.unwrap_or_default(),
        date_added: api_response.date_added,
        urlhaus_reference: api_response.reference,
        message: format!("query_status: {}", api_response.query_status),
        error: None,
    })
}
