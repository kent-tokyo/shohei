//! GreyNoise IP classification — internet scanner and threat classification.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to classify an IP via GreyNoise community API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreyNoiseRequest {
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// GreyNoise IP classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreyNoiseResult {
    pub ip: String,
    /// Internet background noise (scanning, reconnaissance)
    pub noise: bool,
    /// Known benign infrastructure (Cloudflare, Google, etc.)
    pub riot: bool,
    /// Classification: "malicious" | "benign" | "unknown" | "scanning" | None
    pub classification: Option<String>,
    /// Name or organization (e.g. "Shodan.io", "Cloudflare")
    pub name: Option<String>,
    /// Last seen timestamp
    pub last_seen: Option<String>,
    /// API response message
    pub message: String,
    /// Error message if any
    pub error: Option<String>,
}

/// Classify an IP address using GreyNoise community API (no API key required).
pub async fn check_ip_noise(req: &GreyNoiseRequest) -> Result<GreyNoiseResult> {
    let ip = req.ip.clone();
    let timeout_secs = req.timeout_secs;

    let url = format!("https://api.greynoise.io/v3/community/{}", urlencoding::encode(&ip));

    let client = reqwest::Client::new();
    let response = match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(GreyNoiseResult {
                ip,
                noise: false,
                riot: false,
                classification: None,
                name: None,
                last_seen: None,
                message: format!("API request failed: {}", e),
                error: Some(format!("API request failed: {}", e)),
            });
        }
    };

    // 404 = IP not in dataset
    if response.status().as_u16() == 404 {
        return Ok(GreyNoiseResult {
            ip,
            noise: false,
            riot: false,
            classification: None,
            name: None,
            last_seen: None,
            message: "IP not in GreyNoise dataset".to_string(),
            error: None,
        });
    }

    if !response.status().is_success() {
        let status_code = response.status().as_u16();
        return Ok(GreyNoiseResult {
            ip,
            noise: false,
            riot: false,
            classification: None,
            name: None,
            last_seen: None,
            message: format!("HTTP {}", status_code),
            error: Some(format!("HTTP error: {}", status_code)),
        });
    }

    // Parse JSON response
    #[derive(Deserialize)]
    struct GreyNoiseApiResponse {
        noise: Option<bool>,
        riot: Option<bool>,
        classification: Option<String>,
        name: Option<String>,
        last_seen: Option<String>,
        message: Option<String>,
    }

    match response.json::<GreyNoiseApiResponse>().await {
        Ok(api_resp) => {
            Ok(GreyNoiseResult {
                ip,
                noise: api_resp.noise.unwrap_or(false),
                riot: api_resp.riot.unwrap_or(false),
                classification: api_resp.classification,
                name: api_resp.name,
                last_seen: api_resp.last_seen,
                message: api_resp.message.unwrap_or_default(),
                error: None,
            })
        }
        Err(e) => {
            Ok(GreyNoiseResult {
                ip,
                noise: false,
                riot: false,
                classification: None,
                name: None,
                last_seen: None,
                message: format!("Failed to parse API response: {}", e),
                error: Some(format!("JSON parse error: {}", e)),
            })
        }
    }
}
