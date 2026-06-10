//! RPKI (Resource Public Key Infrastructure) / ROA (Route Origin Authorization) checker.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Check RPKI ROA validity for an IP address prefix.
pub async fn check_rpki(req: &RpkiCheckRequest) -> Result<RpkiCheckResult> {
    let ip = &req.ip;

    // For the PoC, we'll use a simplified API validation
    // Production would call Cloudflare RPKI API: https://rpki.cloudflare.com/api/v1/validity/{asn}/{prefix}
    // Or RIPE NCC: https://rpki-validator.ripe.net/api/v1/validity/{asn}/{prefix}

    match check_rpki_validity(ip).await {
        Ok(result) => Ok(result),
        Err(e) => Ok(RpkiCheckResult {
            ip: ip.clone(),
            asn: None,
            prefix: None,
            roa_state: "error".to_string(),
            roa_valid: false,
            error: Some(e.to_string()),
        }),
    }
}

async fn check_rpki_validity(ip: &str) -> Result<RpkiCheckResult> {
    use reqwest::Client;

    let client = Client::new();

    // First, get IP info from ipinfo.io to retrieve ASN
    let ipinfo_url = format!("https://ipinfo.io/{}/json", ip);
    let ip_info_response = client
        .get(&ipinfo_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    let asn = match ip_info_response {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                json.get("org")
                    .and_then(|v| v.as_str())
                    .and_then(|org| org.split_whitespace().next())
                    .and_then(|asn_str| asn_str.parse::<u32>().ok())
            } else {
                None
            }
        }
        Err(_) => None,
    };

    // Determine prefix CIDR (simplified)
    let prefix = if ip.contains(':') {
        format!("{}/64", ip)  // Simplified: assume /64 for IPv6
    } else {
        format!("{}/24", ip)  // Simplified: assume /24 for IPv4
    };

    // Query Cloudflare RPKI API
    let rpki_url = if let Some(asn_num) = asn {
        format!(
            "https://rpki.cloudflare.com/api/v1/validity/AS{}/{}",
            asn_num, prefix
        )
    } else {
        // Without ASN, we can't validate
        return Ok(RpkiCheckResult {
            ip: ip.to_string(),
            asn,
            prefix: Some(prefix),
            roa_state: "not-found".to_string(),
            roa_valid: false,
            error: Some("Could not determine ASN".to_string()),
        });
    };

    let rpki_response = client
        .get(&rpki_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    match rpki_response {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let state = json
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let valid = state == "valid";

                Ok(RpkiCheckResult {
                    ip: ip.to_string(),
                    asn,
                    prefix: Some(prefix),
                    roa_state: state,
                    roa_valid: valid,
                    error: None,
                })
            } else {
                Ok(RpkiCheckResult {
                    ip: ip.to_string(),
                    asn,
                    prefix: Some(prefix),
                    roa_state: "unknown".to_string(),
                    roa_valid: false,
                    error: Some("Invalid response from RPKI API".to_string()),
                })
            }
        }
        Err(e) => Ok(RpkiCheckResult {
            ip: ip.to_string(),
            asn,
            prefix: Some(prefix),
            roa_state: "error".to_string(),
            roa_valid: false,
            error: Some(format!("RPKI API error: {}", e)),
        }),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpkiCheckRequest {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpkiCheckResult {
    pub ip: String,
    pub asn: Option<u32>,
    pub prefix: Option<String>,
    /// "valid", "invalid", "not-found", "unknown", "error"
    pub roa_state: String,
    pub roa_valid: bool,
    pub error: Option<String>,
}
