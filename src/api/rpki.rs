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
    use std::str::FromStr;

    // Validate IP address format to prevent SSRF/injection
    std::net::IpAddr::from_str(ip)
        .map_err(|_| crate::error::ShoheError::Parse(format!("Invalid IP address: {}", ip)))?;

    let client = Client::new();

    // Get BGP route info from RIPE STAT to get actual prefix and ASN
    let bgp_req = crate::api::BgpRouteRequest {
        ip: ip.to_string(),
        timeout_secs: 10,
    };

    let bgp_result = crate::api::check_bgp_route(&bgp_req).await.ok();
    let asn = bgp_result.as_ref().and_then(|r| r.asn);
    let prefix = bgp_result.as_ref().and_then(|r| r.prefix.clone());

    // Require BGP data for accurate prefix; don't guess
    let prefix = match prefix {
        Some(p) => p,
        None => {
            // Return error instead of making incorrect assumptions about prefix length
            return Ok(RpkiCheckResult {
                ip: ip.to_string(),
                asn,
                prefix: None,
                roa_state: "unable_to_determine".to_string(),
                roa_valid: false,
                error: Some("Could not determine prefix length from BGP — RPKI validation unreliable".to_string()),
            });
        }
    };

    // Query Cloudflare RPKI API
    let rpki_url = if let Some(asn_num) = asn {
        format!(
            "https://rpki.cloudflare.com/api/v1/validity/AS{}/{}",
            asn_num, urlencoding::encode(&prefix)
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
