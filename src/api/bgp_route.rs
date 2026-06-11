//! BGP route hijacking detection via RIPE STAT API — detect unauthorized route announcements.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to check BGP route information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpRouteRequest {
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// BGP route information result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpRouteResult {
    pub ip: String,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub prefix: Option<String>,          // e.g. "8.8.8.0/24"
    pub visibility_percent: Option<f64>, // % of RIS peers announcing this prefix
    pub is_announced: bool,
    pub country: Option<String>,
    pub registry: Option<String>,        // "ripencc" | "arin" | "apnic" | "lacnic" | "afrinic"
    pub bgp_peers: Option<u32>,          // number of peers announcing
    pub error: Option<String>,
}

/// Check BGP route information for an IP address via RIPE STAT API.
pub async fn check_bgp_route(req: &BgpRouteRequest) -> Result<BgpRouteResult> {
    // Validate IP address format to prevent SSRF/injection
    use std::str::FromStr;
    if std::net::IpAddr::from_str(&req.ip).is_err() {
        return Ok(BgpRouteResult {
            ip: req.ip.clone(),
            asn: None,
            asn_name: None,
            prefix: None,
            visibility_percent: None,
            is_announced: false,
            country: None,
            registry: None,
            bgp_peers: None,
            error: Some(format!("Invalid IP address: {}", req.ip)),
        });
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(format!("Client build failed: {}", e)))?;

    // Step 1: Get prefix overview and ASN info
    let prefix_url = format!("https://stat.ripe.net/data/prefix-overview/data.json?resource={}", req.ip);
    let prefix_response = match client.get(&prefix_url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(BgpRouteResult {
                ip: req.ip.clone(),
                asn: None,
                asn_name: None,
                prefix: None,
                visibility_percent: None,
                is_announced: false,
                country: None,
                registry: None,
                bgp_peers: None,
                error: Some(format!("Prefix lookup failed: {}", e)),
            });
        }
    };

    // Check response size to prevent memory exhaustion DoS
    const MAX_RESPONSE_SIZE: u64 = 1024 * 500;  // 500 KB limit
    if let Some(len) = prefix_response.content_length() {
        if len > MAX_RESPONSE_SIZE {
            return Ok(BgpRouteResult {
                ip: req.ip.clone(),
                asn: None,
                asn_name: None,
                prefix: None,
                visibility_percent: None,
                is_announced: false,
                country: None,
                registry: None,
                bgp_peers: None,
                error: Some("RIPE STAT response exceeds size limit".to_string()),
            });
        }
    }

    let prefix_body = match prefix_response.text().await {
        Ok(b) => b,
        Err(e) => {
            return Ok(BgpRouteResult {
                ip: req.ip.clone(),
                asn: None,
                asn_name: None,
                prefix: None,
                visibility_percent: None,
                is_announced: false,
                country: None,
                registry: None,
                bgp_peers: None,
                error: Some(format!("Failed to read prefix response: {}", e)),
            });
        }
    };

    let prefix_json: serde_json::Value = match serde_json::from_str(&prefix_body) {
        Ok(j) => j,
        Err(e) => {
            return Ok(BgpRouteResult {
                ip: req.ip.clone(),
                asn: None,
                asn_name: None,
                prefix: None,
                visibility_percent: None,
                is_announced: false,
                country: None,
                registry: None,
                bgp_peers: None,
                error: Some(format!("Failed to parse prefix JSON: {}", e)),
            });
        }
    };

    // Extract data from prefix-overview response
    let data = &prefix_json["data"];

    let prefix = data["resource"]
        .as_str()
        .map(|s| s.to_string());

    let registry = data["block"]["registry"]
        .as_str()
        .map(|s| s.to_string());

    let country = data["block"]["country"]
        .as_str()
        .map(|s| s.to_string());

    let (asn, asn_name) = if let Some(asns) = data["asns"].as_array() {
        if let Some(first_asn) = asns.first() {
            let asn_num = first_asn["asn"].as_u64().map(|n| n as u32);
            let holder = first_asn["holder"].as_str().map(|s| s.to_string());
            (asn_num, holder)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // Step 2: Get routing status (visibility and announcement status)
    let routing_url = format!("https://stat.ripe.net/data/routing-status/data.json?resource={}", req.ip);
    let routing_response = match client.get(&routing_url).send().await {
        Ok(r) => r,
        Err(_) => {
            // Prefix data succeeded, return what we have
            return Ok(BgpRouteResult {
                ip: req.ip.clone(),
                asn,
                asn_name,
                prefix,
                visibility_percent: None,
                is_announced: false,
                country,
                registry,
                bgp_peers: None,
                error: None,
            });
        }
    };

    // Check response size to prevent memory exhaustion DoS
    if let Some(len) = routing_response.content_length() {
        if len > MAX_RESPONSE_SIZE {
            return Ok(BgpRouteResult {
                ip: req.ip.clone(),
                asn,
                asn_name,
                prefix,
                visibility_percent: None,
                is_announced: false,
                country,
                registry,
                bgp_peers: None,
                error: Some("RIPE STAT routing response exceeds size limit".to_string()),
            });
        }
    }

    let routing_body = match routing_response.text().await {
        Ok(b) => b,
        Err(_) => {
            return Ok(BgpRouteResult {
                ip: req.ip.clone(),
                asn,
                asn_name,
                prefix,
                visibility_percent: None,
                is_announced: false,
                country,
                registry,
                bgp_peers: None,
                error: None,
            });
        }
    };

    let routing_json: serde_json::Value = match serde_json::from_str(&routing_body) {
        Ok(j) => j,
        Err(_) => {
            return Ok(BgpRouteResult {
                ip: req.ip.clone(),
                asn,
                asn_name,
                prefix,
                visibility_percent: None,
                is_announced: false,
                country,
                registry,
                bgp_peers: None,
                error: None,
            });
        }
    };

    let routing_data = &routing_json["data"];

    let is_announced = routing_data["is_announced"]
        .as_bool()
        .unwrap_or(false);

    // Try v4 first, fallback to v6 for IPv6 addresses
    let visibility_percent = if let Some(visibility) = routing_data["visibility"]["v4"].as_object() {
        let ris_peers_seeing = visibility["ris_peers_seeing"]
            .as_u64()
            .unwrap_or(0);
        let total_ris_peers = visibility["total_ris_peers_seeing"]
            .as_u64()
            .unwrap_or(1);

        if total_ris_peers > 0 {
            Some((ris_peers_seeing as f64 / total_ris_peers as f64) * 100.0)
        } else {
            None
        }
    } else if let Some(visibility) = routing_data["visibility"]["v6"].as_object() {
        let ris_peers_seeing = visibility["ris_peers_seeing"]
            .as_u64()
            .unwrap_or(0);
        let total_ris_peers = visibility["total_ris_peers_seeing"]
            .as_u64()
            .unwrap_or(1);

        if total_ris_peers > 0 {
            Some((ris_peers_seeing as f64 / total_ris_peers as f64) * 100.0)
        } else {
            None
        }
    } else {
        None
    };

    // Try v4 first, fallback to v6
    let bgp_peers = routing_data["visibility"]["v4"]["ris_peers_seeing"]
        .as_u64()
        .map(|n| n as u32)
        .or_else(|| routing_data["visibility"]["v6"]["ris_peers_seeing"].as_u64().map(|n| n as u32));

    Ok(BgpRouteResult {
        ip: req.ip.clone(),
        asn,
        asn_name,
        prefix,
        visibility_percent,
        is_announced,
        country,
        registry,
        bgp_peers,
        error: None,
    })
}
