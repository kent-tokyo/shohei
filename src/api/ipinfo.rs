//! IP information checker — ASN, geolocation, organization details.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Check IP information including ASN, geolocation, and organization.
pub async fn check_ip_info(req: &IpInfoCheckRequest) -> Result<IpInfoCheckResult> {
    // Use ipinfo.io API (free, no API key required)
    let url = format!("https://ipinfo.io/{}/json", req.ip);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .send()
        .await
        .map_err(|e| crate::error::ShoheError::Transport(format!("IP info request failed: {}", e)))?;

    if !response.status().is_success() {
        return Ok(IpInfoCheckResult {
            ip: req.ip.clone(),
            country: None,
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            org: None,
            timezone: None,
            postal: None,
            hostname: None,
            error: Some(format!("API returned {}", response.status())),
        });
    }

    match response.json::<serde_json::Value>().await {
        Ok(data) => {
            Ok(IpInfoCheckResult {
                ip: req.ip.clone(),
                country: data.get("country").and_then(|v| v.as_str()).map(|s| s.to_string()),
                region: data.get("region").and_then(|v| v.as_str()).map(|s| s.to_string()),
                city: data.get("city").and_then(|v| v.as_str()).map(|s| s.to_string()),
                latitude: data.get("loc")
                    .and_then(|v| v.as_str())
                    .and_then(|loc| loc.split(',').next())
                    .and_then(|lat| lat.trim().parse::<f64>().ok()),
                longitude: data.get("loc")
                    .and_then(|v| v.as_str())
                    .and_then(|loc| loc.split(',').nth(1))
                    .and_then(|lon| lon.trim().parse::<f64>().ok()),
                org: data.get("org").and_then(|v| v.as_str()).map(|s| s.to_string()),
                timezone: data.get("timezone").and_then(|v| v.as_str()).map(|s| s.to_string()),
                postal: data.get("postal").and_then(|v| v.as_str()).map(|s| s.to_string()),
                hostname: data.get("hostname").and_then(|v| v.as_str()).map(|s| s.to_string()),
                error: None,
            })
        }
        Err(e) => {
            Ok(IpInfoCheckResult {
                ip: req.ip.clone(),
                country: None,
                region: None,
                city: None,
                latitude: None,
                longitude: None,
                org: None,
                timezone: None,
                postal: None,
                hostname: None,
                error: Some(format!("Failed to parse response: {}", e)),
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInfoCheckRequest {
    /// IP address to check (IPv4 or IPv6)
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInfoCheckResult {
    pub ip: String,
    /// ISO 3166-1 alpha-2 country code
    pub country: Option<String>,
    /// State/province name
    pub region: Option<String>,
    /// City name
    pub city: Option<String>,
    /// Latitude (from loc field)
    pub latitude: Option<f64>,
    /// Longitude (from loc field)
    pub longitude: Option<f64>,
    /// Organization / AS number + name (e.g., "AS15169 Google LLC")
    pub org: Option<String>,
    /// IANA timezone
    pub timezone: Option<String>,
    /// Postal code
    pub postal: Option<String>,
    /// Reverse DNS hostname
    pub hostname: Option<String>,
    pub error: Option<String>,
}
