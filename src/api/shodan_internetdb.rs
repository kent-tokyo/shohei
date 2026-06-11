//! Shodan InternetDB IP reputation — query open ports, CPEs, tags, and CVE associations.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to query Shodan InternetDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanInternetDbRequest {
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// Result from Shodan InternetDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanInternetDbResult {
    pub ip: String,
    pub open_ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub cpes: Vec<String>,
    pub tags: Vec<String>,
    pub vulns: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanApiResponse {
    pub ip: Option<String>,
    pub ports: Option<Vec<u16>>,
    pub hostnames: Option<Vec<String>>,
    pub cpes: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub vulns: Option<Vec<String>>,
    pub detail: Option<String>,
}

/// Query Shodan InternetDB for IP information.
pub async fn check_shodan_ip(req: &ShodanInternetDbRequest) -> Result<ShodanInternetDbResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(format!("Client build failed: {}", e)))?;

    let url = format!("https://internetdb.shodan.io/{}", req.ip);

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(ShodanInternetDbResult {
                ip: req.ip.clone(),
                open_ports: vec![],
                hostnames: vec![],
                cpes: vec![],
                tags: vec![],
                vulns: vec![],
                error: Some(e.to_string()),
            });
        }
    };

    let status = response.status();

    if status.is_client_error() || status.is_server_error() {
        return Ok(ShodanInternetDbResult {
            ip: req.ip.clone(),
            open_ports: vec![],
            hostnames: vec![],
            cpes: vec![],
            tags: vec![],
            vulns: vec![],
            error: Some(format!("Shodan HTTP {}", status)),
        });
    }

    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return Ok(ShodanInternetDbResult {
                ip: req.ip.clone(),
                open_ports: vec![],
                hostnames: vec![],
                cpes: vec![],
                tags: vec![],
                vulns: vec![],
                error: Some(e.to_string()),
            });
        }
    };

    let api_response: ShodanApiResponse = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            return Ok(ShodanInternetDbResult {
                ip: req.ip.clone(),
                open_ports: vec![],
                hostnames: vec![],
                cpes: vec![],
                tags: vec![],
                vulns: vec![],
                error: Some(e.to_string()),
            });
        }
    };

    // If "detail" field exists, IP not in database
    if api_response.detail.is_some() {
        return Ok(ShodanInternetDbResult {
            ip: req.ip.clone(),
            open_ports: vec![],
            hostnames: vec![],
            cpes: vec![],
            tags: vec![],
            vulns: vec![],
            error: Some("IP not found in Shodan database".to_string()),
        });
    }

    Ok(ShodanInternetDbResult {
        ip: req.ip.clone(),
        open_ports: api_response.ports.unwrap_or_default(),
        hostnames: api_response.hostnames.unwrap_or_default(),
        cpes: api_response.cpes.unwrap_or_default(),
        tags: api_response.tags.unwrap_or_default(),
        vulns: api_response.vulns.unwrap_or_default(),
        error: None,
    })
}
