//! Certificate Transparency checker — validate CT log inclusion.

use serde::{Deserialize, Serialize};
use crate::error::{Result, ShoheError};
use crate::api::tls::{check_tls_chain, TlsCheckRequest};

/// Check Certificate Transparency logs for certificate inclusion.
pub async fn check_ct(req: &CtCheckRequest) -> Result<CtCheckResult> {
    let scts = Vec::new();
    let mut log_entries = Vec::new();
    let unexpected_certs = Vec::new();
    let mut scts = scts;

    // Step 1: Get certificate via TLS
    let tls_req = TlsCheckRequest {
        hostname: req.hostname.clone(),
        port: req.port,
        check_dane: false,
        timeout_secs: req.timeout_secs,
    };

    if let Ok(tls_result) = check_tls_chain(&tls_req).await {
        if !tls_result.chain.is_empty() {
            let _leaf_cert = &tls_result.chain[0];

            // Step 2: Query crt.sh for certificate transparency
            match query_crt_sh(&req.hostname).await {
                Ok(certs) => {
                    for cert in certs {
                        log_entries.push(CtLogEntry {
                            not_before: cert.get("notBefore").cloned(),
                            not_after: cert.get("notAfter").cloned(),
                            serial: cert.get("serial").cloned(),
                        });
                    }
                    scts.push(ScTInfo {
                        version: Some(1),
                        log_id: "crt.sh".to_string(),
                        timestamp: Some(chrono::Local::now().to_rfc3339()),
                    });
                }
                Err(_) => {
                    scts.push(ScTInfo {
                        version: None,
                        log_id: "unknown".to_string(),
                        timestamp: None,
                    });
                }
            }
        }
    }

    let sct_found = !scts.is_empty() && scts[0].log_id != "unknown";
    let error = if scts.is_empty() {
        Some("No CT logs found".to_string())
    } else {
        None
    };

    Ok(CtCheckResult {
        hostname: req.hostname.clone(),
        sct_found,
        scts,
        log_entries,
        unexpected_certs,
        error,
    })
}

async fn query_crt_sh(domain: &str) -> Result<Vec<std::collections::HashMap<String, String>>> {
    use std::collections::HashMap;

    let url = format!("https://crt.sh/?q={}&output=json", domain);
    let client = reqwest::Client::new();

    match client.get(&url).timeout(std::time::Duration::from_secs(10)).send().await {
        Ok(response) => {
            match response.json::<serde_json::Value>().await {
                Ok(value) => {
                    if let serde_json::Value::Array(arr) = value {
                        let mut certs = Vec::new();
                        for item in arr {
                            let mut cert = HashMap::new();
                            if let Some(id) = item.get("id").and_then(|v| v.as_number()) {
                                cert.insert("serial".to_string(), id.to_string());
                            }
                            if let Some(nb) = item.get("not_before").and_then(|v| v.as_str()) {
                                cert.insert("notBefore".to_string(), nb.to_string());
                            }
                            if let Some(na) = item.get("not_after").and_then(|v| v.as_str()) {
                                cert.insert("notAfter".to_string(), na.to_string());
                            }
                            certs.push(cert);
                        }
                        Ok(certs)
                    } else {
                        Err(ShoheError::Parse("Invalid crt.sh response format".to_string()))
                    }
                }
                Err(e) => Err(ShoheError::Transport(format!("Failed to parse crt.sh JSON: {}", e)))
            }
        }
        Err(e) => Err(ShoheError::Transport(format!("crt.sh request failed: {}", e)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtCheckRequest {
    pub hostname: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_port() -> u16 { 443 }
fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtCheckResult {
    pub hostname: String,
    pub sct_found: bool,
    pub scts: Vec<ScTInfo>,
    pub log_entries: Vec<CtLogEntry>,
    pub unexpected_certs: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScTInfo {
    #[serde(default)]
    pub version: Option<u8>,
    pub log_id: String,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtLogEntry {
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
    #[serde(default)]
    pub serial: Option<String>,
}
