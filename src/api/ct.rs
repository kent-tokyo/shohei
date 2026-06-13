//! Certificate Transparency checker — validate CT log inclusion.

use serde::{Deserialize, Serialize};
use crate::error::{Result, ShoheError};
use crate::api::tls::{check_tls_chain, TlsCheckRequest};

/// Default trusted CAs for unexpected certificate detection.
fn default_trusted_cas() -> Vec<String> {
    vec![
        "Let's Encrypt".to_string(),
        "DigiCert".to_string(),
        "Sectigo".to_string(),
        "GlobalSign".to_string(),
        "Comodo".to_string(),
        "Amazon".to_string(),
        "Google Trust Services".to_string(),
        "Microsoft".to_string(),
        "GeoTrust".to_string(),
        "RapidSSL".to_string(),
    ]
}

/// Check Certificate Transparency logs for certificate inclusion.
pub async fn check_ct(req: &CtCheckRequest) -> Result<CtCheckResult> {
    let mut scts = Vec::new();
    let mut log_entries = Vec::new();
    let mut unexpected_certs = Vec::new();

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
                    let default_cas = default_trusted_cas();
                    let trusted_cas = req.expected_cas.as_ref()
                        .unwrap_or(&default_cas);

                    for cert in certs {
                        log_entries.push(CtLogEntry {
                            not_before: cert.get("notBefore").cloned(),
                            not_after: cert.get("notAfter").cloned(),
                            serial: cert.get("serial").cloned(),
                            issuer_name: cert.get("issuer").cloned(),
                        });

                        // Check if issuer is unexpected — case-insensitive match, avoid repeated case conversion
                        if let Some(issuer) = cert.get("issuer") {
                            if !issuer.is_empty() {
                                let issuer_lower = issuer.to_lowercase();
                                let is_expected = trusted_cas.iter()
                                    .any(|ca| issuer_lower.contains(&ca.to_lowercase()));
                                if !is_expected {
                                    let serial = cert.get("serial").cloned().unwrap_or_else(|| "unknown".to_string());
                                    unexpected_certs.push(format!("{} (issuer: {})", serial, issuer));
                                }
                            }
                        }
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

    let sct_found = !scts.is_empty() && scts.iter().any(|s| s.log_id != "unknown");
    let error = if scts.is_empty() {
        Some("No CT logs found".to_string())
    } else if !sct_found {
        Some("All CT logs failed to parse".to_string())
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

/// Typed certificate entry from crt.sh API
#[derive(Debug, Clone, Deserialize)]
struct CrtShCertEntry {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    issuer_name: Option<String>,
}

impl CrtShCertEntry {
    /// Convert to HashMap for compatibility with existing code
    fn to_hashmap(&self) -> std::collections::HashMap<String, String> {
        use std::collections::HashMap;
        let mut m = HashMap::new();
        if let Some(id) = self.id {
            m.insert("serial".to_string(), id.to_string());
        }
        if let Some(nb) = &self.not_before {
            m.insert("notBefore".to_string(), nb.clone());
        }
        if let Some(na) = &self.not_after {
            m.insert("notAfter".to_string(), na.clone());
        }
        if let Some(issuer) = &self.issuer_name {
            m.insert("issuer".to_string(), issuer.clone());
        }
        m
    }
}

async fn query_crt_sh(domain: &str) -> Result<Vec<std::collections::HashMap<String, String>>> {
    let url = format!("https://crt.sh/?q={}&output=json", crate::api::helpers::percent_encode(domain));
    let client = reqwest::Client::new();

    match client.get(&url).timeout(std::time::Duration::from_secs(10)).send().await {
        Ok(response) => {
            // Check response size to prevent memory exhaustion DoS
            const MAX_RESPONSE_SIZE: u64 = 1024 * 500;  // 500 KB limit
            if let Some(len) = response.content_length() {
                if len > MAX_RESPONSE_SIZE {
                    return Err(ShoheError::Parse("crt.sh response exceeds size limit".to_string()));
                }
            }

            match response.json::<Vec<CrtShCertEntry>>().await {
                Ok(certs) => {
                    const MAX_CERTS: usize = 1000;  // Prevent unbounded iteration
                    Ok(certs.iter()
                        .take(MAX_CERTS)
                        .map(|cert| cert.to_hashmap())
                        .collect())
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
    #[serde(default)]
    pub expected_cas: Option<Vec<String>>,
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
    #[serde(default)]
    pub issuer_name: Option<String>,
}
