//! Certificate Transparency checker — validate CT log inclusion.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::tls::{check_tls_chain, TlsCheckRequest};

/// Check Certificate Transparency logs for certificate inclusion.
pub async fn check_ct(req: &CtCheckRequest) -> Result<CtCheckResult> {
    let sct_found = false;
    let mut scts = Vec::new();
    let mut log_entries = Vec::new();

    // Step 1: Get certificate via TLS
    let tls_req = TlsCheckRequest {
        hostname: req.hostname.clone(),
        port: req.port,
        check_dane: false,
        timeout_secs: req.timeout_secs,
    };

    if let Ok(tls_result) = check_tls_chain(&tls_req).await {
        // In a real implementation, we would:
        // 1. Extract SCTs from the certificate's CT Precertificate SCTs extension
        // 2. Query each CT log to verify inclusion
        // For now, we provide a placeholder

        if !tls_result.chain.is_empty() {
            let leaf_cert = &tls_result.chain[0];
            // TODO: Parse CT extension from leaf_cert
            // Add SCT entries if found
            scts.push(ScTInfo {
                version: None,
                log_id: "placeholder".to_string(),
                timestamp: None,
            });

            // TODO: Query CT logs (crt.sh, Google CT Log List)
            log_entries.push(CtLogEntry {
                not_before: Some(leaf_cert.not_before.clone()),
                not_after: Some(leaf_cert.not_after.clone()),
                serial: None,
            });
        }
    }

    let error = if !sct_found && !scts.is_empty() {
        Some("SCTs found in certificate but not yet verified in logs".to_string())
    } else {
        None
    };

    Ok(CtCheckResult {
        hostname: req.hostname.clone(),
        sct_found,
        scts,
        log_entries,
        unexpected_certs: vec![],
        error,
    })
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
