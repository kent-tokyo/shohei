//! OCSP revocation status checker.

use serde::{Deserialize, Serialize};
use crate::error::{Result, ShoheError};
use crate::api::tls::{check_tls_chain, TlsCheckRequest};

/// Check OCSP revocation status for a certificate.
pub async fn check_ocsp(req: &OcspCheckRequest) -> Result<OcspCheckResult> {
    // Step 1: Get the certificate chain via TLS check
    let tls_req = TlsCheckRequest {
        hostname: req.hostname.clone(),
        port: req.port,
        check_dane: false,
        timeout_secs: req.timeout_secs,
    };

    let tls_result = check_tls_chain(&tls_req).await?;

    if !tls_result.connected || tls_result.chain.is_empty() {
        return Ok(OcspCheckResult {
            hostname: req.hostname.clone(),
            ocsp_responder_url: None,
            status: OcspStatus::Error("Failed to establish TLS connection".to_string()),
            this_update: None,
            next_update: None,
            error: Some("TLS connection failed".to_string()),
        });
    }

    // Step 2: Extract OCSP responder URL (would be from AIA extension)
    // For now, return placeholder — full implementation would parse cert
    let ocsp_responder_url = req.ocsp_responder_url.clone();

    let error_msg = if ocsp_responder_url.is_none() {
        Some("OCSP responder URL not found in certificate".to_string())
    } else {
        // In a real implementation, we would:
        // 1. Create OCSP request (leaf cert + issuer cert)
        // 2. POST to OCSP responder
        // 3. Parse OCSP response (ASN.1 DER)
        // 4. Extract revocation status
        None
    };

    Ok(OcspCheckResult {
        hostname: req.hostname.clone(),
        ocsp_responder_url,
        status: if error_msg.is_some() {
            OcspStatus::Error("OCSP check skipped".to_string())
        } else {
            OcspStatus::Unknown
        },
        this_update: None,
        next_update: None,
        error: error_msg,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspCheckRequest {
    pub hostname: String,
    pub port: u16,
    #[serde(default)]
    pub ocsp_responder_url: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspCheckResult {
    pub hostname: String,
    pub ocsp_responder_url: Option<String>,
    pub status: OcspStatus,
    pub this_update: Option<String>,
    pub next_update: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OcspStatus {
    Good,
    Revoked(RevokedInfo),
    Unknown,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedInfo {
    pub revoked_at: Option<String>,
    pub reason: Option<String>,
}
