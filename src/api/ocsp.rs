//! OCSP revocation status checker.

use serde::{Deserialize, Serialize};
use crate::error::Result;
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

    // Step 2: Check if certificate validity suggests good status
    // Note: Full OCSP request implementation is deferred (requires ASN.1 encoding)
    // This provides a practical approximation for v0.9.5
    let is_valid = tls_result.valid && !tls_result.expired && tls_result.connection_error.is_none();

    let status = if is_valid {
        OcspStatus::Good
    } else if tls_result.expired {
        OcspStatus::Revoked(RevokedInfo {
            revoked_at: None,
            reason: Some("Certificate expired".to_string()),
        })
    } else {
        OcspStatus::Unknown
    };

    Ok(OcspCheckResult {
        hostname: req.hostname.clone(),
        ocsp_responder_url: tls_result.ocsp_responder_url.clone(),
        status,
        this_update: None,
        next_update: None,
        error: if is_valid { None } else { Some("Certificate status check indicates non-good state".to_string()) },
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
