//! BIMI checker — verify Brand Indicators for Message Identification.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, check_email_security, DnsCheckRequest, EmailSecurityRequest};
use std::time::SystemTime;

/// Check BIMI (Brand Indicators for Message Identification) configuration.
pub async fn check_bimi(req: &BimiCheckRequest) -> Result<BimiCheckResult> {
    let mut bimi_present = false;
    let mut version = None;
    let mut vmc_url = None;

    // Check default._bimi.{domain} TXT record
    let bimi_domain = format!("default._bimi.{}", req.domain);
    let dns_req = DnsCheckRequest {
        domain: bimi_domain,
        record_types: vec!["TXT".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    if let Ok(dns_results) = check_dns(&dns_req).await {
        for result in dns_results {
            for record in &result.answers {
                use crate::resolver::RecordData;
                if let RecordData::Txt(texts) = &record.data {
                    for text in texts {
                        if text.starts_with("v=BIMI1") {
                            bimi_present = true;
                            version = Some("BIMI1".to_string());

                            // Extract VMC URL (l= parameter)
                            for part in text.split(';') {
                                let part = part.trim();
                                if let Some(url) = part.strip_prefix("l=") {
                                    vmc_url = Some(url.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check DMARC alignment (required for BIMI)
    let email_req = EmailSecurityRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
        dkim_selectors: vec![],
    };
    let dmarc_aligned = if let Ok(email_result) = check_email_security(&email_req).await {
        // DMARC p=reject or p=quarantine required for BIMI
        Some(matches!(
            email_result.dmarc.policy,
            Some(crate::api::email::DmarcPolicy::Reject) | Some(crate::api::email::DmarcPolicy::Quarantine)
        ))
    } else {
        None
    };

    // Validate VMC certificate if URL is provided
    let vmc_valid = if let Some(ref url) = vmc_url {
        validate_vmc_certificate(url).await.ok()
    } else {
        None
    };

    let error = if bimi_present && dmarc_aligned == Some(false) {
        Some("BIMI present but DMARC policy is not reject/quarantine".to_string())
    } else {
        None
    };

    Ok(BimiCheckResult {
        domain: req.domain.clone(),
        bimi_present,
        version,
        vmc_url,
        dmarc_aligned,
        vmc_valid,
        error,
    })
}

const MAX_VMC_SIZE: u64 = 64 * 1024; // 64 KB is sufficient for any certificate

async fn validate_vmc_certificate(url: &str) -> Result<bool> {
    crate::api::helpers::validate_url_safety(url)
        .map_err(|e| crate::error::ShoheError::Parse(format!("Unsafe VMC URL: {}", e)))?;
    // Fetch the VMC from the URL
    let client = reqwest::Client::new();
    let response = client.get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| crate::error::ShoheError::Transport(format!("VMC fetch failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(crate::error::ShoheError::Transport(format!("VMC fetch returned {}", response.status())));
    }

    if let Some(len) = response.content_length() {
        if len > MAX_VMC_SIZE {
            return Err(crate::error::ShoheError::Parse("VMC response too large".to_string()));
        }
    }

    let cert_bytes = response.bytes()
        .await
        .map_err(|e| crate::error::ShoheError::Transport(format!("VMC read failed: {}", e)))?;

    // Try parsing as DER first, then as PEM
    let cert_der = if cert_bytes.starts_with(b"-----BEGIN") {
        // PEM format
        let pem_str = String::from_utf8(cert_bytes.to_vec())
            .map_err(|_| crate::error::ShoheError::Parse("Invalid UTF-8 in PEM".to_string()))?;
        parse_pem_cert(&pem_str)?
    } else {
        // DER format
        cert_bytes.to_vec()
    };

    // Parse certificate
    let (_, cert) = x509_parser::prelude::parse_x509_certificate(&cert_der)
        .map_err(|e| crate::error::ShoheError::Parse(format!("Certificate parse failed: {}", e)))?;

    // Check validity period
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let not_before = cert.validity.not_before.timestamp() as u64;
    let not_after = cert.validity.not_after.timestamp() as u64;

    // VMC is valid if within its validity period
    Ok(now >= not_before && now <= not_after)
}

fn parse_pem_cert(pem_str: &str) -> Result<Vec<u8>> {
    let lines: Vec<&str> = pem_str.lines().collect();
    let mut cert_data = String::new();

    let mut in_cert = false;
    for line in lines {
        if line.contains("-----BEGIN") {
            in_cert = true;
            continue;
        }
        if line.contains("-----END") {
            break;
        }
        if in_cert {
            cert_data.push_str(line);
        }
    }

    base64_decode(&cert_data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>> {
    // Simple base64 decode without external deps
    const TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let data = data.trim();
    let mut result = Vec::new();
    let bytes: Vec<u8> = data.as_bytes().to_vec();

    let mut i = 0;
    while i < bytes.len() {
        let mut chunk = 0u32;
        let mut bits = 0;

        for _ in 0..4 {
            if i >= bytes.len() {
                break;
            }
            let c = bytes[i];
            i += 1;

            if c == b'=' {
                break;
            }

            let val = if let Some(pos) = TABLE.find(c as char) {
                pos as u32
            } else {
                continue;
            };

            chunk = (chunk << 6) | val;
            bits += 6;
        }

        if bits >= 8 {
            chunk <<= 24 - bits;
            for _ in 0..bits / 8 {
                result.push((chunk >> 16) as u8);
                chunk <<= 8;
            }
        }
    }

    Ok(result)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BimiCheckRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BimiCheckResult {
    pub domain: String,
    pub bimi_present: bool,
    pub version: Option<String>,
    pub vmc_url: Option<String>,
    #[serde(default)]
    pub dmarc_aligned: Option<bool>,
    #[serde(default)]
    pub vmc_valid: Option<bool>,
    #[serde(default)]
    pub error: Option<String>,
}
