//! BIMI checker — verify Brand Indicators for Message Identification.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, check_email_security, DnsCheckRequest, EmailSecurityRequest};

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
        vmc_valid: None,  // TODO: validate VMC certificate if URL provided
        error,
    })
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
