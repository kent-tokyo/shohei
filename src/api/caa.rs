//! CAA record validator — verify certificate issuance authorization.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest};

/// Check CAA records for certificate issuance authorization.
pub async fn check_caa(req: &CaaCheckRequest) -> Result<CaaCheckResult> {
    let mut records = Vec::new();
    let mut authorized_cas = Vec::new();
    let mut wildcard_authorized = Vec::new();
    let mut caa_present = false;

    // Check domain and www.domain
    for domain_variant in &[req.domain.clone(), format!("www.{}", req.domain)] {
        let dns_req = DnsCheckRequest {
            domain: domain_variant.clone(),
            record_types: vec!["CAA".to_string()],
            timeout_secs: req.timeout_secs,
            ..Default::default()
        };

        if let Ok(dns_results) = check_dns(&dns_req).await {
            for result in dns_results {
                for record in &result.answers {
                    use crate::resolver::RecordData;
                    if let RecordData::Caa { flags, tag, value } = &record.data {
                        caa_present = true;
                        records.push(CaaRecord {
                            flags: *flags,
                            tag: tag.clone(),
                            value: value.clone(),
                        });

                        // Parse CA from value (e.g., "letsencrypt.org" or "ca.example.com")
                        if tag == "issue" {
                            authorized_cas.push(value.split_whitespace().next().unwrap_or("").to_string());
                        } else if tag == "issuewildcard" {
                            wildcard_authorized.push(value.split_whitespace().next().unwrap_or("").to_string());
                        }
                    }
                }
            }
        }
    }

    // Check compliance if issued_by_ca provided
    let compliance = if let Some(ref ca) = req.issued_by_ca {
        authorized_cas.iter().any(|auth_ca| auth_ca.contains(ca)) ||
        wildcard_authorized.iter().any(|wild_ca| wild_ca.contains(ca))
    } else {
        true  // No CA to check against
    };

    let mut issues = Vec::new();
    if caa_present {
        if authorized_cas.is_empty() && wildcard_authorized.is_empty() {
            issues.push("CAA records present but no CAs authorized".to_string());
        }
    }

    if let Some(ref ca) = req.issued_by_ca {
        if !compliance {
            issues.push(format!("CA {} is not authorized by CAA records", ca));
        }
    }

    Ok(CaaCheckResult {
        domain: req.domain.clone(),
        caa_present,
        records,
        authorized_cas,
        wildcard_authorized,
        compliance,
        issues,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaCheckRequest {
    pub domain: String,
    #[serde(default)]
    pub issued_by_ca: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaCheckResult {
    pub domain: String,
    pub caa_present: bool,
    pub records: Vec<CaaRecord>,
    pub authorized_cas: Vec<String>,
    pub wildcard_authorized: Vec<String>,
    pub compliance: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}
