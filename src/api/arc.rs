//! ARC (Authenticated Received Chain) checker — email authentication.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Check ARC (Authenticated Received Chain) policy for a domain.
pub async fn check_arc(req: &ArcCheckRequest) -> Result<ArcCheckResult> {
    let domain = &req.domain;

    // ARC records are TXT records at _arc.<n>.domain (n=1,2,3...)
    // We check for the presence of ARC seals and authorization records

    let mut arc_seals = Vec::new();
    let arc_aars = Vec::new();

    // Check for ARC-Seal and ARC-Authentication-Results records
    for i in 1..=5 {
        // Query _arc<i>._domainkey.<domain>
        let seal_domain = format!("_arc{}.{}", i, domain);
        let _aar_domain = format!("_dmarc.{}", domain);  // ARC uses DMARC authentication

        let dns_req = crate::api::DnsCheckRequest {
            domain: seal_domain.clone(),
            record_types: vec!["TXT".to_string()],
            timeout_secs: req.timeout_secs,
            ..Default::default()
        };

        if let Ok(results) = crate::api::check_dns(&dns_req).await {
            for result in results {
                for record in &result.answers {
                    if let crate::api::RecordData::Txt(txt_data) = &record.data {
                        let txt_value = txt_data.join("");
                        if txt_value.contains("v=ARC1") {
                            arc_seals.push(ArcRecord {
                                index: i,
                                record_type: "seal".to_string(),
                                value: Some(txt_value),
                                valid: true,
                            });
                        }
                    }
                }
            }
        }
    }

    // Note: Full ARC validation requires:
    // 1. Parsing email headers (not available from domain-only check)
    // 2. Cryptographic signature verification
    // 3. DKIM/SPF/DMARC chain validation
    // This is a simplified domain-level check only

    let arc_present = !arc_seals.is_empty();
    let arc_status = if arc_present {
        "present".to_string()
    } else {
        "not-configured".to_string()
    };

    Ok(ArcCheckResult {
        domain: domain.clone(),
        arc_present,
        arc_status,
        seals: arc_seals,
        aars: arc_aars,
        note: Some(
            "ARC validation requires email message headers. Domain-level check only \
             verifies DNS record presence, not actual email chain authentication.".to_string()
        ),
        error: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcCheckRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcCheckResult {
    pub domain: String,
    pub arc_present: bool,
    /// "present", "not-configured"
    pub arc_status: String,
    pub seals: Vec<ArcRecord>,
    pub aars: Vec<ArcRecord>,
    pub note: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcRecord {
    pub index: usize,
    pub record_type: String,  // "seal" or "aar"
    pub value: Option<String>,
    pub valid: bool,
}
