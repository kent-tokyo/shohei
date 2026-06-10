//! Email security validator — check MX, SPF, DKIM, DMARC.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest};
use crate::resolver::RecordData;

/// Check email security configuration for a domain.
pub async fn check_email_security(req: &EmailSecurityRequest) -> Result<EmailSecurityResult> {
    let dns_req = DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["MX".to_string(), "TXT".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };
    let dns_results = check_dns(&dns_req).await?;

    let mut mx_records = Vec::new();
    let mut spf_raw = None;
    let mut dmarc_raw = None;

    // Parse MX and TXT from results
    for result in &dns_results {
        if result.query.record_type == "MX" {
            for record in &result.answers {
                if let RecordData::Mx { priority, exchange } = &record.data {
                    mx_records.push(MxEntry { priority: *priority, exchange: exchange.clone() });
                }
            }
        } else if result.query.record_type == "TXT" {
            for record in &result.answers {
                if let RecordData::Txt(texts) = &record.data {
                    for text in texts {
                        if text.starts_with("v=spf1") {
                            spf_raw = Some(text.clone());
                        } else if text.starts_with("v=DMARC1") {
                            dmarc_raw = Some(text.clone());
                        }
                    }
                }
            }
        }
    }

    // Check DMARC at _dmarc.domain
    let dmarc_req = DnsCheckRequest {
        domain: format!("_dmarc.{}", req.domain),
        record_types: vec!["TXT".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };
    if let Ok(dmarc_results) = check_dns(&dmarc_req).await {
        if let Some(result) = dmarc_results.first() {
            for record in &result.answers {
                if let RecordData::Txt(texts) = &record.data {
                    for text in texts {
                        if text.starts_with("v=DMARC1") {
                            dmarc_raw = Some(text.clone());
                        }
                    }
                }
            }
        }
    }

    let mx_valid = !mx_records.is_empty();
    let spf_valid = spf_raw.is_some();
    let dmarc_policy = parse_dmarc_policy(&dmarc_raw);
    let dmarc_valid = dmarc_policy.is_some();

    let mut score: u8 = 0;
    if mx_valid { score += 25; }
    if spf_valid { score += 25; }
    if dmarc_policy != Some(DmarcPolicy::None) && dmarc_policy.is_some() { score += 25; }

    // Check DKIM selectors
    let mut dkim_results = Vec::new();
    for selector in &req.dkim_selectors {
        let dkim_req = DnsCheckRequest {
            domain: format!("{}._domainkey.{}", selector, req.domain),
            record_types: vec!["TXT".to_string()],
            timeout_secs: req.timeout_secs,
            ..Default::default()
        };
        let (present, raw) = match check_dns(&dkim_req).await {
            Ok(results) if !results.is_empty() && !results[0].answers.is_empty() => {
                let mut txt_value = None;
                for record in &results[0].answers {
                    if let RecordData::Txt(texts) = &record.data {
                        if let Some(text) = texts.first() {
                            txt_value = Some(text.clone());
                            break;
                        }
                    }
                }
                (true, txt_value)
            }
            _ => (false, None),
        };

        if present { score += 6; } // 25/4 selectors
        dkim_results.push(DkimCheckResult {
            selector: selector.clone(),
            present,
            raw,
        });
    }
    score = score.min(100);

    Ok(EmailSecurityResult {
        domain: req.domain.clone(),
        mx: MxCheckResult { records: mx_records, valid: mx_valid },
        spf: SpfCheckResult { raw: spf_raw, valid: spf_valid, issues: vec![] },
        dmarc: DmarcCheckResult { raw: dmarc_raw, policy: dmarc_policy, valid: dmarc_valid, issues: vec![] },
        dkim: dkim_results,
        score,
    })
}

fn parse_dmarc_policy(raw: &Option<String>) -> Option<DmarcPolicy> {
    raw.as_ref().and_then(|s| {
        if s.contains("p=reject") {
            Some(DmarcPolicy::Reject)
        } else if s.contains("p=quarantine") {
            Some(DmarcPolicy::Quarantine)
        } else if s.contains("p=none") {
            Some(DmarcPolicy::None)
        } else {
            None
        }
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSecurityRequest {
    pub domain: String,
    pub timeout_secs: u64,
    #[serde(default = "default_dkim_selectors")]
    pub dkim_selectors: Vec<String>,
}

fn default_dkim_selectors() -> Vec<String> {
    vec!["default".to_string(), "google".to_string(), "selector1".to_string(), "selector2".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSecurityResult {
    pub domain: String,
    pub mx: MxCheckResult,
    pub spf: SpfCheckResult,
    pub dmarc: DmarcCheckResult,
    pub dkim: Vec<DkimCheckResult>,
    pub score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxCheckResult {
    pub records: Vec<MxEntry>,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxEntry {
    pub priority: u16,
    pub exchange: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfCheckResult {
    pub raw: Option<String>,
    pub valid: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcCheckResult {
    pub raw: Option<String>,
    pub policy: Option<DmarcPolicy>,
    pub valid: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimCheckResult {
    pub selector: String,
    pub present: bool,
    pub raw: Option<String>,
}
