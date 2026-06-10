//! Email security validator — check MX, SPF, DKIM, DMARC.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest};
use crate::resolver::RecordData;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

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
    let dmarc_valid = dmarc_policy.is_some() && dmarc_policy != Some(DmarcPolicy::None);

    // Parse SPF details
    let (spf_mechanisms, spf_lookup_count, spf_has_all) = if let Some(ref spf) = spf_raw {
        let (mechs, count, has_all) = parse_spf_record(spf);
        (Some(mechs), Some(count), Some(has_all))
    } else {
        (None, None, None)
    };

    // Parse DMARC details
    let (dmarc_rua, dmarc_ruf, dmarc_pct, dmarc_sp, dmarc_adkim, dmarc_aspf) = if let Some(ref dmarc) = dmarc_raw {
        let (rua, ruf, pct, sp, adkim, aspf) = parse_dmarc_record(dmarc);
        (Some(rua), Some(ruf), pct, sp, adkim, aspf)
    } else {
        (None, None, None, None, None, None)
    };

    let mut score: u8 = 0;
    if mx_valid { score += 25; }
    if spf_valid { score += 25; }
    if dmarc_policy != Some(DmarcPolicy::None) && dmarc_policy.is_some() { score += 25; }

    // Check DKIM selectors
    let mut dkim_results = Vec::new();
    let mut dkim_present_count = 0;
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

        if present { dkim_present_count += 1; }
        dkim_results.push(DkimCheckResult {
            selector: selector.clone(),
            present,
            raw,
        });
    }

    // Award DKIM points proportionally
    if dkim_present_count > 0 {
        score = score.saturating_add((25 * dkim_present_count as u8) / (req.dkim_selectors.len() as u8));
    }
    score = score.min(100);

    // Check MX reachability
    let mut mx_reachability = Vec::new();
    for mx in &mx_records {
        let dns_resolves = match check_dns(&DnsCheckRequest {
            domain: mx.exchange.clone(),
            record_types: vec!["A".to_string(), "AAAA".to_string()],
            timeout_secs: req.timeout_secs,
            ..Default::default()
        })
        .await
        {
            Ok(results) => !results.is_empty() && !results[0].answers.is_empty(),
            Err(_) => false,
        };

        // Test TCP port 25
        let tcp_port_25_open = if dns_resolves {
            check_mx_port_25(&mx.exchange, req.timeout_secs).await
        } else {
            false
        };

        mx_reachability.push(MxReachability {
            exchange: mx.exchange.clone(),
            dns_resolves,
            tcp_port_25_open,
        });
    }

    // Build SPF issues
    let mut spf_issues = Vec::new();
    if spf_valid {
        if let Some(count) = spf_lookup_count {
            if count > 10 {
                spf_issues.push(format!("SPF lookup count exceeds 10 limit ({} lookups)", count));
            }
        }
        if let Some(raw_spf) = &spf_raw {
            if raw_spf.contains("+all") {
                spf_issues.push("SPF +all allows any sender (critical)".to_string());
            } else if raw_spf.contains("~all") {
                spf_issues.push("SPF ~all softfail is not enforced".to_string());
            }
        }
    }

    // Build DMARC issues
    let mut dmarc_issues = Vec::new();
    if dmarc_policy == Some(DmarcPolicy::None) {
        dmarc_issues.push("DMARC p=none provides no protection".to_string());
    }
    if let Some(pct_val) = dmarc_pct {
        if pct_val < 100 {
            dmarc_issues.push(format!("DMARC pct={} applies to only {}% of messages", pct_val, pct_val));
        }
    }
    if dmarc_policy.is_some() && dmarc_rua.is_none() {
        dmarc_issues.push("No DMARC aggregate report URI configured".to_string());
    }

    Ok(EmailSecurityResult {
        domain: req.domain.clone(),
        mx: MxCheckResult { records: mx_records, valid: mx_valid },
        spf: SpfCheckResult {
            raw: spf_raw,
            valid: spf_valid,
            issues: spf_issues,
            mechanisms: spf_mechanisms,
            lookup_count: spf_lookup_count,
            has_all: spf_has_all,
        },
        dmarc: DmarcCheckResult {
            raw: dmarc_raw,
            policy: dmarc_policy,
            valid: dmarc_valid,
            issues: dmarc_issues,
            rua: dmarc_rua,
            ruf: dmarc_ruf,
            pct: dmarc_pct,
            sp: dmarc_sp,
            adkim: dmarc_adkim,
            aspf: dmarc_aspf,
        },
        dkim: dkim_results,
        mx_reachability: if mx_reachability.is_empty() { None } else { Some(mx_reachability) },
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

fn parse_spf_record(spf: &str) -> (Vec<String>, usize, bool) {
    let mut mechanisms = Vec::new();
    let mut lookup_count = 0;
    let mut has_all = false;

    for part in spf.split_whitespace() {
        if part.starts_with("+all") || part.starts_with("~all") || part.starts_with("-all") || part.starts_with("?all") {
            has_all = true;
        }

        if part.starts_with("ip4:") || part.starts_with("ip6:") || part.starts_with("include:")
            || part.starts_with("a:") || part.starts_with("mx:") || part.starts_with("ptr:")
            || part.starts_with("exists:") || part.starts_with("all") {
            mechanisms.push(part.to_string());
            if part.starts_with("include:") || part.starts_with("a:") || part.starts_with("mx:")
                || part.starts_with("ptr:") || part.starts_with("exists:") {
                lookup_count += 1;
            }
        }
    }

    (mechanisms, lookup_count, has_all)
}

fn parse_dmarc_record(dmarc: &str) -> (Vec<String>, Vec<String>, Option<u8>, Option<DmarcPolicy>, Option<String>, Option<String>) {
    let mut rua = Vec::new();
    let mut ruf = Vec::new();
    let mut pct = None;
    let mut sp = None;
    let mut adkim = None;
    let mut aspf = None;

    for part in dmarc.split(';') {
        let part = part.trim();
        if let Some(uri_part) = part.strip_prefix("rua=") {
            for uri in uri_part.split(',') {
                rua.push(uri.trim().to_string());
            }
        } else if let Some(uri_part) = part.strip_prefix("ruf=") {
            for uri in uri_part.split(',') {
                ruf.push(uri.trim().to_string());
            }
        } else if let Some(pct_str) = part.strip_prefix("pct=") {
            if let Ok(p) = pct_str.trim().parse::<u8>() {
                pct = Some(p);
            }
        } else if let Some(sp_str) = part.strip_prefix("sp=") {
            sp = match sp_str.trim() {
                "reject" => Some(DmarcPolicy::Reject),
                "quarantine" => Some(DmarcPolicy::Quarantine),
                "none" => Some(DmarcPolicy::None),
                _ => None,
            };
        } else if let Some(adkim_str) = part.strip_prefix("adkim=") {
            adkim = Some(adkim_str.trim().to_string());
        } else if let Some(aspf_str) = part.strip_prefix("aspf=") {
            aspf = Some(aspf_str.trim().to_string());
        }
    }

    (rua, ruf, pct, sp, adkim, aspf)
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
    #[serde(default)]
    pub mx_reachability: Option<Vec<MxReachability>>,
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
pub struct MxReachability {
    pub exchange: String,
    pub dns_resolves: bool,
    pub tcp_port_25_open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfCheckResult {
    pub raw: Option<String>,
    pub valid: bool,
    pub issues: Vec<String>,
    pub mechanisms: Option<Vec<String>>,  // NEW: extracted mechanisms (ip4, ip6, include, etc.)
    pub lookup_count: Option<usize>,       // NEW: DNS lookup count (RFC 4408 limit = 10)
    pub has_all: Option<bool>,             // NEW: has +all (accept-all) qualifier
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcCheckResult {
    pub raw: Option<String>,
    pub policy: Option<DmarcPolicy>,
    pub valid: bool,
    pub issues: Vec<String>,
    pub rua: Option<Vec<String>>,          // NEW: aggregate report URIs
    pub ruf: Option<Vec<String>>,          // NEW: forensic report URIs
    pub pct: Option<u8>,                   // NEW: percent of messages subject to policy (0-100)
    pub sp: Option<DmarcPolicy>,           // NEW: subdomain policy
    pub adkim: Option<String>,             // NEW: DKIM alignment (relaxed/strict)
    pub aspf: Option<String>,              // NEW: SPF alignment (relaxed/strict)
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

async fn check_mx_port_25(hostname: &str, timeout_secs: u64) -> bool {
    let addr = format!("{}:25", hostname);
    match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}
