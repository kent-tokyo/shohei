//! MTA-STS checker — verify SMTP TLS policy enforcement.

use serde::{Deserialize, Serialize};
use crate::error::{Result, ShoheError};
use crate::api::{check_dns, DnsCheckRequest};

/// Check MTA-STS policy for a domain.
pub async fn check_mta_sts(req: &MtaStsRequest) -> Result<MtaStsResult> {
    let mut txt_record_present = false;
    let mut txt_version = None;

    // Check _smtp._tls.{domain} TXT record
    let txt_req = DnsCheckRequest {
        domain: format!("_smtp._tls.{}", req.domain),
        record_types: vec!["TXT".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    if let Ok(txt_results) = check_dns(&txt_req).await {
        if let Some(result) = txt_results.first() {
            for record in &result.answers {
                if let crate::resolver::RecordData::Txt(texts) = &record.data {
                    for text in texts {
                        if text.starts_with("v=STSv1") {
                            txt_record_present = true;
                            if let Some(id_part) = text.split_whitespace().find(|p| p.starts_with("id=")) {
                                txt_version = Some(id_part[3..].to_string());
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    // Try to fetch the MTA-STS policy file
    let policy_url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt", domain = req.domain);
    if let Err(e) = crate::api::helpers::validate_url_safety(&policy_url) {
        return Ok(MtaStsResult {
            domain: req.domain.clone(),
            txt_record_present,
            txt_version,
            policy_url: Some(policy_url),
            policy: None,
            fetch_error: Some(format!("Policy URL blocked: {}", e)),
        });
    }
    let (policy, fetch_error) = match fetch_mta_sts_policy(&policy_url, req.timeout_secs).await {
        Ok(p) => (Some(p), None),
        Err(e) => (None, Some(e.to_string())),
    };

    Ok(MtaStsResult {
        domain: req.domain.clone(),
        txt_record_present,
        txt_version,
        policy_url: Some(policy_url),
        policy,
        fetch_error,
    })
}

async fn fetch_mta_sts_policy(url: &str, timeout_secs: u64) -> Result<MtaStsPolicy> {
    // RFC 8461 §3.3: MUST NOT follow HTTP redirects for MTA-STS policy fetch
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ShoheError::Transport(e.to_string()))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| ShoheError::Transport(format!("HTTP fetch failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(ShoheError::Transport(format!(
            "HTTP fetch failed: status {}",
            response.status()
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| ShoheError::Transport(format!("failed to read response: {}", e)))?;

    parse_mta_sts_policy(&body)
}

fn parse_mta_sts_policy(content: &str) -> Result<MtaStsPolicy> {
    let mut version = None;
    let mut mode = None;
    let mut mx = Vec::new();
    let mut max_age_seconds = 86400; // default 1 day

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(v) = line.strip_prefix("version:") {
            version = Some(v.trim().to_string());
        } else if let Some(m) = line.strip_prefix("mode:") {
            let mode_str = m.trim();
            mode = Some(match mode_str {
                "enforce" => MtaStsMode::Enforce,
                "testing" => MtaStsMode::Testing,
                "none" => MtaStsMode::None,
                _ => return Err(ShoheError::Parse(format!("unknown MTA-STS mode: {}", mode_str))),
            });
        } else if let Some(m) = line.strip_prefix("mx:") {
            mx.push(m.trim().to_string());
        } else if let Some(age) = line.strip_prefix("max_age:") {
            if let Ok(secs) = age.trim().parse::<u64>() {
                max_age_seconds = secs;
            }
        }
    }

    let version = version.ok_or_else(|| ShoheError::Parse("MTA-STS version not found".to_string()))?;
    let mode = mode.ok_or_else(|| ShoheError::Parse("MTA-STS mode not found".to_string()))?;

    if mx.is_empty() {
        return Err(ShoheError::Parse("MTA-STS mx records not found".to_string()));
    }

    Ok(MtaStsPolicy {
        version,
        mode,
        mx,
        max_age_seconds,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsResult {
    pub domain: String,
    pub txt_record_present: bool,
    pub txt_version: Option<String>,
    pub policy_url: Option<String>,
    pub policy: Option<MtaStsPolicy>,
    pub fetch_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsPolicy {
    pub version: String,
    pub mode: MtaStsMode,
    pub mx: Vec<String>,
    pub max_age_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MtaStsMode {
    Enforce,
    Testing,
    None,
}
