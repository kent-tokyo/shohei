//! Domain registration risk assessment — identify phishing and squatting indicators.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to assess domain registration risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRiskRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// Domain registration risk assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRiskResult {
    pub domain: String,
    /// "high" | "medium" | "low" | "unknown"
    pub risk_level: String,
    /// Days since registration (negative = not yet registered)
    pub domain_age_days: Option<i64>,
    /// Days until expiry (negative = expired)
    pub days_until_expiry: Option<i64>,
    /// Risk signals: "newly_registered", "recently_registered", "expired", "expiring_soon"
    pub risk_signals: Vec<String>,
    /// Domain registrar
    pub registrar: Option<String>,
    /// WHOIS lookup error (if any)
    pub whois_error: Option<String>,
}

/// Evaluate domain registration risk for phishing and squatting.
pub async fn check_domain_risk(req: &DomainRiskRequest) -> Result<DomainRiskResult> {
    let domain = req.domain.clone();
    let timeout_secs = req.timeout_secs;

    // Get WHOIS data
    let whois_req = crate::api::WhoisCheckRequest {
        domain: domain.clone(),
        timeout_secs,
    };

    let whois_result = match crate::api::check_whois(&whois_req).await {
        Ok(result) => result,
        Err(e) => {
            return Ok(DomainRiskResult {
                domain,
                risk_level: "unknown".to_string(),
                domain_age_days: None,
                days_until_expiry: None,
                risk_signals: vec![],
                registrar: None,
                whois_error: Some(format!("{}", e)),
            });
        }
    };

    let mut risk_signals = Vec::new();
    let mut domain_age_days: Option<i64> = None;
    let mut days_until_expiry: Option<i64> = None;

    // Calculate domain age if created_date is available
    if let Some(created_str) = &whois_result.created_date {
        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(created_str) {
            let now = chrono::Utc::now();
            let created_utc = created.with_timezone(&chrono::Utc);
            let age_duration = now.signed_duration_since(created_utc);
            domain_age_days = Some(age_duration.num_days());

            if domain_age_days.unwrap_or(0) < 30 {
                risk_signals.push("newly_registered".to_string());
            } else if domain_age_days.unwrap_or(0) < 90 {
                risk_signals.push("recently_registered".to_string());
            }
        }
    }

    // Calculate days until expiry if expiration_date is available
    if let Some(expiry_str) = &whois_result.expiration_date {
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expiry_str) {
            let now = chrono::Utc::now();
            let expiry_utc = expiry.with_timezone(&chrono::Utc);
            let ttl_duration = expiry_utc.signed_duration_since(now);
            days_until_expiry = Some(ttl_duration.num_days());

            if days_until_expiry.unwrap_or(0) < 0 {
                risk_signals.push("expired".to_string());
            } else if days_until_expiry.unwrap_or(0) < 30 {
                risk_signals.push("expiring_soon".to_string());
            }
        }
    }

    // Determine risk level based on signal count
    let risk_level = if risk_signals.len() >= 2 {
        "high".to_string()
    } else if risk_signals.len() == 1 {
        "medium".to_string()
    } else {
        "low".to_string()
    };

    Ok(DomainRiskResult {
        domain,
        risk_level,
        domain_age_days,
        days_until_expiry,
        risk_signals,
        registrar: whois_result.registrar,
        whois_error: whois_result.error,
    })
}
