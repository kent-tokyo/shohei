//! WHOIS / RDAP domain registration information checker.

use serde::{Deserialize, Serialize};
use crate::error::{Result, ShoheError};

/// Check domain registration details via RDAP API.
pub async fn check_whois(req: &WhoisCheckRequest) -> Result<WhoisCheckResult> {
    // Use RDAP (RFC 7480) instead of legacy WHOIS protocol
    let rdap_url = format!("https://rdap.iana.org/domain/{}", req.domain);

    let client = reqwest::Client::new();
    let response = client
        .get(&rdap_url)
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .send()
        .await
        .map_err(|e| ShoheError::Transport(format!("RDAP request failed: {}", e)))?;

    if !response.status().is_success() {
        return Ok(WhoisCheckResult {
            domain: req.domain.clone(),
            registrar: None,
            created_date: None,
            updated_date: None,
            expiration_date: None,
            nameservers: vec![],
            dnssec_signed: None,
            days_until_expiry: None,
            expiry_warning: false,
            status: "not_found".to_string(),
            error: Some(format!("RDAP lookup failed with status {}", response.status())),
        });
    }

    match response.json::<serde_json::Value>().await {
        Ok(rdap_data) => parse_rdap_response(&req.domain, &rdap_data),
        Err(e) => {
            Ok(WhoisCheckResult {
                domain: req.domain.clone(),
                registrar: None,
                created_date: None,
                updated_date: None,
                expiration_date: None,
                nameservers: vec![],
                dnssec_signed: None,
                days_until_expiry: None,
                expiry_warning: false,
                status: "error".to_string(),
                error: Some(format!("Failed to parse RDAP response: {}", e)),
            })
        }
    }
}

fn parse_rdap_response(domain: &str, rdap_data: &serde_json::Value) -> Result<WhoisCheckResult> {
    let mut registrar = None;
    let mut created_date = None;
    let mut updated_date = None;
    let mut expiration_date = None;
    let mut nameservers = Vec::new();
    let mut dnssec_signed = None;

    // Extract registrar from entities
    if let Some(entities) = rdap_data.get("entities").and_then(|e| e.as_array()) {
        for entity in entities {
            if let Some(roles) = entity.get("roles").and_then(|r| r.as_array()) {
                if roles.iter().any(|r| r.as_str() == Some("registrar")) {
                    if let Some(org_name) = entity
                        .get("vcardArray")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.get(1))
                        .and_then(|v| v.as_array())
                        .and_then(|arr| {
                            arr.iter()
                                .find(|item| {
                                    item.as_array()
                                        .and_then(|a| a.get(0))
                                        .and_then(|v| v.as_str())
                                        == Some("fn")
                                })
                                .and_then(|item| item.as_array())
                                .and_then(|a| a.get(3))
                        })
                        .and_then(|v| v.as_str())
                    {
                        registrar = Some(org_name.to_string());
                        break;
                    }
                }
            }
        }
    }

    // Extract important dates
    if let Some(events) = rdap_data.get("events").and_then(|e| e.as_array()) {
        for event in events {
            if let Some(event_action) = event.get("eventAction").and_then(|a| a.as_str()) {
                if let Some(event_date) = event.get("eventDate").and_then(|d| d.as_str()) {
                    match event_action {
                        "registration" => created_date = Some(event_date.to_string()),
                        "last changed" | "last update" => updated_date = Some(event_date.to_string()),
                        "expiration" => expiration_date = Some(event_date.to_string()),
                        _ => {}
                    }
                }
            }
        }
    }

    // Extract nameservers
    if let Some(nameserver_refs) = rdap_data.get("nameservers").and_then(|n| n.as_array()) {
        for ns_ref in nameserver_refs {
            if let Some(ns_name) = ns_ref.get("ldhName").and_then(|n| n.as_str()) {
                nameservers.push(ns_name.to_string());
            }
        }
    }

    // Check DNSSEC status from secureDNS object (RFC 7480)
    if let Some(secure_dns) = rdap_data.get("secureDNS").and_then(|s| s.as_object()) {
        if let Some(zone_signed) = secure_dns.get("zoneSigned").and_then(|v| v.as_bool()) {
            dnssec_signed = Some(zone_signed);
        } else if let Some(delegation_signed) = secure_dns.get("delegationSigned").and_then(|v| v.as_bool()) {
            dnssec_signed = Some(delegation_signed);
        }
    }

    // Calculate days until expiry
    let (days_until_expiry, expiry_warning) = if let Some(exp_date_str) = &expiration_date {
        if let Some(exp_secs) = parse_date_secs(exp_date_str) {
            let now_secs = crate::api::helpers::now_timestamp();
            let days = (exp_secs as i64 - now_secs as i64) / 86400;
            let warning = days < 30 && days > 0;
            (Some(days), warning)
        } else {
            (None, false)
        }
    } else {
        (None, false)
    };

    Ok(WhoisCheckResult {
        domain: domain.to_string(),
        registrar,
        created_date,
        updated_date,
        expiration_date,
        nameservers,
        dnssec_signed,
        days_until_expiry,
        expiry_warning,
        status: "success".to_string(),
        error: None,
    })
}

fn parse_date_secs(date_str: &str) -> Option<u64> {
    // Try RFC 3339 (e.g. "2024-12-31T23:59:59Z")
    crate::api::helpers::parse_rfc3339_secs(date_str)
        .or_else(|| {
            // Try "%Y-%m-%dT%H:%M:%S" without timezone
            crate::api::helpers::parse_naive_datetime_secs(date_str)
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisCheckRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisCheckResult {
    pub domain: String,
    pub registrar: Option<String>,
    pub created_date: Option<String>,
    pub updated_date: Option<String>,
    pub expiration_date: Option<String>,
    pub nameservers: Vec<String>,
    pub dnssec_signed: Option<bool>,
    #[serde(default)]
    pub days_until_expiry: Option<i64>,
    #[serde(default)]
    pub expiry_warning: bool,
    pub status: String,
    pub error: Option<String>,
}
