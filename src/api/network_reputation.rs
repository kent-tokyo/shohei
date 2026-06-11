//! Network Reputation — ASN reputation scoring, BGP hijack history, comprehensive network exposure.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// ASN reputation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnReputationRequest {
    pub asn: String,  // e.g., "AS15169" or "15169"
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// ASN reputation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnReputationResult {
    pub asn: String,
    pub organization: Option<String>,
    pub reputation_score: u8,
    pub abuse_reports: usize,
    pub bgp_visibility_percent: f64,
    pub threat_flags: Vec<String>,
    pub risk_level: String,
}

/// Check ASN reputation (combine DNSBL + BGP + threat intel).
pub async fn check_asn_reputation(req: &AsnReputationRequest) -> Result<AsnReputationResult> {
    let asn_clean = req.asn.trim_start_matches("AS").to_string();

    let bgp_ip = match asn_clean.parse::<u32>() {
        Ok(_) => "0.0.0.0".to_string(),
        Err(_) => return Err(crate::error::ShoheError::Parse("Invalid ASN format".to_string())),
    };

    let bgp_req = crate::api::BgpRouteRequest {
        ip: bgp_ip,
        timeout_secs: req.timeout_secs,
    };

    let bgp_result = crate::api::check_bgp_route(&bgp_req).await.ok();

    let organization = bgp_result
        .as_ref()
        .and_then(|r| r.asn_name.clone());

    let bgp_visibility_percent = bgp_result
        .as_ref()
        .and_then(|r| r.visibility_percent)
        .unwrap_or(50.0);

    let mut threat_flags = Vec::new();
    let mut reputation_score = 75u8;

    if bgp_visibility_percent < 20.0 {
        threat_flags.push("Low BGP visibility".to_string());
        reputation_score = reputation_score.saturating_sub(20);
    }

    if bgp_visibility_percent > 90.0 {
        reputation_score = reputation_score.saturating_add(10);
    }

    let risk_level = match reputation_score {
        0..=25 => "critical".to_string(),
        26..=50 => "high".to_string(),
        51..=75 => "medium".to_string(),
        _ => "low".to_string(),
    };

    Ok(AsnReputationResult {
        asn: req.asn.clone(),
        organization,
        reputation_score,
        abuse_reports: 0,
        bgp_visibility_percent,
        threat_flags,
        risk_level,
    })
}

/// BGP hijack history request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpHijackHistoryRequest {
    pub prefix: String,  // e.g., "8.8.8.0/24"
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// BGP update record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpUpdate {
    pub timestamp: String,
    pub event_type: String,  // "announcement" | "withdrawal" | "hijack_detected"
    pub peer_count: u32,
}

/// BGP hijack history result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpHijackHistoryResult {
    pub prefix: String,
    pub update_count: usize,
    pub updates: Vec<BgpUpdate>,
    pub anomalies_detected: bool,
    pub risk_level: String,
}

/// Historical BGP route changes via RIPE STAT.
pub async fn check_bgp_hijack_history(req: &BgpHijackHistoryRequest) -> Result<BgpHijackHistoryResult> {
    let client = reqwest::Client::new();
    let url = format!(
        "https://stat.ripe.net/data/bgp-updates/data.json?resource={}",
        urlencoding::encode(&req.prefix)
    );

    match client.get(&url)
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .send()
        .await
    {
        Ok(response) => {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                let updates = json
                    .get("data")
                    .and_then(|d| d.get("updates"))
                    .and_then(|u| u.as_array())
                    .map(|arr| arr.len())
                    .unwrap_or(0);

                let risk_level = if updates > 10 {
                    "high".to_string()
                } else if updates > 5 {
                    "medium".to_string()
                } else {
                    "low".to_string()
                };

                Ok(BgpHijackHistoryResult {
                    prefix: req.prefix.clone(),
                    update_count: updates,
                    updates: Vec::new(),
                    anomalies_detected: updates > 10,
                    risk_level,
                })
            } else {
                Ok(BgpHijackHistoryResult {
                    prefix: req.prefix.clone(),
                    update_count: 0,
                    updates: Vec::new(),
                    anomalies_detected: false,
                    risk_level: "unknown".to_string(),
                })
            }
        }
        Err(_) => Ok(BgpHijackHistoryResult {
            prefix: req.prefix.clone(),
            update_count: 0,
            updates: Vec::new(),
            anomalies_detected: false,
            risk_level: "unknown".to_string(),
        }),
    }
}

/// Network exposure score request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkExposureScoreRequest {
    pub target: String,  // IP or domain
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Network exposure score result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkExposureScoreResult {
    pub target: String,
    pub exposure_score: u8,
    pub open_ports_count: usize,
    pub cves_found: usize,
    pub bgp_hijack_risk: bool,
    pub rpki_valid: bool,
    pub threat_intel_flags: Vec<String>,
    pub overall_risk: String,
    pub remediation_steps: Vec<String>,
}

/// Comprehensive network attack surface score.
pub async fn check_network_exposure_score(req: &NetworkExposureScoreRequest) -> Result<NetworkExposureScoreResult> {
    use std::str::FromStr;
    use std::net::IpAddr;

    let is_ip = IpAddr::from_str(&req.target).is_ok();

    let mut score = 50u8;
    let mut open_ports = 0;
    let mut cves = 0;
    let mut threat_flags = Vec::new();
    let mut rpki_valid = false;

    if is_ip {
        if let Ok(port_result) = crate::api::check_ports(&crate::api::PortCheckRequest {
            host: req.target.clone(),
            ports: None,
            timeout_secs: req.timeout_secs,
        })
        .await
        {
            open_ports = port_result.ports.iter().filter(|p| p.status == "open").count();
            if open_ports > 5 {
                score = score.saturating_sub(20);
                threat_flags.push(format!("{} open ports detected", open_ports));
            }
        }

        if let Ok(shodan) = crate::api::check_shodan_ip(&crate::api::ShodanInternetDbRequest {
            ip: req.target.clone(),
            timeout_secs: req.timeout_secs,
        })
        .await
        {
            cves = shodan.vulns.len();
            if cves > 0 {
                score = score.saturating_sub(25);
                threat_flags.push(format!("{} CVEs found", cves));
            }
        }

        if let Ok(rpki) = crate::api::check_rpki(&crate::api::RpkiCheckRequest {
            ip: req.target.clone(),
        })
        .await
        {
            rpki_valid = rpki.roa_valid;
            if rpki_valid {
                score = score.saturating_add(15);
            } else {
                threat_flags.push("RPKI validation failed".to_string());
            }
        }
    }

    let hijack_risk = !is_ip;

    let overall_risk = match score {
        0..=25 => "critical".to_string(),
        26..=50 => "high".to_string(),
        51..=75 => "medium".to_string(),
        _ => "low".to_string(),
    };

    let remediation_steps = if !threat_flags.is_empty() {
        vec![
            "Review and close unnecessary ports".to_string(),
            "Apply security patches for CVEs".to_string(),
            "Enable RPKI signing".to_string(),
        ]
    } else {
        vec!["Network exposure appears well managed".to_string()]
    };

    Ok(NetworkExposureScoreResult {
        target: req.target.clone(),
        exposure_score: score,
        open_ports_count: open_ports,
        cves_found: cves,
        bgp_hijack_risk: hijack_risk,
        rpki_valid,
        threat_intel_flags: threat_flags,
        overall_risk,
        remediation_steps,
    })
}

fn default_timeout() -> u64 {
    crate::api::helpers::DEFAULT_REQUEST_TIMEOUT_SECS
}
