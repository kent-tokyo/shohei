//! Threat intelligence aggregation hub — unified threat scoring from 6+ sources.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Unified threat intelligence summary from multiple sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceSummary {
    pub target: String,  // domain or IP
    pub target_type: String,  // "domain" or "ip"
    pub risk_score: u8,  // 0-100: aggregate threat level
    pub threat_sources: Vec<ThreatSource>,  // individual source results
    pub overall_verdict: String,  // "clean" | "suspicious" | "malicious"
    pub flagged_by: Vec<String>,  // which sources flagged as malicious
    pub last_updated: String,  // ISO 8601 timestamp
}

/// Individual threat intelligence source result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSource {
    pub source_name: String,  // "GreyNoise" | "Shodan" | "URLhaus" | "VirusTotal" | etc.
    pub is_malicious: bool,
    pub threat_type: Option<String>,  // "scanner" | "phishing" | "malware" | "typosquat"
    pub confidence: u8,  // 0-100 confidence level
    pub details: ThreatDetails,
}

/// Threat details from individual source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetails {
    pub classification: Option<String>,
    pub tags: Vec<String>,
    pub last_seen: Option<String>,
    pub evidence: Option<String>,  // summary of why flagged
}

/// Request to aggregate threat intelligence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelRequest {
    pub target: String,  // domain or IP
    #[serde(default)]
    pub include_sources: Option<Vec<String>>,  // limit to specific sources, default: all
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 30 }  // Higher timeout for parallel requests

/// Aggregate threat intelligence from multiple sources.
pub async fn check_threat_intel_aggregate(req: &ThreatIntelRequest) -> Result<ThreatIntelligenceSummary> {
    use std::str::FromStr;
    use std::net::IpAddr;

    // Determine if target is IP or domain
    let target_type = if IpAddr::from_str(&req.target).is_ok() {
        "ip".to_string()
    } else {
        "domain".to_string()
    };

    let sources_to_check = req.include_sources.as_ref()
        .map(|s| s.clone())
        .unwrap_or_else(|| vec![
            "GreyNoise".to_string(),
            "Shodan".to_string(),
            "URLhaus".to_string(),
            "BrandImpersonation".to_string(),
            "CT".to_string(),
        ]);

    let mut threat_sources = Vec::new();
    let mut flagged_count = 0u8;
    let mut total_scores = Vec::new();

    // GreyNoise: IP reputation
    if sources_to_check.contains(&"GreyNoise".to_string()) && target_type == "ip" {
        if let Ok(result) = check_greynoise_threat(&req.target, req.timeout_secs).await {
            if result.is_malicious {
                flagged_count += 1;
            }
            total_scores.push(result.score);
            threat_sources.push(result.source);
        }
    }

    // Shodan: Open ports, CVEs, banners
    if sources_to_check.contains(&"Shodan".to_string()) && target_type == "ip" {
        if let Ok(result) = check_shodan_threat(&req.target, req.timeout_secs).await {
            if result.is_malicious {
                flagged_count += 1;
            }
            total_scores.push(result.score);
            threat_sources.push(result.source);
        }
    }

    // URLhaus: Malware/phishing URLs
    if sources_to_check.contains(&"URLhaus".to_string()) && target_type == "domain" {
        if let Ok(result) = check_urlhaus_threat(&req.target, req.timeout_secs).await {
            if result.is_malicious {
                flagged_count += 1;
            }
            total_scores.push(result.score);
            threat_sources.push(result.source);
        }
    }

    // Brand impersonation
    if sources_to_check.contains(&"BrandImpersonation".to_string()) && target_type == "domain" {
        if let Ok(result) = check_brand_threat(&req.target, req.timeout_secs).await {
            if result.is_malicious {
                flagged_count += 1;
            }
            total_scores.push(result.score);
            threat_sources.push(result.source);
        }
    }

    // Certificate Transparency: Unexpected CAs
    if sources_to_check.contains(&"CT".to_string()) && target_type == "domain" {
        if let Ok(result) = check_ct_threat(&req.target, req.timeout_secs).await {
            if result.is_malicious {
                flagged_count += 1;
            }
            total_scores.push(result.score);
            threat_sources.push(result.source);
        }
    }

    // Calculate aggregate risk score
    let risk_score = if total_scores.is_empty() {
        0u8
    } else {
        let avg = total_scores.iter().map(|&s| s as u32).sum::<u32>() / total_scores.len() as u32;
        std::cmp::min(100, avg as u8)
    };

    // Determine overall verdict
    let overall_verdict = if flagged_count >= 2 {
        "malicious".to_string()
    } else if flagged_count == 1 || risk_score > 70 {
        "suspicious".to_string()
    } else {
        "clean".to_string()
    };

    let flagged_by = threat_sources.iter()
        .filter(|s| s.is_malicious)
        .map(|s| s.source_name.clone())
        .collect();

    Ok(ThreatIntelligenceSummary {
        target: req.target.clone(),
        target_type,
        risk_score,
        threat_sources,
        overall_verdict,
        flagged_by,
        last_updated: chrono::Local::now().to_rfc3339(),
    })
}

// ─── Helper: Check GreyNoise threat
async fn check_greynoise_threat(ip: &str, timeout_secs: u64) -> Result<ThreatSourceResult> {
    let req = crate::api::GreyNoiseRequest {
        ip: ip.to_string(),
        timeout_secs,
    };
    let result = crate::api::check_ip_noise(&req).await?;

    let is_malicious = result.classification.as_ref()
        .map(|c| c == "malicious" || c == "malware")
        .unwrap_or(false);

    let score = if is_malicious { 90u8 } else if result.noise { 30u8 } else { 10u8 };

    Ok(ThreatSourceResult {
        is_malicious,
        score,
        source: ThreatSource {
            source_name: "GreyNoise".to_string(),
            is_malicious,
            threat_type: result.classification.clone(),
            confidence: if is_malicious { 95 } else { 70 },
            details: ThreatDetails {
                classification: result.classification,
                tags: if result.noise { vec!["scanner".to_string()] } else { vec![] },
                last_seen: result.last_seen,
                evidence: if result.message.is_empty() { None } else { Some(result.message) },
            },
        },
    })
}

// ─── Helper: Check Shodan threat
async fn check_shodan_threat(ip: &str, timeout_secs: u64) -> Result<ThreatSourceResult> {
    let req = crate::api::ShodanInternetDbRequest {
        ip: ip.to_string(),
        timeout_secs,
    };
    let result = crate::api::check_shodan_ip(&req).await?;

    // Check if CVEs are present
    let has_cves = !result.vulns.is_empty();
    let open_port_count = result.open_ports.len();

    let is_malicious = has_cves && open_port_count > 3;  // CVEs + many open ports = suspicious
    let score = if is_malicious { 85u8 } else if has_cves { 60u8 } else if open_port_count > 5 { 40u8 } else { 20u8 };

    let tags = vec![
        format!("{}_open_ports", open_port_count),
        if has_cves { "has_cves".to_string() } else { "no_cves".to_string() },
    ];

    Ok(ThreatSourceResult {
        is_malicious,
        score,
        source: ThreatSource {
            source_name: "Shodan".to_string(),
            is_malicious,
            threat_type: if has_cves { Some("vulnerable_service".to_string()) } else { None },
            confidence: if is_malicious { 85 } else { 60 },
            details: ThreatDetails {
                classification: Some(format!("{} open ports", open_port_count)),
                tags,
                last_seen: None,
                evidence: if has_cves {
                    Some(format!("Found {} CVEs", result.vulns.len()))
                } else {
                    None
                },
            },
        },
    })
}

// ─── Helper: Check URLhaus threat
async fn check_urlhaus_threat(domain: &str, timeout_secs: u64) -> Result<ThreatSourceResult> {
    let url = format!("https://{}", domain);
    let req = crate::api::UrlhausRequest {
        url,
        timeout_secs,
    };
    let result = crate::api::check_url_reputation(&req).await?;

    let is_malicious = result.is_malicious;
    let score = if is_malicious { 95u8 } else { 5u8 };

    Ok(ThreatSourceResult {
        is_malicious,
        score,
        source: ThreatSource {
            source_name: "URLhaus".to_string(),
            is_malicious,
            threat_type: result.threat.clone(),
            confidence: if is_malicious { 98 } else { 90 },
            details: ThreatDetails {
                classification: Some(result.url_status),
                tags: result.tags,
                last_seen: result.date_added,
                evidence: Some(result.message),
            },
        },
    })
}

// ─── Helper: Check brand impersonation threat
async fn check_brand_threat(domain: &str, timeout_secs: u64) -> Result<ThreatSourceResult> {
    let req = crate::api::BrandImpersonationRequest {
        domain: domain.to_string(),
        timeout_secs,
    };
    let result = crate::api::check_brand_impersonation(&req).await?;

    let is_malicious = result.is_impersonating;

    // Determine risk based on match quality
    let max_risk = result.matches.iter()
        .map(|m| m.risk.as_str())
        .max_by_key(|r| match *r {
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        });

    let score = match max_risk {
        Some("high") => 90u8,
        Some("medium") => 60u8,
        Some("low") => 20u8,
        _ => 5u8,
    };

    let tags = result.matches.iter()
        .map(|m| format!("impersonates_{}", m.brand))
        .collect();

    Ok(ThreatSourceResult {
        is_malicious,
        score,
        source: ThreatSource {
            source_name: "BrandImpersonation".to_string(),
            is_malicious,
            threat_type: if is_malicious { Some("phishing".to_string()) } else { None },
            confidence: 85,
            details: ThreatDetails {
                classification: if is_malicious { Some("impersonation_detected".to_string()) } else { Some("clean".to_string()) },
                tags,
                last_seen: None,
                evidence: if is_malicious {
                    Some(format!("Matches: {}", result.matches.iter()
                        .map(|m| format!("{} ({})", m.brand, m.match_type))
                        .collect::<Vec<_>>()
                        .join(", ")))
                } else {
                    None
                },
            },
        },
    })
}

// ─── Helper: Check CT threat
async fn check_ct_threat(domain: &str, timeout_secs: u64) -> Result<ThreatSourceResult> {
    let req = crate::api::CtCheckRequest {
        hostname: domain.to_string(),
        port: 443,
        timeout_secs,
        expected_cas: None,
    };
    let result = crate::api::check_ct(&req).await?;

    let is_malicious = !result.unexpected_certs.is_empty();
    let score = if is_malicious { 70u8 } else { 10u8 };

    Ok(ThreatSourceResult {
        is_malicious,
        score,
        source: ThreatSource {
            source_name: "CertificateTransparency".to_string(),
            is_malicious,
            threat_type: if is_malicious { Some("unexpected_ca".to_string()) } else { None },
            confidence: if is_malicious { 80 } else { 95 },
            details: ThreatDetails {
                classification: Some(format!("{} unexpected certs", result.unexpected_certs.len())),
                tags: if is_malicious { vec!["potential_takeover".to_string()] } else { vec![] },
                last_seen: None,
                evidence: if is_malicious {
                    Some(result.unexpected_certs.join(", "))
                } else {
                    None
                },
            },
        },
    })
}

// ─── Internal result wrapper
struct ThreatSourceResult {
    is_malicious: bool,
    score: u8,
    source: ThreatSource,
}
