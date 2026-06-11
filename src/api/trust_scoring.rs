//! Trust scoring — unified 5-dimensional trust assessment for domains and IPs.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Domain trust score request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTrustScoreRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// IP trust score request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpTrustScoreRequest {
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 30 }

/// Unified trust score (0-100).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub target: String,
    pub target_type: String,  // "domain" or "ip"
    pub overall_score: u8,  // 0-100: aggregate trust level
    pub trust_level: String,  // "high_trust" | "medium_trust" | "low_trust" | "untrusted"
    pub dimension_scores: DimensionScores,
    pub risk_factors: Vec<String>,
    pub trust_factors: Vec<String>,
    pub recommendation: String,
}

/// 5-dimensional trust assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionScores {
    pub dns_trust: u8,  // 20% weight: DNS consistency, DNSSEC, DMARC/SPF/DKIM
    pub tls_trust: u8,  // 25% weight: Certificate validity, CA trust, expiry
    pub threat_reputation: u8,  // 25% weight: GreyNoise, Shodan, VirusTotal flags
    pub registration_age: u8,  // 15% weight: Domain age (new = low trust)
    pub infrastructure_maturity: u8,  // 15% weight: BGP stability, RPKI, ASN trust
}

impl DimensionScores {
    /// Calculate weighted overall score.
    pub fn weighted_score(&self) -> u8 {
        let weighted = (self.dns_trust as u32 * 20
            + self.tls_trust as u32 * 25
            + self.threat_reputation as u32 * 25
            + self.registration_age as u32 * 15
            + self.infrastructure_maturity as u32 * 15) / 100;
        std::cmp::min(100, weighted as u8)
    }
}

/// Compute trust score for domain.
pub async fn check_domain_trust_score(req: &DomainTrustScoreRequest) -> Result<TrustScore> {
    let mut dimensions = DimensionScores {
        dns_trust: 50,
        tls_trust: 50,
        threat_reputation: 50,
        registration_age: 50,
        infrastructure_maturity: 50,
    };

    let mut risk_factors = Vec::new();
    let mut trust_factors = Vec::new();

    // ─── Dimension 1: DNS Trust (20%)
    if let Ok(email_result) = crate::api::check_email_security(&crate::api::EmailSecurityRequest {
        domain: req.domain.clone(),
        dkim_selectors: vec!["default".to_string(), "google".to_string()],
        timeout_secs: req.timeout_secs,
    }).await {
        let has_dmarc = email_result.dmarc.raw.is_some();
        let has_spf = email_result.spf.raw.is_some();

        if has_dmarc && has_spf {
            dimensions.dns_trust = 85;
            trust_factors.push("Complete email security (SPF+DMARC)".to_string());
        } else if has_spf {
            dimensions.dns_trust = 60;
            trust_factors.push("SPF record configured".to_string());
        } else {
            dimensions.dns_trust = 30;
            risk_factors.push("Missing email security records".to_string());
        }
    }

    // ─── Dimension 2: TLS Trust (25%)
    if let Ok(tls_result) = crate::api::check_tls_chain(&crate::api::TlsCheckRequest {
        hostname: req.domain.clone(),
        port: 443,
        check_dane: false,
        timeout_secs: req.timeout_secs,
    }).await {
        if tls_result.valid {
            let days_until_expiry = tls_result.days_until_expiry.unwrap_or(0);
            if days_until_expiry > 180 {
                dimensions.tls_trust = 95;
                trust_factors.push("Valid TLS with 6+ months validity".to_string());
            } else if days_until_expiry > 30 {
                dimensions.tls_trust = 70;
                trust_factors.push("Valid TLS but approaching expiry".to_string());
            } else {
                dimensions.tls_trust = 20;
                risk_factors.push("TLS certificate expiring soon".to_string());
            }

            if let Some(version) = &tls_result.tls_version {
                if version.contains("1.3") {
                    trust_factors.push("TLS 1.3".to_string());
                }
            }
        } else {
            dimensions.tls_trust = 10;
            risk_factors.push("Invalid or missing TLS".to_string());
        }
    }

    // ─── Dimension 3: Threat Reputation (25%)
    if let Ok(threat_result) = crate::api::check_threat_intel_aggregate(&crate::api::ThreatIntelRequest {
        target: req.domain.clone(),
        include_sources: None,
        timeout_secs: req.timeout_secs,
    }).await {
        dimensions.threat_reputation = std::cmp::max(0, 100 - threat_result.risk_score);
        if threat_result.overall_verdict == "clean" {
            trust_factors.push("Clean threat reputation".to_string());
        } else {
            risk_factors.push(format!("Threat flags: {}", threat_result.overall_verdict));
        }
    }

    // ─── Dimension 4: Registration Age (15%)
    if let Ok(whois_result) = crate::api::check_whois(&crate::api::WhoisCheckRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        if let Some(created) = whois_result.created_date {
            if created.contains("2024") {
                dimensions.registration_age = 40;
                risk_factors.push("Recently registered".to_string());
            } else if created.contains("2023") {
                dimensions.registration_age = 70;
                trust_factors.push("Established domain (1-2 years)".to_string());
            } else {
                dimensions.registration_age = 85;
                trust_factors.push("Legacy domain".to_string());
            }
        }
    }

    // ─── Dimension 5: Infrastructure Maturity (15%)
    if let Ok(caa_result) = crate::api::check_caa(&crate::api::CaaCheckRequest {
        domain: req.domain.clone(),
        issued_by_ca: None,
        timeout_secs: req.timeout_secs,
    }).await {
        if !caa_result.records.is_empty() {
            dimensions.infrastructure_maturity = 85;
            trust_factors.push("CAA records configured".to_string());
        } else {
            dimensions.infrastructure_maturity = 45;
            risk_factors.push("No CAA records".to_string());
        }
    }

    let overall_score = dimensions.weighted_score();
    let trust_level = match overall_score {
        80..=100 => "high_trust".to_string(),
        60..=79 => "medium_trust".to_string(),
        40..=59 => "low_trust".to_string(),
        _ => "untrusted".to_string(),
    };

    let recommendation = match overall_score {
        90..=100 => "Verified safe — proceed with confidence".to_string(),
        75..=89 => "Generally trustworthy — monitor".to_string(),
        60..=74 => "Acceptable — verify before engagement".to_string(),
        40..=59 => "Elevated risk — exercise caution".to_string(),
        _ => "High risk — avoid until verified".to_string(),
    };

    Ok(TrustScore {
        target: req.domain.clone(),
        target_type: "domain".to_string(),
        overall_score,
        trust_level,
        dimension_scores: dimensions,
        risk_factors,
        trust_factors,
        recommendation,
    })
}

/// Compute trust score for IP.
pub async fn check_ip_trust_score(req: &IpTrustScoreRequest) -> Result<TrustScore> {
    let mut dimensions = DimensionScores {
        dns_trust: 50,
        tls_trust: 50,
        threat_reputation: 50,
        registration_age: 50,
        infrastructure_maturity: 50,
    };

    let mut risk_factors = Vec::new();
    let mut trust_factors = Vec::new();

    // ─── Dimension 1: DNS Trust (20%)
    if let Ok(rdns_result) = crate::api::check_rdns(&crate::api::RdnsCheckRequest {
        ip: req.ip.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        if let Some(ptr) = &rdns_result.ptr_record {
            if !ptr.is_empty() {
                dimensions.dns_trust = 80;
                trust_factors.push("Reverse DNS configured".to_string());
            } else {
                dimensions.dns_trust = 30;
                risk_factors.push("No reverse DNS".to_string());
            }
        } else {
            dimensions.dns_trust = 30;
            risk_factors.push("No reverse DNS".to_string());
        }
    }

    // ─── Dimension 2: TLS Trust (25%)
    dimensions.tls_trust = 50;  // IP-based TLS less common

    // ─── Dimension 3: Threat Reputation (25%)
    if let Ok(threat_result) = crate::api::check_threat_intel_aggregate(&crate::api::ThreatIntelRequest {
        target: req.ip.clone(),
        include_sources: None,
        timeout_secs: req.timeout_secs,
    }).await {
        dimensions.threat_reputation = std::cmp::max(0, 100 - threat_result.risk_score);
        if threat_result.overall_verdict != "clean" {
            risk_factors.push(format!("Threat: {}", threat_result.overall_verdict));
        } else {
            trust_factors.push("Clean threat reputation".to_string());
        }
    }

    // ─── Dimension 4: Registration Age (15%)
    if let Ok(bgp_result) = crate::api::check_bgp_route(&crate::api::BgpRouteRequest {
        ip: req.ip.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        if let Some(asn) = bgp_result.asn {
            dimensions.registration_age = 75;
            trust_factors.push(format!("BGP announced (ASN{})", asn));
        } else {
            dimensions.registration_age = 30;
            risk_factors.push("Not in BGP routing".to_string());
        }
    }

    // ─── Dimension 5: Infrastructure Maturity (15%)
    if let Ok(rpki_result) = crate::api::check_rpki(&crate::api::RpkiCheckRequest {
        ip: req.ip.clone(),
    }).await {
        if rpki_result.roa_valid {
            dimensions.infrastructure_maturity = 95;
            trust_factors.push("RPKI ROA valid".to_string());
        } else if rpki_result.roa_state == "invalid" {
            dimensions.infrastructure_maturity = 15;
            risk_factors.push("RPKI ROA invalid".to_string());
        } else {
            dimensions.infrastructure_maturity = 50;
        }
    }

    let overall_score = dimensions.weighted_score();
    let trust_level = match overall_score {
        80..=100 => "high_trust".to_string(),
        60..=79 => "medium_trust".to_string(),
        40..=59 => "low_trust".to_string(),
        _ => "untrusted".to_string(),
    };

    let recommendation = match overall_score {
        90..=100 => "Well-configured infrastructure — high trust".to_string(),
        75..=89 => "Legitimate infrastructure — safe".to_string(),
        60..=74 => "Standard infrastructure — acceptable".to_string(),
        40..=59 => "Suspicious indicators — verify".to_string(),
        _ => "High-risk IP — block or quarantine".to_string(),
    };

    Ok(TrustScore {
        target: req.ip.clone(),
        target_type: "ip".to_string(),
        overall_score,
        trust_level,
        dimension_scores: dimensions,
        risk_factors,
        trust_factors,
        recommendation,
    })
}
