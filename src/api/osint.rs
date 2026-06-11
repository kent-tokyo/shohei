//! OSINT — open-source intelligence gathering (subdomains, WHOIS, threat mapping).

use serde::{Deserialize, Serialize};
use crate::error::Result;
use std::collections::HashSet;

/// Subdomain enumeration request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainEnumerationRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// WHOIS enrichment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisEnrichmentRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// DNS threat mapping request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsThreatMappingRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// DNS takeover risk request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTakeoverRiskRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 30 }

/// Subdomain enumeration result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainEnumerationResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub unique_count: usize,
    pub sources: SubdomainSources,
    pub error: Option<String>,
}

/// Subdomain sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainSources {
    pub certificate_transparency: Vec<String>,
    pub whois_nameservers: Vec<String>,
    pub dns_resolution: Vec<String>,
}

/// WHOIS enrichment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisEnrichmentResult {
    pub domain: String,
    pub registrar: Option<String>,
    pub created_date: Option<String>,
    pub expires_date: Option<String>,
    pub nameservers: Vec<String>,
    pub registrant_country: Option<String>,
    pub dns_sec_status: Option<String>,
    pub error: Option<String>,
}

/// DNS threat mapping result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsThreatMappingResult {
    pub domain: String,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub risk_score: u8,
    pub flagged_by_sources: Vec<String>,
    pub error: Option<String>,
}

/// Individual threat indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,  // "suspicious_ns" | "known_phishing_ip" | "c2_domain" | "ddos_target"
    pub value: String,
    pub source: String,
    pub severity: String,  // "low" | "medium" | "high"
}

/// DNS takeover risk result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTakeoverRiskResult {
    pub domain: String,
    pub risk_level: String,  // "none" | "low" | "medium" | "high"
    pub nameservers: Vec<NameserverStatus>,
    pub dangling_records: Vec<String>,
    pub recommendations: Vec<String>,
    pub error: Option<String>,
}

/// Nameserver status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameserverStatus {
    pub ns: String,
    pub responds: bool,
    pub soa_record: Option<String>,
    pub ns_redundancy: u8,  // number of NS records total
}

/// Enumerate subdomains via Certificate Transparency and WHOIS.
pub async fn enumerate_subdomains(req: &SubdomainEnumerationRequest) -> Result<SubdomainEnumerationResult> {
    let mut all_subdomains = HashSet::new();
    let mut ct_subs = Vec::new();
    let mut whois_subs = Vec::new();
    let mut dns_subs = Vec::new();

    // ─── Source 1: Certificate Transparency via crt.sh
    if let Ok(ct_result) = crate::api::check_ct(&crate::api::CtCheckRequest {
        hostname: req.domain.clone(),
        port: 443,
        timeout_secs: req.timeout_secs,
        expected_cas: None,
    }).await {
        for _ in &ct_result.log_entries {
            ct_subs.push(format!("*.{}", req.domain));
        }
    }

    // ─── Source 2: WHOIS Nameserver extraction
    if let Ok(whois_result) = crate::api::check_whois(&crate::api::WhoisCheckRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        for ns in &whois_result.nameservers {
            if ns.contains(&req.domain) {
                whois_subs.push(ns.clone());
            }
        }
    }

    // ─── Source 3: DNS resolution of common subdomains
    let common_prefixes = vec!["www", "mail", "ftp", "smtp", "api", "admin", "test", "staging"];
    for prefix in common_prefixes {
        let subdomain = format!("{}.{}", prefix, req.domain);
        if let Ok(_) = crate::api::check_dns(&crate::api::DnsCheckRequest {
            domain: subdomain.clone(),
            record_types: vec!["A".to_string()],
            ..Default::default()
        }).await {
            dns_subs.push(subdomain);
        }
    }

    // Merge and deduplicate
    all_subdomains.extend(ct_subs.iter().cloned());
    all_subdomains.extend(whois_subs.iter().cloned());
    all_subdomains.extend(dns_subs.iter().cloned());
    all_subdomains.insert(req.domain.clone());

    let mut result_subs: Vec<String> = all_subdomains.into_iter().collect();
    result_subs.sort();

    Ok(SubdomainEnumerationResult {
        domain: req.domain.clone(),
        subdomains: result_subs.clone(),
        unique_count: result_subs.len(),
        sources: SubdomainSources {
            certificate_transparency: ct_subs,
            whois_nameservers: whois_subs,
            dns_resolution: dns_subs,
        },
        error: None,
    })
}

/// Enrich WHOIS data with additional details.
pub async fn enrich_whois(req: &WhoisEnrichmentRequest) -> Result<WhoisEnrichmentResult> {
    let mut result = WhoisEnrichmentResult {
        domain: req.domain.clone(),
        registrar: None,
        created_date: None,
        expires_date: None,
        nameservers: vec![],
        registrant_country: None,
        dns_sec_status: None,
        error: None,
    };

    // Get WHOIS data
    if let Ok(whois) = crate::api::check_whois(&crate::api::WhoisCheckRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        result.created_date = whois.created_date;
        result.expires_date = whois.expiration_date;
        result.nameservers = whois.nameservers;
        result.registrar = whois.registrar;
    }

    // Check DNSSEC status
    if let Ok(dnssec) = crate::api::check_dnssec(&crate::api::DnssecCheckRequest {
        domain: req.domain.clone(),
        record_type: "A".to_string(),
        resolver_ip: None,
        verbose: false,
    }).await {
        result.dns_sec_status = Some(format!("Chain length: {}", dnssec.steps.len()));
    }

    Ok(result)
}

/// Map DNS to threat sources.
pub async fn map_dns_threats(req: &DnsThreatMappingRequest) -> Result<DnsThreatMappingResult> {
    let mut threats = Vec::new();
    let mut flagged_sources = HashSet::new();

    // Check if domain has threat flags
    if let Ok(threat) = crate::api::check_threat_intel_aggregate(&crate::api::ThreatIntelRequest {
        target: req.domain.clone(),
        include_sources: None,
        timeout_secs: req.timeout_secs,
    }).await {
        if threat.overall_verdict != "clean" {
            for source in &threat.flagged_by {
                flagged_sources.insert(source.clone());
                threats.push(ThreatIndicator {
                    indicator_type: "malicious_domain".to_string(),
                    value: req.domain.clone(),
                    source: source.clone(),
                    severity: if threat.overall_verdict == "malicious" { "high" } else { "medium" }.to_string(),
                });
            }
        }
    }

    // Check for suspicious NS configuration
    if let Ok(dns_result) = crate::api::check_dns(&crate::api::DnsCheckRequest {
        domain: format!("{}.", req.domain),
        record_types: vec!["NS".to_string()],
        ..Default::default()
    }).await {
        if dns_result.is_empty() {
            threats.push(ThreatIndicator {
                indicator_type: "suspicious_ns".to_string(),
                value: "no_nameservers".to_string(),
                source: "dns_check".to_string(),
                severity: "high".to_string(),
            });
            flagged_sources.insert("dns_check".to_string());
        }
    }

    let risk_score = if flagged_sources.is_empty() { 0 } else { (flagged_sources.len() as u8) * 30 };

    Ok(DnsThreatMappingResult {
        domain: req.domain.clone(),
        threat_indicators: threats,
        risk_score: std::cmp::min(100, risk_score),
        flagged_by_sources: flagged_sources.into_iter().collect(),
        error: None,
    })
}

/// Assess DNS takeover risk.
pub async fn assess_dns_takeover_risk(req: &DnsTakeoverRiskRequest) -> Result<DnsTakeoverRiskResult> {
    let mut nameservers = Vec::new();
    let mut dangling_records = Vec::new();
    let mut risk_level = "none".to_string();
    let mut recommendations = Vec::new();

    // Get NS records
    if let Ok(dns_result) = crate::api::check_dns(&crate::api::DnsCheckRequest {
        domain: format!("{}.", req.domain),
        record_types: vec!["NS".to_string()],
        ..Default::default()
    }).await {
        let ns_count = dns_result.len();

        for result in dns_result {
            for answer in &result.answers {
                if let crate::resolver::RecordData::Ns(ns_domain) = &answer.data {
                    let responds = if let Ok(_) = crate::api::check_rdns(&crate::api::RdnsCheckRequest {
                        ip: ns_domain.clone(),
                        timeout_secs: req.timeout_secs,
                    }).await {
                        true
                    } else {
                        false
                    };

                    nameservers.push(NameserverStatus {
                        ns: ns_domain.clone(),
                        responds,
                        soa_record: None,
                        ns_redundancy: ns_count as u8,
                    });

                    if !responds {
                        dangling_records.push(format!("NS {} not responding", ns_domain));
                        risk_level = "high".to_string();
                    }
                }
            }
        }

        if nameservers.len() < 2 {
            risk_level = "high".to_string();
            recommendations.push("Configure at least 2 nameservers for redundancy".to_string());
        }
    } else {
        risk_level = "high".to_string();
        dangling_records.push("Domain not found in DNS".to_string());
        recommendations.push("Verify domain registration and NS configuration".to_string());
    }

    if dangling_records.is_empty() && risk_level == "none" {
        recommendations.push("DNS configuration appears secure".to_string());
    }

    Ok(DnsTakeoverRiskResult {
        domain: req.domain.clone(),
        risk_level,
        nameservers,
        dangling_records,
        recommendations,
        error: None,
    })
}
