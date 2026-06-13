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

/// Subdomain brute-force request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainBruteforceRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Subdomain brute-force result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainBruteforceResult {
    pub domain: String,
    pub discovered_subdomains: Vec<String>,
    pub discovery_count: usize,
    pub error: Option<String>,
}

/// Perform DNS brute-force on common subdomain prefixes (parallel).
pub async fn bruteforce_subdomains(req: &SubdomainBruteforceRequest) -> Result<SubdomainBruteforceResult> {
    let common_subs = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "test",
        "staging", "dev", "api", "cdn", "img", "images", "static", "assets",
        "download", "downloads", "upload", "uploads", "blog", "shop", "store",
        "forum", "wiki", "git", "gitlab", "jenkins", "vpn", "remote",
    ];

    let handles: Vec<_> = common_subs.iter().map(|sub| {
        let subdomain = format!("{}.{}", sub, req.domain);
        tokio::spawn(async move {
            let ok = crate::api::check_dns(&crate::api::DnsCheckRequest {
                domain: subdomain.clone(),
                record_types: vec!["A".to_string()],
                timeout_secs: 5,
                ..Default::default()
            }).await
            .map(|r| !r.is_empty() && !r[0].answers.is_empty())
            .unwrap_or(false);
            if ok { Some(subdomain) } else { None }
        })
    }).collect();

    let mut discovered: Vec<String> = Vec::new();
    for handle in handles {
        if let Ok(Some(sub)) = handle.await {
            discovered.push(sub);
        }
    }
    discovered.sort();

    Ok(SubdomainBruteforceResult {
        domain: req.domain.clone(),
        discovery_count: discovered.len(),
        discovered_subdomains: discovered,
        error: None,
    })
}

/// Domain typosquat detection request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatDetectionRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Typosquat variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatVariant {
    pub variant: String,
    pub type_: String,  // "character_omission" | "character_swap" | "vowel_swap"
    pub exists: bool,
    pub ip: Option<String>,
}

/// Domain typosquat detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatDetectionResult {
    pub domain: String,
    pub typosquat_variants: Vec<TyposquatVariant>,
    pub potentially_malicious: usize,
    pub error: Option<String>,
}

/// Detect common typosquat domain variants.
pub async fn detect_typosquats(req: &TyposquatDetectionRequest) -> Result<TyposquatDetectionResult> {
    let mut variants = Vec::new();
    let parts: Vec<&str> = req.domain.split('.').collect();

    if parts.is_empty() {
        return Ok(TyposquatDetectionResult {
            domain: req.domain.clone(),
            typosquat_variants: vec![],
            potentially_malicious: 0,
            error: Some("Invalid domain".to_string()),
        });
    }

    let domain_name = parts[0];
    let tld = if parts.len() > 1 { parts[1] } else { "com" };

    // Character omissions — use char_indices to avoid byte-boundary panic on multibyte chars
    let domain_chars: Vec<char> = domain_name.chars().collect();
    for i in 0..domain_chars.len() {
        let variant = format!(
            "{}{}.{}",
            &domain_chars[..i].iter().collect::<String>(),
            &domain_chars[i + 1..].iter().collect::<String>(),
            tld
        );
        if variant != req.domain {
            let exists = crate::api::check_dns(&crate::api::DnsCheckRequest {
                domain: variant.clone(),
                record_types: vec!["A".to_string()],
                timeout_secs: 5,
                ..Default::default()
            }).await.ok().map(|r| !r.is_empty()).unwrap_or(false);

            variants.push(TyposquatVariant {
                variant,
                type_: "character_omission".to_string(),
                exists,
                ip: None,
            });
        }
    }

    // Adjacent character swaps — use char count (not byte count) for loop bound
    for i in 0..domain_chars.len().saturating_sub(1) {
        let mut chars = domain_chars.clone();
        chars.swap(i, i + 1);
        let swapped: String = chars.iter().collect();
        let variant = format!("{}.{}", swapped, tld);

        if variant != req.domain {
            let exists = crate::api::check_dns(&crate::api::DnsCheckRequest {
                domain: variant.clone(),
                record_types: vec!["A".to_string()],
                timeout_secs: 5,
                ..Default::default()
            }).await.ok().map(|r| !r.is_empty()).unwrap_or(false);

            variants.push(TyposquatVariant {
                variant,
                type_: "character_swap".to_string(),
                exists,
                ip: None,
            });
        }
    }

    let potentially_malicious = variants.iter().filter(|v| v.exists).count();

    Ok(TyposquatDetectionResult {
        domain: req.domain.clone(),
        typosquat_variants: variants,
        potentially_malicious,
        error: None,
    })
}

/// IP WHOIS enrichment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWhoisEnrichmentRequest {
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// IP WHOIS enrichment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWhoisEnrichmentResult {
    pub ip: String,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub organization: Option<String>,
    pub country: Option<String>,
    pub prefix: Option<String>,
    pub is_announced: bool,
    pub abuse_contact: Option<String>,
    pub error: Option<String>,
}

/// Enrich IP with WHOIS and BGP data.
pub async fn enrich_ip_whois(req: &IpWhoisEnrichmentRequest) -> Result<IpWhoisEnrichmentResult> {
    let mut result = IpWhoisEnrichmentResult {
        ip: req.ip.clone(),
        asn: None,
        asn_name: None,
        organization: None,
        country: None,
        prefix: None,
        is_announced: false,
        abuse_contact: None,
        error: None,
    };

    // Get BGP data
    if let Ok(bgp) = crate::api::check_bgp_route(&crate::api::BgpRouteRequest {
        ip: req.ip.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        result.asn = bgp.asn;
        result.asn_name = bgp.asn_name;
        result.country = bgp.country;
        result.prefix = bgp.prefix;
        result.is_announced = bgp.is_announced;
    }

    // Get IP info
    if let Ok(ipinfo) = crate::api::check_ip_info(&crate::api::IpInfoCheckRequest {
        ip: req.ip.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        result.organization = ipinfo.org;
    }

    Ok(result)
}

/// Domain age timeline request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAgeTimelineRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Domain age analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAgeAnalysis {
    pub domain: String,
    pub created_date: Option<String>,
    pub expires_date: Option<String>,
    pub updated_date: Option<String>,
    pub age_days: Option<u32>,
    pub risk_level: String,  // "new" | "young" | "established" | "legacy"
    pub registrar: Option<String>,
    pub analysis: String,
}

/// Analyze domain age and history.
pub async fn analyze_domain_age(req: &DomainAgeTimelineRequest) -> Result<DomainAgeAnalysis> {
    let mut analysis = DomainAgeAnalysis {
        domain: req.domain.clone(),
        created_date: None,
        expires_date: None,
        updated_date: None,
        age_days: None,
        risk_level: "unknown".to_string(),
        registrar: None,
        analysis: String::new(),
    };

    if let Ok(whois) = crate::api::check_whois(&crate::api::WhoisCheckRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        analysis.created_date = whois.created_date.clone();
        analysis.expires_date = whois.expiration_date.clone();
        analysis.registrar = whois.registrar.clone();

        // Estimate age in days
        if let Some(created) = &whois.created_date {
            if let Ok(created_year) = created.split('-').next().unwrap_or("2024").parse::<u32>() {
                let current_year = (crate::api::helpers::now_timestamp() / (86400 * 365) + 1970) as u32;
                let age_years = current_year.saturating_sub(created_year);
                let age_days = age_years * 365;
                analysis.age_days = Some(age_days);

                analysis.risk_level = match age_years {
                    0 => "new".to_string(),
                    1..=2 => "young".to_string(),
                    3..=10 => "established".to_string(),
                    _ => "legacy".to_string(),
                };

                analysis.analysis = match age_years {
                    0 => "Domain registered within the last year — elevated risk for phishing/scams".to_string(),
                    1..=2 => "Domain 1-2 years old — monitor for suspicious activity".to_string(),
                    3..=10 => "Domain established 3-10 years — generally trustworthy".to_string(),
                    _ => "Legacy domain 10+ years — high trust".to_string(),
                };
            }
        }
    }

    Ok(analysis)
}

/// Certificate history request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateHistoryRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Certificate history result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateHistoryResult {
    pub domain: String,
    pub cert_count: usize,
    pub issuers: Vec<String>,
    pub earliest_cert: Option<String>,
    pub latest_cert: Option<String>,
    pub wildcard_certs: usize,
    pub san_domains: Vec<String>,
    pub error: Option<String>,
}

/// Retrieve certificate history from Certificate Transparency logs.
pub async fn get_certificate_history(req: &CertificateHistoryRequest) -> Result<CertificateHistoryResult> {
    let mut result = CertificateHistoryResult {
        domain: req.domain.clone(),
        cert_count: 0,
        issuers: Vec::new(),
        earliest_cert: None,
        latest_cert: None,
        wildcard_certs: 0,
        san_domains: Vec::new(),
        error: None,
    };

    if let Ok(ct) = crate::api::check_ct(&crate::api::CtCheckRequest {
        hostname: req.domain.clone(),
        port: 443,
        timeout_secs: req.timeout_secs,
        expected_cas: None,
    }).await {
        result.cert_count = ct.log_entries.len();

        let mut issuers_set = HashSet::new();
        for entry in &ct.log_entries {
            if let Some(issuer) = &entry.issuer_name {
                issuers_set.insert(issuer.clone());
            }
        }
        result.issuers = issuers_set.into_iter().collect();
    }

    Ok(result)
}

/// Threat actor infrastructure request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorInfraRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Related infrastructure item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureItem {
    pub item: String,
    pub type_: String,  // "domain" | "ip" | "asn" | "certificate"
    pub threat_score: u8,
    pub connection: String,  // how it relates
}

/// Threat actor infrastructure result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorInfraResult {
    pub domain: String,
    pub related_infrastructure: Vec<InfrastructureItem>,
    pub threat_score: u8,
    pub recommendations: Vec<String>,
    pub error: Option<String>,
}

/// Map threat actor infrastructure.
pub async fn map_threat_actor_infra(req: &ThreatActorInfraRequest) -> Result<ThreatActorInfraResult> {
    let mut infra = Vec::new();
    let mut threat_score = 0u8;
    let mut recommendations = Vec::new();

    // Get IP of domain
    if let Ok(dns_results) = crate::api::check_dns(&crate::api::DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["A".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    }).await {
        for result in dns_results {
            for answer in &result.answers {
                if let crate::resolver::RecordData::A(ip) = &answer.data {
                    let ip_str = ip.to_string();

                    // Check threat intel on IP
                    if let Ok(threat) = crate::api::check_threat_intel_aggregate(&crate::api::ThreatIntelRequest {
                        target: ip_str.clone(),
                        include_sources: None,
                        timeout_secs: req.timeout_secs,
                    }).await {
                        threat_score = std::cmp::max(threat_score, threat.risk_score);
                        if threat.overall_verdict != "clean" {
                            infra.push(InfrastructureItem {
                                item: ip_str.clone(),
                                type_: "ip".to_string(),
                                threat_score: threat.risk_score,
                                connection: "A record resolution".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Get nameservers
    if let Ok(dns_results) = crate::api::check_dns(&crate::api::DnsCheckRequest {
        domain: format!("{}.", req.domain),
        record_types: vec!["NS".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    }).await {
        for result in dns_results {
            for answer in &result.answers {
                if let crate::resolver::RecordData::Ns(ns) = &answer.data {
                    infra.push(InfrastructureItem {
                        item: ns.clone(),
                        type_: "domain".to_string(),
                        threat_score: 10,
                        connection: "Nameserver".to_string(),
                    });
                }
            }
        }
    }

    if threat_score > 50 {
        recommendations.push("High threat infrastructure detected — block or isolate".to_string());
    } else if threat_score > 25 {
        recommendations.push("Moderate threat indicators — monitor closely".to_string());
    } else if !infra.is_empty() {
        recommendations.push("Infrastructure identified — verify legitimacy".to_string());
    }

    Ok(ThreatActorInfraResult {
        domain: req.domain.clone(),
        related_infrastructure: infra,
        threat_score,
        recommendations,
        error: None,
    })
}

/// DNS history request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHistoryRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// DNS history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHistoryEntry {
    pub record_type: String,
    pub value: String,
    pub current: bool,
}

/// DNS history result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHistoryResult {
    pub domain: String,
    pub current_records: Vec<DnsHistoryEntry>,
    pub analysis: String,
    pub error: Option<String>,
}

/// Analyze current DNS configuration as historical snapshot.
pub async fn analyze_dns_history(req: &DnsHistoryRequest) -> Result<DnsHistoryResult> {
    let mut records = Vec::new();
    let mut analysis = String::new();

    // Query common record types
    let record_types = vec!["A", "AAAA", "MX", "NS", "TXT", "CNAME"];

    for rtype in record_types {
        if let Ok(dns_results) = crate::api::check_dns(&crate::api::DnsCheckRequest {
            domain: req.domain.clone(),
            record_types: vec![rtype.to_string()],
            timeout_secs: req.timeout_secs,
            ..Default::default()
        }).await {
            for result in dns_results {
                for answer in &result.answers {
                    let value = match &answer.data {
                        crate::resolver::RecordData::A(ip) => ip.clone(),
                        crate::resolver::RecordData::Aaaa(ip) => ip.clone(),
                        crate::resolver::RecordData::Cname(name) => name.clone(),
                        crate::resolver::RecordData::Ns(name) => name.clone(),
                        crate::resolver::RecordData::Ptr(name) => name.clone(),
                        crate::resolver::RecordData::Mx { exchange, .. } => exchange.clone(),
                        crate::resolver::RecordData::Txt(texts) => texts.join("; "),
                        crate::resolver::RecordData::Srv { target, port, .. } => format!("{}:{}", target, port),
                        _ => answer.name.clone(),
                    };

                    records.push(DnsHistoryEntry {
                        record_type: rtype.to_string(),
                        value,
                        current: true,
                    });
                }
            }
        }
    }

    analysis = format!(
        "Current DNS snapshot: {} record(s). Monitor for unexpected changes indicating compromise or takeover.",
        records.len()
    );

    Ok(DnsHistoryResult {
        domain: req.domain.clone(),
        current_records: records,
        analysis,
        error: None,
    })
}

/// IP geolocation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpGeolocationRequest {
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// IP geolocation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpGeolocationResult {
    pub ip: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
}

/// Get IP geolocation information.
pub async fn get_ip_geolocation(req: &IpGeolocationRequest) -> Result<IpGeolocationResult> {
    let mut result = IpGeolocationResult {
        ip: req.ip.clone(),
        country: None,
        region: None,
        city: None,
        latitude: None,
        longitude: None,
        timezone: None,
        isp: None,
    };

    if let Ok(ipinfo) = crate::api::check_ip_info(&crate::api::IpInfoCheckRequest {
        ip: req.ip.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        result.country = ipinfo.country;
        result.region = ipinfo.region;
        result.city = ipinfo.city;
        result.latitude = ipinfo.latitude;
        result.longitude = ipinfo.longitude;
        result.timezone = ipinfo.timezone;
        result.isp = ipinfo.org;
    }

    Ok(result)
}

/// ASN information request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnLookupRequest {
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// ASN lookup result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnLookupResult {
    pub ip: String,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub route: Option<String>,
    pub announced_by: Option<String>,
}

/// Look up ASN information for IP.
pub async fn lookup_asn(req: &AsnLookupRequest) -> Result<AsnLookupResult> {
    let mut result = AsnLookupResult {
        ip: req.ip.clone(),
        asn: None,
        organization: None,
        route: None,
        announced_by: None,
    };

    if let Ok(bgp) = crate::api::check_bgp_route(&crate::api::BgpRouteRequest {
        ip: req.ip.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        result.asn = bgp.asn;
        result.organization = bgp.asn_name;
        result.route = bgp.prefix;
        result.announced_by = bgp.registry;
    }

    Ok(result)
}

/// WHOIS privacy detection request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisPrivacyDetectionRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// WHOIS privacy detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisPrivacyDetectionResult {
    pub domain: String,
    pub uses_privacy_protection: bool,
    pub privacy_service: Option<String>,
    pub risk_indicators: Vec<String>,
    pub recommendation: String,
}

/// Detect WHOIS privacy protection.
pub async fn detect_whois_privacy(req: &WhoisPrivacyDetectionRequest) -> Result<WhoisPrivacyDetectionResult> {
    let mut result = WhoisPrivacyDetectionResult {
        domain: req.domain.clone(),
        uses_privacy_protection: false,
        privacy_service: None,
        risk_indicators: Vec::new(),
        recommendation: "Unable to retrieve WHOIS data for privacy detection".to_string(),
    };

    if let Ok(_whois) = crate::api::check_whois(&crate::api::WhoisCheckRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        result.recommendation = "WHOIS data retrieved — privacy status analysis requires deeper inspection".to_string();
    }

    Ok(result)
}

/// Email spoofing risk request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSpoofingRiskRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Email spoofing risk result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSpoofingRiskResult {
    pub domain: String,
    pub spf_configured: bool,
    pub dkim_configured: bool,
    pub dmarc_configured: bool,
    pub dmarc_policy: Option<String>,
    pub risk_score: u8,  // 0-100, higher = more vulnerable
    pub recommendations: Vec<String>,
}

/// Assess email spoofing risk.
pub async fn assess_email_spoofing_risk(req: &EmailSpoofingRiskRequest) -> Result<EmailSpoofingRiskResult> {
    let mut result = EmailSpoofingRiskResult {
        domain: req.domain.clone(),
        spf_configured: false,
        dkim_configured: false,
        dmarc_configured: false,
        dmarc_policy: None,
        risk_score: 100,
        recommendations: Vec::new(),
    };

    if let Ok(email) = crate::api::check_email_security(&crate::api::EmailSecurityRequest {
        domain: req.domain.clone(),
        dkim_selectors: vec!["default".to_string(), "google".to_string()],
        timeout_secs: req.timeout_secs,
    }).await {
        result.spf_configured = email.spf.raw.is_some();
        result.dkim_configured = !email.dkim.is_empty();
        result.dmarc_configured = email.dmarc.raw.is_some();
        result.dmarc_policy = Some(format!("{:?}", email.dmarc.policy));

        let mut score = 100u8;
        if result.spf_configured { score = score.saturating_sub(30); }
        if result.dkim_configured { score = score.saturating_sub(20); }
        if result.dmarc_configured { score = score.saturating_sub(40); }
        result.risk_score = score;

        if !result.spf_configured {
            result.recommendations.push("Configure SPF record to prevent email spoofing".to_string());
        }
        if !result.dkim_configured {
            result.recommendations.push("Set up DKIM signing for email authentication".to_string());
        }
        if !result.dmarc_configured {
            result.recommendations.push("Implement DMARC policy for sender validation".to_string());
        }
    } else {
        result.recommendations.push("Unable to retrieve email security config".to_string());
    }

    Ok(result)
}

/// TLS certificate validation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertValidationRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// TLS certificate validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertValidationResult {
    pub domain: String,
    pub cert_valid: bool,
    pub certificate_issuer: Option<String>,
    pub signature_algorithm: Option<String>,
    pub key_size: Option<u16>,
    pub days_until_expiry: Option<i64>,
    pub validation_issues: Vec<String>,
    pub trust_level: String,
}

/// Validate TLS certificate.
pub async fn validate_tls_cert(req: &TlsCertValidationRequest) -> Result<TlsCertValidationResult> {
    let mut result = TlsCertValidationResult {
        domain: req.domain.clone(),
        cert_valid: false,
        certificate_issuer: None,
        signature_algorithm: None,
        key_size: None,
        days_until_expiry: None,
        validation_issues: Vec::new(),
        trust_level: "untrusted".to_string(),
    };

    if let Ok(tls) = crate::api::check_tls_chain(&crate::api::TlsCheckRequest {
        hostname: req.domain.clone(),
        port: 443,
        check_dane: false,
        timeout_secs: req.timeout_secs,
    }).await {
        result.cert_valid = tls.valid;
        result.days_until_expiry = tls.days_until_expiry;

        // Extract issuer from certificate chain (leaf cert is first)
        if !tls.chain.is_empty() {
            result.certificate_issuer = tls.chain[0].issuer_cn.clone();
        }

        if result.cert_valid {
            result.trust_level = "trusted".to_string();
        } else {
            result.validation_issues.push("Certificate validation failed".to_string());
        }

        if let Some(days) = result.days_until_expiry {
            if days < 0 {
                result.validation_issues.push("Certificate is expired".to_string());
                result.trust_level = "untrusted".to_string();
            } else if days < 30 {
                result.validation_issues.push(format!("Certificate expires in {} days", days));
            }
        }
    } else {
        result.validation_issues.push("Unable to retrieve TLS certificate".to_string());
    }

    Ok(result)
}

/// Infrastructure overlap request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureOverlapRequest {
    pub domains: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Infrastructure overlap result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureOverlapResult {
    pub domains_checked: usize,
    pub shared_ips: Vec<String>,
    pub shared_nameservers: Vec<String>,
    pub shared_asns: Vec<u32>,
    pub overlap_score: u8,  // 0-100, higher = more overlap
    pub suspicion_level: String,  // "none" | "low" | "medium" | "high"
}

/// Detect infrastructure overlap between domains.
pub async fn detect_infrastructure_overlap(req: &InfrastructureOverlapRequest) -> Result<InfrastructureOverlapResult> {
    let mut result = InfrastructureOverlapResult {
        domains_checked: req.domains.len(),
        shared_ips: Vec::new(),
        shared_nameservers: Vec::new(),
        shared_asns: Vec::new(),
        overlap_score: 0,
        suspicion_level: "none".to_string(),
    };

    let mut all_ips: Vec<String> = Vec::new();
    let mut all_nameservers: Vec<String> = Vec::new();
    let mut all_asns: Vec<u32> = Vec::new();

    for domain in &req.domains {
        // Get IPs
        if let Ok(dns_results) = crate::api::check_dns(&crate::api::DnsCheckRequest {
            domain: domain.clone(),
            record_types: vec!["A".to_string()],
            timeout_secs: req.timeout_secs,
            ..Default::default()
        }).await {
            for result in dns_results {
                for answer in &result.answers {
                    if let crate::resolver::RecordData::A(ip) = &answer.data {
                        all_ips.push(ip.clone());
                    }
                }
            }
        }

        // Get nameservers
        if let Ok(dns_results) = crate::api::check_dns(&crate::api::DnsCheckRequest {
            domain: format!("{}.", domain),
            record_types: vec!["NS".to_string()],
            timeout_secs: req.timeout_secs,
            ..Default::default()
        }).await {
            for result in dns_results {
                for answer in &result.answers {
                    if let crate::resolver::RecordData::Ns(ns) = &answer.data {
                        all_nameservers.push(ns.clone());
                    }
                }
            }
        }

        // Get ASNs
        if let Some(ip) = all_ips.last() {
            if let Ok(bgp) = crate::api::check_bgp_route(&crate::api::BgpRouteRequest {
                ip: ip.clone(),
                timeout_secs: req.timeout_secs,
            }).await {
                if let Some(asn) = bgp.asn {
                    all_asns.push(asn);
                }
            }
        }
    }

    // Find overlap
    let ip_counts: std::collections::HashMap<String, usize> = all_ips.iter()
        .fold(std::collections::HashMap::new(), |mut m, ip| {
            *m.entry(ip.clone()).or_insert(0) += 1;
            m
        });

    for (ip, count) in ip_counts {
        if count > 1 {
            result.shared_ips.push(ip);
        }
    }

    let ns_counts: std::collections::HashMap<String, usize> = all_nameservers.iter()
        .fold(std::collections::HashMap::new(), |mut m, ns| {
            *m.entry(ns.clone()).or_insert(0) += 1;
            m
        });

    for (ns, count) in ns_counts {
        if count > 1 {
            result.shared_nameservers.push(ns);
        }
    }

    result.shared_asns = all_asns.iter()
        .fold(std::collections::HashMap::new(), |mut m, asn| {
            *m.entry(*asn).or_insert(0) += 1;
            m
        })
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(asn, _)| asn)
        .collect();

    let overlap_indicators = result.shared_ips.len() + result.shared_nameservers.len() + result.shared_asns.len();
    result.overlap_score = std::cmp::min(100, (overlap_indicators * 25) as u8);

    result.suspicion_level = match result.overlap_score {
        0 => "none".to_string(),
        1..=25 => "low".to_string(),
        26..=50 => "medium".to_string(),
        _ => "high".to_string(),
    };

    Ok(result)
}

/// Technology stack fingerprinting request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechStackFingerprintingRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Technology detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechStackResult {
    pub domain: String,
    pub detected_technologies: Vec<String>,
    pub web_server: Option<String>,
    pub programming_languages: Vec<String>,
    pub frameworks: Vec<String>,
}

/// Fingerprint domain technology stack.
pub async fn fingerprint_tech_stack(req: &TechStackFingerprintingRequest) -> Result<TechStackResult> {
    let mut result = TechStackResult {
        domain: req.domain.clone(),
        detected_technologies: Vec::new(),
        web_server: None,
        programming_languages: Vec::new(),
        frameworks: Vec::new(),
    };

    if let Ok(tech) = crate::api::check_tech_stack(&crate::api::TechFingerprintRequest {
        url: format!("https://{}", req.domain),
        timeout_secs: req.timeout_secs,
    }).await {
        result.detected_technologies = tech.technologies.iter()
            .map(|t| t.technology.clone())
            .collect();

        // Categorize detected technologies
        for tech_item in &tech.technologies {
            match tech_item.category.as_str() {
                "Web Servers" => {
                    result.web_server = Some(tech_item.technology.clone());
                }
                "Programming Languages" => {
                    result.programming_languages.push(tech_item.technology.clone());
                }
                "Web Frameworks" => {
                    result.frameworks.push(tech_item.technology.clone());
                }
                _ => {}
            }
        }
    }

    Ok(result)
}

/// Domain reputation analysis request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputationAnalysisRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Domain reputation analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputationAnalysisResult {
    pub domain: String,
    pub reputation_score: u8,
    pub reputation_level: String,
    pub trust_indicators: Vec<String>,
    pub risk_indicators: Vec<String>,
    pub final_recommendation: String,
}

/// Analyze domain reputation.
pub async fn analyze_domain_reputation(req: &DomainReputationAnalysisRequest) -> Result<DomainReputationAnalysisResult> {
    let mut result = DomainReputationAnalysisResult {
        domain: req.domain.clone(),
        reputation_score: 50,
        reputation_level: "unknown".to_string(),
        trust_indicators: Vec::new(),
        risk_indicators: Vec::new(),
        final_recommendation: String::new(),
    };

    let mut score = 50u8;

    // Check domain health
    if let Ok(_health) = crate::api::check_domain_health(&crate::api::DomainHealthRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        score = score.saturating_add(10);
        result.trust_indicators.push("Domain health check passed".to_string());
    }

    // Check threat intelligence
    if let Ok(threat) = crate::api::check_threat_intel_aggregate(&crate::api::ThreatIntelRequest {
        target: req.domain.clone(),
        include_sources: None,
        timeout_secs: req.timeout_secs,
    }).await {
        if threat.overall_verdict == "clean" {
            score = score.saturating_add(20);
            result.trust_indicators.push("No threat intelligence flags".to_string());
        } else {
            score = score.saturating_sub(30);
            result.risk_indicators.push(format!("Threat verdict: {}", threat.overall_verdict));
        }
    }

    // Check domain age
    if let Ok(age_analysis) = analyze_domain_age(&DomainAgeTimelineRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
    }).await {
        match age_analysis.risk_level.as_str() {
            "legacy" => {
                score = score.saturating_add(15);
                result.trust_indicators.push("Legacy domain (10+ years)".to_string());
            }
            "established" => {
                score = score.saturating_add(10);
                result.trust_indicators.push("Established domain (3-10 years)".to_string());
            }
            "young" => {
                result.risk_indicators.push("Young domain (1-2 years)".to_string());
            }
            "new" => {
                score = score.saturating_sub(15);
                result.risk_indicators.push("Newly registered domain (<1 year)".to_string());
            }
            _ => {}
        }
    }

    // Check email security
    if let Ok(email) = crate::api::check_email_security(&crate::api::EmailSecurityRequest {
        domain: req.domain.clone(),
        dkim_selectors: vec!["default".to_string(), "google".to_string()],
        timeout_secs: req.timeout_secs,
    }).await {
        let has_all = email.spf.raw.is_some() && !email.dkim.is_empty() && email.dmarc.raw.is_some();
        if has_all {
            score = score.saturating_add(10);
            result.trust_indicators.push("Complete email security (SPF+DKIM+DMARC)".to_string());
        } else if email.spf.raw.is_some() || email.dmarc.raw.is_some() {
            score = score.saturating_add(5);
            result.trust_indicators.push("Partial email security configured".to_string());
        } else {
            result.risk_indicators.push("Missing email security records".to_string());
        }
    }

    result.reputation_score = std::cmp::min(100, score);

    result.reputation_level = match result.reputation_score {
        85..=100 => "excellent".to_string(),
        70..=84 => "good".to_string(),
        50..=69 => "fair".to_string(),
        30..=49 => "poor".to_string(),
        _ => "bad".to_string(),
    };

    result.final_recommendation = match result.reputation_level.as_str() {
        "excellent" => "Verified safe — proceed with confidence".to_string(),
        "good" => "Generally trustworthy — monitor for changes".to_string(),
        "fair" => "Acceptable — verify before engagement".to_string(),
        "poor" => "Elevated risk — exercise caution".to_string(),
        "bad" => "High risk — avoid until verified".to_string(),
        _ => "Unknown reputation".to_string(),
    };

    Ok(result)
}
