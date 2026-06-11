//! High-level library API for DNS diagnostics.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use crate::error::{Result, ShoheError};
use crate::resolver::QueryOptions;
use hickory_proto::rr::RecordType;

pub use crate::resolver::{DnsQueryResult, DnsQuery, DnsRecord, RecordData, TrustState};
pub use crate::resolver::iterative::{ResolutionTrace, ResolutionStep, StepResponseType};
pub use crate::dnssec::chain::{DnssecChain, DnssecStep, DnssecStepType};

pub mod helpers;
pub mod propagation;
pub mod email;
pub mod bench;
pub mod tls;
pub mod mta_sts;
pub mod http;
pub mod ocsp;
pub mod starttls;
pub mod health;
pub mod caa;
pub mod bimi;
pub mod ct;
pub mod whois;
pub mod subdomain;
pub mod ports;
pub mod rdns;
pub mod dnsbl;
pub mod cdn;
pub mod delegation;
pub mod ipinfo;
pub mod tlsvuln;
pub mod tls_rpt;
pub mod ipv6;
pub mod rpki;
pub mod dns_amplification;
pub mod wildcard_dns;
pub mod cipher_suites;
pub mod arc;
pub mod traceroute;
pub mod zone_transfer;
pub mod greynoise;
pub mod domain_risk;
pub mod techfingerprint;
pub mod cve_lookup;
pub mod typosquat;
pub mod redirect_chain;
pub mod parked_domain;
pub mod brand_impersonation;
pub mod urlhaus;
pub mod url_analysis;
pub mod shodan_internetdb;
pub mod ssh_fingerprint;
pub mod compliance;
pub mod bgp_route;
pub mod dns_hijacking;
pub mod spf_analysis;
pub mod threat_intelligence;
pub mod trust_scoring;

pub use propagation::{check_propagation, check_propagation_global, PropagationRequest, PropagationResolver, PropagationResult, PropagationStatus, ResolverCheckResult};
pub use email::{check_email_security, EmailSecurityRequest, EmailSecurityResult, DmarcPolicy};
pub use bench::{benchmark_latency, LatencyBenchRequest, BenchTransport, LatencyBenchResult};
pub use tls::{check_tls_chain, TlsCheckRequest, TlsCheckResult, CertInfo, DaneTlsaResult};
pub use mta_sts::{check_mta_sts, MtaStsRequest, MtaStsResult, MtaStsPolicy, MtaStsMode};
pub use http::{check_http, HttpCheckRequest, HttpCheckResult, HttpTlsInfo};
pub use ocsp::{check_ocsp, OcspCheckRequest, OcspCheckResult, OcspStatus, RevokedInfo};
pub use starttls::{check_starttls, StartTlsCheckRequest, StartTlsCheckResult, StartTlsProtocol};
pub use health::{check_domain_health, DomainHealthRequest, DomainHealthReport, HealthComponent, HealthStatus};
pub use caa::{check_caa, CaaCheckRequest, CaaCheckResult, CaaRecord};
pub use bimi::{check_bimi, BimiCheckRequest, BimiCheckResult};
pub use ct::{check_ct, CtCheckRequest, CtCheckResult, ScTInfo, CtLogEntry};
pub use whois::{check_whois, WhoisCheckRequest, WhoisCheckResult};
pub use subdomain::{check_common_subdomains, SubdomainCheckRequest, SubdomainCheckResult, SubdomainStatus};
pub use ports::{check_ports, PortCheckRequest, PortCheckResult, PortStatus};
pub use rdns::{check_rdns, RdnsCheckRequest, RdnsCheckResult};
pub use dnsbl::{check_dnsbl, DnsblCheckRequest, DnsblCheckResult, DnsblServiceResult};
pub use cdn::{detect_cdn, CdnDetectRequest, CdnDetectResult};
pub use delegation::{check_delegation, DelegationCheckRequest, DelegationCheckResult, DelegationNsResult};
pub use ipinfo::{check_ip_info, IpInfoCheckRequest, IpInfoCheckResult};
pub use tlsvuln::{check_tls_vulns, TlsVulnCheckRequest, TlsVulnCheckResult};
pub use tls_rpt::{check_tls_rpt, TlsRptRequest, TlsRptResult};
pub use ipv6::{check_ipv6, Ipv6CheckRequest, Ipv6CheckResult};
pub use rpki::{check_rpki, RpkiCheckRequest, RpkiCheckResult};
pub use dns_amplification::{check_dns_amplification, DnsAmplificationRequest, DnsAmplificationResult};
pub use wildcard_dns::{check_wildcard_dns, WildcardDnsRequest, WildcardDnsResult};
pub use cipher_suites::{check_cipher_suites, CipherSuitesRequest, CipherSuitesResult};
pub use arc::{check_arc, ArcCheckRequest, ArcCheckResult};
pub use traceroute::{check_traceroute, TracerouteRequest, TracerouteResult};
pub use zone_transfer::{check_zone_transfer, ZoneTransferRequest, ZoneTransferResult};
pub use greynoise::{check_ip_noise, GreyNoiseRequest, GreyNoiseResult};
pub use domain_risk::{check_domain_risk, DomainRiskRequest, DomainRiskResult};
pub use techfingerprint::{check_tech_stack, TechFingerprintRequest, TechFingerprintResult};
pub use cve_lookup::{check_cve, CveLookupRequest, CveLookupResult};
pub use typosquat::{check_typosquatting, TyposquatRequest, TyposquatResult};
pub use redirect_chain::{check_redirect_chain, RedirectChainRequest, RedirectChainResult};
pub use parked_domain::{check_parked_domain, ParkedDomainRequest, ParkedDomainResult};
pub use brand_impersonation::{check_brand_impersonation, BrandImpersonationRequest, BrandImpersonationResult};
pub use urlhaus::{check_url_reputation, UrlhausRequest, UrlhausResult};
pub use url_analysis::{check_url_analysis, UrlAnalysisRequest, UrlAnalysisResult};
pub use shodan_internetdb::{check_shodan_ip, ShodanInternetDbRequest, ShodanInternetDbResult};
pub use ssh_fingerprint::{check_ssh_fingerprint, SshFingerprintRequest, SshFingerprintResult};
pub use compliance::{check_compliance, ComplianceRequest, ComplianceResult};
pub use bgp_route::{check_bgp_route, BgpRouteRequest, BgpRouteResult};
pub use dns_hijacking::{check_dns_hijacking, DnsHijackingRequest, DnsHijackingResult, DnsHijackingRiskLevel};
pub use spf_analysis::{check_spf_deep, SpfAnalysisRequest, SpfAnalysisResult};
pub use threat_intelligence::{
    check_threat_intel_aggregate, threat_intel_risk_score, phishing_detection_aggregate, malware_detected_sources,
    ThreatIntelRequest, ThreatIntelligenceSummary, ThreatRiskScore, PhishingDetectionSummary, MalwareSourcesList,
};
pub use trust_scoring::{
    check_domain_trust_score, check_ip_trust_score,
    DomainTrustScoreRequest, IpTrustScoreRequest, TrustScore, DimensionScores,
};

// ── Transport enum ─────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "config")]
pub enum Transport {
    #[serde(rename = "system")]
    System,
    #[serde(rename = "server")]
    Server(String),
    #[serde(rename = "doh")]
    Doh(String),
    #[serde(rename = "dot")]
    Dot(String),
    #[serde(rename = "doq")]
    Doq(String),
}

impl Default for Transport {
    fn default() -> Self { Transport::System }
}

// ── DnsCheckRequest ────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCheckRequest {
    pub domain: String,
    #[serde(default = "default_record_types")]
    pub record_types: Vec<String>,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub validate_dnssec: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub ipv4_only: bool,
    #[serde(default)]
    pub ipv6_only: bool,
    #[serde(default)]
    pub no_recurse: bool,
    #[serde(default)]
    pub force_tcp: bool,
}

fn default_record_types() -> Vec<String> { vec!["A".to_string()] }
fn default_timeout() -> u64 { 5 }

impl Default for DnsCheckRequest {
    fn default() -> Self {
        Self {
            domain: String::new(),
            record_types: default_record_types(),
            transport: Transport::default(),
            validate_dnssec: false,
            timeout_secs: default_timeout(),
            ipv4_only: false,
            ipv6_only: false,
            no_recurse: false,
            force_tcp: false,
        }
    }
}

// ── DnssecCheckRequest ─────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecCheckRequest {
    pub domain: String,
    #[serde(default = "default_record_type")]
    pub record_type: String,
    #[serde(default)]
    pub resolver_ip: Option<String>,
    #[serde(default)]
    pub verbose: bool,
}

fn default_record_type() -> String { "A".to_string() }

impl Default for DnssecCheckRequest {
    fn default() -> Self {
        Self {
            domain: String::new(),
            record_type: default_record_type(),
            resolver_ip: None,
            verbose: false,
        }
    }
}

// ── Entry points ───────────────────────────────────────────────────────────
pub async fn check_dns(req: &DnsCheckRequest) -> Result<Vec<DnsQueryResult>> {
    if req.domain.is_empty() {
        return Err(ShoheError::Parse("domain cannot be empty".to_string()));
    }

    let record_types = if req.record_types.is_empty() {
        vec!["A".to_string()]
    } else {
        req.record_types.clone()
    };

    let transport = build_transport_config(&req.transport).await?;
    let mut results = Vec::new();
    let mut handles = vec![];

    for rtype_str in record_types {
        let rtype = RecordType::from_str(&rtype_str)
            .map_err(|_| ShoheError::Parse(format!("invalid record type: {}", rtype_str)))?;

        let opts = QueryOptions {
            domain: req.domain.clone(),
            record_type: rtype,
            server: parse_server_addr(&req.transport),
            transport: transport.clone(),
            validate_dnssec: req.validate_dnssec,
            force_tcp: req.force_tcp,
            no_recurse: req.no_recurse,
            timeout_secs: req.timeout_secs,
            ipv4_only: req.ipv4_only,
            ipv6_only: req.ipv6_only,
        };

        let handle = tokio::spawn(async move { crate::resolver::standard::query(&opts).await });
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.await.map_err(|e| ShoheError::Transport(e.to_string()))??;
        results.push(result);
    }

    Ok(results)
}

pub async fn check_dnssec(req: &DnssecCheckRequest) -> Result<DnssecChain> {
    if req.domain.is_empty() {
        return Err(ShoheError::Parse("domain cannot be empty".to_string()));
    }

    let rtype = RecordType::from_str(&req.record_type)
        .map_err(|_| ShoheError::Parse(format!("invalid record type: {}", req.record_type)))?;

    let resolver_ip = if let Some(ref ip_str) = req.resolver_ip {
        Some(IpAddr::from_str(ip_str)
            .map_err(|_| ShoheError::Parse(format!("invalid IP address: {}", ip_str)))?)
    } else {
        None
    };

    crate::dnssec::chain::build_chain(&req.domain, rtype, resolver_ip, req.verbose).await
}

pub async fn trace_resolution(domain: &str, record_type: &str) -> Result<ResolutionTrace> {
    if domain.is_empty() {
        return Err(ShoheError::Parse("domain cannot be empty".to_string()));
    }

    let rtype = RecordType::from_str(record_type)
        .map_err(|_| ShoheError::Parse(format!("invalid record type: {}", record_type)))?;

    crate::resolver::iterative::trace(domain, rtype, None).await
}

// ── Helpers ────────────────────────────────────────────────────────────────
async fn build_transport_config(transport: &Transport) -> Result<Option<(hickory_resolver::config::ResolverConfig, String)>> {
    match transport {
        Transport::System => Ok(None),
        Transport::Server(_) => Ok(None),
        Transport::Doh(url) => {
            let (config, label) = crate::transport::doh::build_doh_config(url).await
                .map_err(|e| ShoheError::Transport(format!("DoH config failed: {}", e)))?;
            Ok(Some((config, label)))
        }
        Transport::Dot(addr) => {
            let (config, label) = crate::transport::dot::build_dot_config(addr).await
                .map_err(|e| ShoheError::Transport(format!("DoT config failed: {}", e)))?;
            Ok(Some((config, label)))
        }
        Transport::Doq(addr) => {
            let (config, label) = crate::transport::doq::build_doq_config(addr).await
                .map_err(|e| ShoheError::Transport(format!("DoQ config failed: {}", e)))?;
            Ok(Some((config, label)))
        }
    }
}

fn parse_server_addr(transport: &Transport) -> Option<std::net::SocketAddr> {
    match transport {
        Transport::Server(addr_str) => {
            std::net::SocketAddr::from_str(addr_str)
                .or_else(|_| std::net::IpAddr::from_str(addr_str)
                    .map(|ip| std::net::SocketAddr::new(ip, 53)))
                .ok()
        }
        _ => None,
    }
}
