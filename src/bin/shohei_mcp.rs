//! shohei MCP server — expose shohei library API as Claude tools.
//!
//! This binary makes shohei's DNS/TLS/email/propagation/latency APIs available
//! to Claude and other AI agents via the Model Context Protocol (MCP).
//!
//! Run with: shohei-mcp (reads JSON-RPC 2.0 on stdin, writes on stdout)

use rmcp::{ServiceExt, handler::server::wrapper::Parameters, tool_router, tool, schemars};
use serde::Deserialize;
use shohei::api::*;

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckDnsParams {
    /// Domain to query
    domain: String,
    /// Record types (A, AAAA, MX, TXT, etc)
    #[serde(default)]
    record_types: Option<Vec<String>>,
    /// Transport to use: System, DoH, DoT, DoQ, or server IP (default: System)
    #[serde(default)]
    transport: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckHttpParams {
    /// URL to check (http:// or https://)
    url: String,
    /// Follow redirects (default: true)
    #[serde(default = "default_true")]
    follow_redirects: bool,
}

fn default_true() -> bool { true }

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckTlsChainParams {
    /// Hostname to inspect
    hostname: String,
    /// Port (default 443)
    #[serde(default)]
    port: Option<u16>,
    /// Check DANE/TLSA records
    #[serde(default)]
    check_dane: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckEmailSecurityParams {
    /// Domain to check
    domain: String,
    /// Custom DKIM selectors to check (default: ["default", "google", "selector1", "selector2"])
    #[serde(default)]
    dkim_selectors: Option<Vec<String>>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckMtaStsParams {
    /// Domain to check
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckPropagationGlobalParams {
    /// Domain to check
    domain: String,
    /// Record type to check (default: A)
    #[serde(default = "default_record_type")]
    record_type: String,
}

fn default_record_type() -> String { "A".to_string() }

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckPropagationParams {
    /// Domain to check
    domain: String,
    /// Record type to check
    #[serde(default = "default_record_type")]
    record_type: String,
    /// Resolvers (comma-separated IP addresses, optional)
    #[serde(default)]
    resolvers: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckDnssecParams {
    /// Domain to check
    domain: String,
    /// Record type (default: A)
    #[serde(default = "default_record_type")]
    record_type: String,
    /// Custom resolver IP (optional)
    #[serde(default)]
    resolver_ip: Option<String>,
    /// Verbose output
    #[serde(default)]
    verbose: bool,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct TraceResolutionParams {
    /// Domain to trace
    domain: String,
    /// Record type (default: A)
    #[serde(default = "default_record_type")]
    record_type: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckOcspParams {
    /// Hostname to check
    hostname: String,
    /// Port (default 443)
    #[serde(default = "default_port")]
    port: u16,
}

fn default_port() -> u16 { 443 }

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckStartTlsParams {
    /// Hostname to check
    hostname: String,
    /// Port (25 for SMTP, 143 for IMAP, 110 for POP3)
    port: u16,
    /// Protocol (Smtp, Imap, Pop3)
    protocol: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckDomainHealthParams {
    /// Domain to assess
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckCaaParams {
    /// Domain to check
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckBimiParams {
    /// Domain to check
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckCtParams {
    /// Hostname to check
    hostname: String,
    /// Port (default 443)
    #[serde(default = "default_port")]
    port: u16,
    /// Expected CAs for unexpected cert detection (optional)
    #[serde(default)]
    expected_cas: Option<Vec<String>>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct BenchmarkLatencyParams {
    /// Domain to benchmark
    domain: String,
    /// Transports to test (comma-separated: System, DoH, DoT, DoQ, or IP address) (optional)
    #[serde(default)]
    transports: Option<String>,
    /// Record type to query (default: "A")
    #[serde(default)]
    record_type: Option<String>,
    /// Number of rounds to run (default: 3)
    #[serde(default)]
    rounds: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckWhoisParams {
    /// Domain to check
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckSubdomainsParams {
    /// Domain to check for subdomains
    domain: String,
    /// Extra subdomains to check in addition to default list
    #[serde(default)]
    extra_subdomains: Option<Vec<String>>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckPortsParams {
    /// Host to check ports on
    host: String,
    /// Custom ports to check (comma-separated, optional)
    #[serde(default)]
    ports: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckRdnsParams {
    /// IP address to check (IPv4 or IPv6)
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckDnsblParams {
    /// IP address to check against DNSBL services (IPv4 or IPv6)
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DetectCdnParams {
    /// URL to check for CDN/WAF headers
    url: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckDelegationParams {
    /// Domain to audit
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckIpInfoParams {
    /// IP address to check (IPv4 or IPv6)
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckTlsVulnsParams {
    /// Hostname to check
    hostname: String,
    /// Port (default 443)
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckTlsRptParams {
    /// Domain to check
    domain: String,
    /// Validate DNSSEC (default: false)
    #[serde(default)]
    dnssec: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckIpv6Params {
    /// Domain to check
    domain: String,
    /// Port to check (default 443)
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckArcParams {
    /// Domain to check ARC records for
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckCipherSuitesParams {
    /// Hostname to check
    hostname: String,
    /// Port (default 443)
    #[serde(default = "default_port")]
    port: u16,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckRpkiParams {
    /// IP address or CIDR prefix to check
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckDnsAmplificationParams {
    /// Domain to check
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckTracerouteParams {
    /// Host to trace route to
    host: String,
    /// Maximum hops (default 30)
    #[serde(default)]
    max_hops: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckWildcardDnsParams {
    /// Domain to check for wildcard DNS
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckZoneTransferParams {
    /// Domain to attempt zone transfer on
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckIpNoiseParams {
    /// IP address to check
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckDomainRiskParams {
    /// Domain to assess for registration risk
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckTechStackParams {
    /// URL to check for technology fingerprints
    url: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckCveParams {
    /// Software/version keyword to search for (e.g. "Apache 2.4", "WordPress 6.5")
    keyword: String,
    /// Maximum number of results to return (default 10, max 20)
    #[serde(default)]
    max_results: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckTyposquattingParams {
    /// Domain to check for typosquatting variants (e.g. "google.com")
    domain: String,
    /// Maximum mutations to generate (default 200, max 500)
    #[serde(default)]
    max_mutations: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckRedirectChainParams {
    /// URL to trace redirects for
    url: String,
    /// Maximum hops to follow (default 20)
    #[serde(default)]
    max_hops: Option<u32>,
    /// Check domain age for each redirect hop (opt-in due to latency)
    #[serde(default)]
    check_domain_age: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckParkedDomainParams {
    /// Domain to check for parking indicators
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckBrandImpersonationParams {
    /// Domain to check for brand impersonation
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckUrlReputationParams {
    /// URL to check against URLhaus malware/phishing database
    url: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckUrlAnalysisParams {
    /// URL to analyze for phishing and brand impersonation signals
    url: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckShodanIpParams {
    /// IP address to query (e.g. "8.8.8.8")
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckSshFingerprintParams {
    /// Host to connect to (e.g. "github.com")
    host: String,
    /// SSH port (default 22)
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckComplianceParams {
    /// Domain to assess
    domain: String,
    /// URL for HTTP/HTTPS checks (optional)
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckBgpRouteParams {
    /// IP address to check (e.g. "8.8.8.8")
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckDnsHijackingParams {
    /// Domain to check
    domain: String,
    /// Record type (default "A")
    #[serde(default)]
    record_type: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckSpfDeepParams {
    /// Domain to analyze
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckThreatIntelParams {
    /// Domain or IP to check
    target: String,
    /// Specific sources to include (optional, default: all)
    #[serde(default)]
    include_sources: Option<Vec<String>>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct ThreatIntelRiskScoreParams {
    /// Domain or IP to analyze
    target: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PhishingDetectionParams {
    /// Domain to check for phishing indicators
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct MalwareSourcesParams {
    /// IP address to check
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DomainTrustScoreParams {
    /// Domain to assess
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct IpTrustScoreParams {
    /// IP address to assess
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct SubdomainEnumerationParams {
    /// Domain to enumerate
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct WhoisEnrichmentParams {
    /// Domain to enrich
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DnsThreatMappingParams {
    /// Domain to map threats for
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DnsTakeoverRiskParams {
    /// Domain to assess for DNS takeover risk
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct SubdomainBruteforceParams {
    /// Domain to brute-force
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct TyposquatDetectionParams {
    /// Domain to check for typosquats
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct IpWhoisEnrichmentParams {
    /// IP address to enrich
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DomainAgeTimelineParams {
    /// Domain to analyze
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CertificateHistoryParams {
    /// Domain to check certificate history
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct ThreatActorInfraParams {
    /// Domain to map threat infrastructure
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DnsHistoryParams {
    /// Domain to analyze DNS history
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct IpGeolocationParams {
    /// IP address to geolocate
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct AsnLookupParams {
    /// IP address to look up ASN
    ip: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct WhoisPrivacyDetectionParams {
    /// Domain to check for WHOIS privacy
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct EmailSpoofingRiskParams {
    /// Domain to assess for email spoofing risk
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct TlsCertValidationParams {
    /// Domain to validate TLS certificate
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct InfrastructureOverlapParams {
    /// List of domains to check for infrastructure overlap
    domains: Vec<String>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct TechStackFingerprintingParams {
    /// Domain to fingerprint technology stack
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DomainReputationAnalysisParams {
    /// Domain to analyze reputation
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PolicyDefinitionParams {
    /// Policy name
    policy_name: String,
    /// Policy type: blocklist | allowlist | rate_limit | approval_gate
    policy_type: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DomainBlocklistParams {
    /// Domains to block
    domains: Vec<String>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct IpBlocklistParams {
    /// IPs to block
    ips: Vec<String>,
    /// Threat level: low | medium | high | critical
    threat_level: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct AllowlistParams {
    /// Domains to whitelist
    domains: Vec<String>,
    /// Reason for allowlisting
    reason: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct RateLimitPolicyParams {
    /// User ID
    user_id: String,
    /// Requests per minute
    requests_per_minute: u32,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct ApprovalGateParams {
    /// Operation type
    operation: String,
    /// Requester name
    requester: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct AuditLogQueryParams {
    /// Number of days to query
    #[serde(default = "default_audit_days")]
    days: u32,
}

fn default_audit_days() -> u32 { 30 }

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct ComplianceReportParams {
    /// Compliance framework: SOC2 | ISO27001 | HIPAA | GDPR | PCI-DSS
    framework: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct ToolCallControlParams {
    /// Tool name to control
    tool_name: String,
    /// Comma-separated allowed user IDs
    #[serde(default)]
    allowed_users: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct RiskClassificationParams {
    /// Domain or IP to classify
    target: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct QuarantineParams {
    /// Targets to quarantine
    targets: Vec<String>,
    /// Reason for quarantine
    reason: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PolicyViolationAlertParams {
    /// Domain causing violation
    domain: String,
    /// Violation type
    violation_type: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DataResidencyComplianceParams {
    /// Domain to check
    domain: String,
    /// Required region: EU | US | APAC | CA
    required_region: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct EncryptionStatusParams {
    /// Domain to verify
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PolicyExceptionParams {
    /// Target domain/IP
    target: String,
    /// Exception type: temporary | permanent
    exception_type: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct AuditTrailVerificationParams {
    /// Domain to verify
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PolicyEffectivenessParams {
    /// Days to analyze
    #[serde(default = "default_effectiveness_days")]
    days: u32,
}

fn default_effectiveness_days() -> u32 { 30 }

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct IncidentResponsePlaybookParams {
    /// Incident type: data_breach | malware | ransomware | ddos
    incident_type: String,
    /// Severity: low | medium | high | critical
    #[serde(default = "default_severity")]
    severity: String,
}

fn default_severity() -> String { "high".to_string() }

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct SecurityPostureAssessmentParams {
    /// Domain to assess
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct BreachSimulationParams {
    /// Simulation type: phishing | credential_theft | data_exfil | lateral_movement
    simulation_type: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PiiDetectionParams {
    /// Domain to scan for PII
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PiiAnonymizationParams {
    /// Domain with PII to anonymize
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DataRetentionPolicyParams {
    /// Domain for retention policy
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct GdprComplianceParams {
    /// Domain to assess
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct HipaaComplianceParams {
    /// Domain to assess
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PciDssComplianceParams {
    /// Domain to assess
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DataClassificationParams {
    /// Domain to classify
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DataMaskingParams {
    /// Domain to mask
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DataDeletionParams {
    /// Domain with data to delete
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DataSubjectAccessParams {
    /// Domain for request
    domain: String,
    /// Subject identifier (email, phone, SSN)
    subject_identifier: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct ConsentManagementParams {
    /// Domain for consent
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CryptographicSignatureParams {
    /// Domain to sign
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct AuditTrailImmutabilityParams {
    /// Domain to verify
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PrivacyImpactAssessmentParams {
    /// Domain to assess
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct PrivacyBreachNotificationParams {
    /// Domain affected
    domain: String,
    /// Number of affected records
    breach_scope: u32,
    /// Breach type: unauthorized_access | data_exfiltration | ransomware
    breach_type: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct Rfc3161TimestampParams {
    /// Document hash
    document_hash: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct TimestampValidationParams {
    /// Timestamp token
    timestamp_token: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct SignstoreRekorParams {
    /// Artifact hash
    artifact_hash: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct RekorVerificationParams {
    /// Entry UUID
    entry_uuid: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct ZkProofGenerationParams {
    /// Circuit type: merkle_proof | range_proof | authentication
    circuit_type: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct ZkProofVerificationParams {
    /// Proof
    proof: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct EscrowAgreementParams {
    /// Payer
    payer: String,
    /// Payee
    payee: String,
    /// Amount
    amount: u64,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct EscrowReleaseParams {
    /// Escrow ID
    escrow_id: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct DigitalNotarizationParams {
    /// Document hash
    document_hash: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct NotarizationVerificationParams {
    /// Notarization ID
    notarization_id: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct KeyManagementParams {
    /// Key type: RSA | ECDSA | EdDSA
    key_type: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct KeyRotationParams {
    /// Key ID to rotate
    key_id: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct AuditTrailBindingParams {
    /// Number of audit entries
    audit_entries: usize,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct HsmIntegrationParams {
    /// Operation type: sign | encrypt | decrypt | generate_key
    operation: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CryptographicComplianceParams {
    /// Domain to verify
    domain: String,
}

#[derive(Clone)]
struct ShoheiServer;

#[tool_router(server_handler)]
impl ShoheiServer {
    #[tool(description = "Check DNS records for a domain")]
    async fn check_dns(
        &self,
        Parameters(CheckDnsParams { domain, record_types, transport }): Parameters<CheckDnsParams>,
    ) -> String {
        let transport_enum = match transport.as_deref() {
            Some("doh") | Some("doh-cloudflare") => Transport::Doh("https://1.1.1.1/dns-query".to_string()),
            Some("dot") | Some("dot-cloudflare") => Transport::Dot("1.1.1.1:853".to_string()),
            Some("doq") | Some("doq-cloudflare") => Transport::Doq("1.1.1.1:853".to_string()),
            Some(addr) => Transport::Server(addr.to_string()),
            None => Transport::System,
        };

        let req = DnsCheckRequest {
            domain,
            record_types: record_types.unwrap_or_else(|| vec!["A".to_string()]),
            transport: transport_enum,
            ..Default::default()
        };
        match shohei::api::check_dns(&req).await {
            Ok(results) => serde_json::to_string_pretty(&results).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check HTTP(S) endpoint reachability and headers")]
    async fn check_http(
        &self,
        Parameters(CheckHttpParams { url, follow_redirects }): Parameters<CheckHttpParams>,
    ) -> String {
        let req = HttpCheckRequest {
            url,
            follow_redirects,
            timeout_secs: 10,
        };
        match shohei::api::check_http(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Inspect TLS certificate chain for a hostname")]
    async fn check_tls_chain(
        &self,
        Parameters(CheckTlsChainParams {
            hostname,
            port,
            check_dane,
        }): Parameters<CheckTlsChainParams>,
    ) -> String {
        let req = TlsCheckRequest {
            hostname,
            port: port.unwrap_or(443),
            check_dane: check_dane.unwrap_or(false),
            timeout_secs: 10,
        };
        match shohei::api::check_tls_chain(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check email security (MX, SPF, DKIM, DMARC)")]
    async fn check_email_security(
        &self,
        Parameters(CheckEmailSecurityParams { domain, dkim_selectors }): Parameters<CheckEmailSecurityParams>,
    ) -> String {
        let req = EmailSecurityRequest {
            domain,
            timeout_secs: 5,
            dkim_selectors: dkim_selectors.unwrap_or_else(|| vec![
                "default".to_string(),
                "google".to_string(),
                "selector1".to_string(),
                "selector2".to_string(),
            ]),
        };
        match shohei::api::check_email_security(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check MTA-STS policy for SMTP TLS enforcement")]
    async fn check_mta_sts(
        &self,
        Parameters(CheckMtaStsParams { domain }): Parameters<CheckMtaStsParams>,
    ) -> String {
        let req = MtaStsRequest {
            domain,
            timeout_secs: 5,
        };
        match shohei::api::check_mta_sts(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check OCSP revocation status for a certificate")]
    async fn check_ocsp(
        &self,
        Parameters(CheckOcspParams { hostname, port }): Parameters<CheckOcspParams>,
    ) -> String {
        let req = OcspCheckRequest {
            hostname,
            port,
            ocsp_responder_url: None,
            timeout_secs: 10,
        };
        match shohei::api::check_ocsp(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check STARTTLS capability for SMTP/IMAP/POP3")]
    async fn check_starttls(
        &self,
        Parameters(CheckStartTlsParams { hostname, port, protocol }): Parameters<CheckStartTlsParams>,
    ) -> String {
        let proto = match protocol.to_lowercase().as_str() {
            "smtp" => StartTlsProtocol::Smtp,
            "imap" => StartTlsProtocol::Imap,
            "pop3" => StartTlsProtocol::Pop3,
            _ => return format!("{{\"error\": \"unknown protocol {}\"}}", protocol),
        };

        let req = StartTlsCheckRequest {
            hostname,
            port,
            protocol: proto,
            timeout_secs: 10,
        };
        match shohei::api::check_starttls(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Comprehensive domain health assessment")]
    async fn check_domain_health(
        &self,
        Parameters(CheckDomainHealthParams { domain }): Parameters<CheckDomainHealthParams>,
    ) -> String {
        let req = DomainHealthRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_domain_health(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check CAA records for certificate issuance authorization")]
    async fn check_caa(
        &self,
        Parameters(CheckCaaParams { domain }): Parameters<CheckCaaParams>,
    ) -> String {
        let req = CaaCheckRequest {
            domain,
            issued_by_ca: None,
            timeout_secs: 5,
        };
        match shohei::api::check_caa(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check BIMI configuration for brand protection")]
    async fn check_bimi(
        &self,
        Parameters(CheckBimiParams { domain }): Parameters<CheckBimiParams>,
    ) -> String {
        let req = BimiCheckRequest {
            domain,
            timeout_secs: 5,
        };
        match shohei::api::check_bimi(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check Certificate Transparency logs")]
    async fn check_ct(
        &self,
        Parameters(CheckCtParams { hostname, port, expected_cas }): Parameters<CheckCtParams>,
    ) -> String {
        let req = CtCheckRequest {
            hostname,
            port,
            timeout_secs: 10,
            expected_cas,
        };
        match shohei::api::check_ct(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check DNS propagation across 6 global resolvers")]
    async fn check_propagation_global(
        &self,
        Parameters(CheckPropagationGlobalParams { domain, record_type }): Parameters<
            CheckPropagationGlobalParams,
        >,
    ) -> String {
        let req = PropagationRequest {
            domain: domain.clone(),
            record_type,
            resolvers: vec![
                PropagationResolver { name: "Google".to_string(), address: "8.8.8.8".to_string(), region: None },
                PropagationResolver { name: "Cloudflare".to_string(), address: "1.1.1.1".to_string(), region: None },
                PropagationResolver { name: "Quad9".to_string(), address: "9.9.9.9".to_string(), region: None },
                PropagationResolver { name: "OpenDNS".to_string(), address: "208.67.222.222".to_string(), region: None },
                PropagationResolver { name: "CleanBrowsing".to_string(), address: "185.228.168.168".to_string(), region: None },
                PropagationResolver { name: "Comodo".to_string(), address: "8.26.56.26".to_string(), region: None },
            ],
            timeout_secs: 5,
        };
        match shohei::api::check_propagation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check DNS propagation across custom resolvers (default: 6 global resolvers)")]
    async fn check_propagation(
        &self,
        Parameters(CheckPropagationParams { domain, record_type, resolvers }): Parameters<
            CheckPropagationParams,
        >,
    ) -> String {
        let resolver_list = if let Some(resolver_str) = resolvers {
            let mut list = Vec::new();
            for (idx, addr) in resolver_str.split(',').enumerate() {
                let addr = addr.trim().to_string();
                list.push(PropagationResolver {
                    name: format!("Resolver{}", idx + 1),
                    address: addr,
                    region: None,
                });
            }
            list
        } else {
            // Default: 6 global resolvers (same as check_propagation_global)
            vec![
                PropagationResolver { name: "Google".to_string(), address: "8.8.8.8".to_string(), region: None },
                PropagationResolver { name: "Cloudflare".to_string(), address: "1.1.1.1".to_string(), region: None },
                PropagationResolver { name: "Quad9".to_string(), address: "9.9.9.9".to_string(), region: None },
                PropagationResolver { name: "OpenDNS".to_string(), address: "208.67.222.222".to_string(), region: None },
                PropagationResolver { name: "CleanBrowsing".to_string(), address: "185.228.168.168".to_string(), region: None },
                PropagationResolver { name: "Comodo".to_string(), address: "8.26.56.26".to_string(), region: None },
            ]
        };

        let req = PropagationRequest {
            domain,
            record_type,
            resolvers: resolver_list,
            timeout_secs: 5,
        };
        match shohei::api::check_propagation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Validate DNSSEC chain of trust")]
    async fn check_dnssec(
        &self,
        Parameters(CheckDnssecParams { domain, record_type, resolver_ip, verbose }): Parameters<
            CheckDnssecParams,
        >,
    ) -> String {
        let req = DnssecCheckRequest {
            domain,
            record_type,
            resolver_ip,
            verbose,
        };
        match shohei::api::check_dnssec(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Trace DNS resolution path from root to authoritative")]
    async fn trace_resolution(
        &self,
        Parameters(TraceResolutionParams { domain, record_type }): Parameters<
            TraceResolutionParams,
        >,
    ) -> String {
        match shohei::api::trace_resolution(&domain, &record_type).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Benchmark DNS latency across transports")]
    async fn benchmark_latency(
        &self,
        Parameters(BenchmarkLatencyParams { domain, transports, record_type, rounds }): Parameters<
            BenchmarkLatencyParams,
        >,
    ) -> String {
        let mut bench_transports = vec![
            BenchTransport {
                transport: Transport::System,
                label: "System".to_string(),
            },
            BenchTransport {
                transport: Transport::Doh("https://1.1.1.1/dns-query".to_string()),
                label: "DoH-Cloudflare".to_string(),
            },
        ];

        if let Some(transport_str) = transports {
            bench_transports.clear();
            for (idx, t) in transport_str.split(',').enumerate() {
                let t = t.trim();
                let (transport, label) = match t.to_lowercase().as_str() {
                    "system" => (Transport::System, "System".to_string()),
                    "doh" | "doh-cloudflare" => (
                        Transport::Doh("https://1.1.1.1/dns-query".to_string()),
                        "DoH-Cloudflare".to_string(),
                    ),
                    "dot" | "dot-cloudflare" => (
                        Transport::Dot("1.1.1.1:853".to_string()),
                        "DoT-Cloudflare".to_string(),
                    ),
                    "doq" | "doq-cloudflare" => (
                        Transport::Doq("1.1.1.1:853".to_string()),
                        "DoQ-Cloudflare".to_string(),
                    ),
                    addr => {
                        (Transport::Server(addr.to_string()), format!("Server{}", idx + 1))
                    }
                };
                bench_transports.push(BenchTransport { transport, label });
            }
        }

        let req = LatencyBenchRequest {
            domain,
            record_type: record_type.unwrap_or_else(|| "A".to_string()),
            transports: bench_transports,
            rounds: rounds.unwrap_or(3),
            timeout_secs: 5,
        };
        match shohei::api::benchmark_latency(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check domain registration details and expiration")]
    async fn check_whois(
        &self,
        Parameters(CheckWhoisParams { domain }): Parameters<CheckWhoisParams>,
    ) -> String {
        let req = WhoisCheckRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_whois(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check common subdomains for DNS/HTTP/TLS validity")]
    async fn check_subdomains(
        &self,
        Parameters(CheckSubdomainsParams { domain, extra_subdomains }): Parameters<CheckSubdomainsParams>,
    ) -> String {
        let req = SubdomainCheckRequest {
            domain,
            timeout_secs: 10,
            extra_subdomains,
        };
        match shohei::api::check_common_subdomains(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check port reachability and service detection")]
    async fn check_ports(
        &self,
        Parameters(CheckPortsParams { host, ports }): Parameters<CheckPortsParams>,
    ) -> String {
        let port_list = ports.as_ref().and_then(|p| {
            let parsed: Result<Vec<u16>, _> = p.split(',')
                .map(|s| s.trim().parse::<u16>())
                .collect();
            parsed.ok()
        });

        let req = PortCheckRequest {
            host,
            ports: port_list,
            timeout_secs: 5,
        };
        match shohei::api::check_ports(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check reverse DNS and forward-confirmed reverse DNS (FCrDNS)")]
    async fn check_rdns(
        &self,
        Parameters(CheckRdnsParams { ip }): Parameters<CheckRdnsParams>,
    ) -> String {
        let req = RdnsCheckRequest {
            ip,
            timeout_secs: 10,
        };
        match shohei::api::check_rdns(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check IP reputation against DNSBL services")]
    async fn check_dnsbl(
        &self,
        Parameters(CheckDnsblParams { ip }): Parameters<CheckDnsblParams>,
    ) -> String {
        let req = DnsblCheckRequest {
            ip,
            timeout_secs: 10,
        };
        match shohei::api::check_dnsbl(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Detect CDN and WAF providers via HTTP headers")]
    async fn detect_cdn(
        &self,
        Parameters(DetectCdnParams { url }): Parameters<DetectCdnParams>,
    ) -> String {
        let req = CdnDetectRequest {
            url,
            timeout_secs: 10,
        };
        match shohei::api::detect_cdn(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check DNS delegation consistency (SOA serials, NS reachability)")]
    async fn check_delegation(
        &self,
        Parameters(CheckDelegationParams { domain }): Parameters<CheckDelegationParams>,
    ) -> String {
        let req = DelegationCheckRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_delegation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check IP information (ASN, geolocation, organization)")]
    async fn check_ip_info(
        &self,
        Parameters(CheckIpInfoParams { ip }): Parameters<CheckIpInfoParams>,
    ) -> String {
        let req = IpInfoCheckRequest {
            ip,
            timeout_secs: 10,
        };
        match shohei::api::check_ip_info(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check TLS protocol vulnerabilities (TLS 1.0/1.1/1.2/1.3 support, forward secrecy)")]
    async fn check_tls_vulns(
        &self,
        Parameters(CheckTlsVulnsParams { hostname, port }): Parameters<CheckTlsVulnsParams>,
    ) -> String {
        let req = TlsVulnCheckRequest {
            hostname,
            port: port.unwrap_or(443),
            timeout_secs: 10,
        };
        match shohei::api::check_tls_vulns(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check TLS-RPT (SMTP TLS Reporting Policy) record")]
    async fn check_tls_rpt(
        &self,
        Parameters(CheckTlsRptParams { domain, dnssec }): Parameters<CheckTlsRptParams>,
    ) -> String {
        let req = TlsRptRequest {
            domain,
            dnssec: dnssec.unwrap_or(false),
            timeout_secs: 10,
        };
        match shohei::api::check_tls_rpt(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check IPv6 dual-stack support (DNS AAAA, TCP, TLS, HTTP)")]
    async fn check_ipv6(
        &self,
        Parameters(CheckIpv6Params { domain, port }): Parameters<CheckIpv6Params>,
    ) -> String {
        let req = Ipv6CheckRequest {
            domain,
            port: port.unwrap_or(443),
            timeout_secs: 10,
        };
        match shohei::api::check_ipv6(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check ARC (Authenticated Received Chain) records for a domain")]
    async fn check_arc(
        &self,
        Parameters(CheckArcParams { domain }): Parameters<CheckArcParams>,
    ) -> String {
        let req = ArcCheckRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_arc(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check supported TLS cipher suites for a hostname")]
    async fn check_cipher_suites(
        &self,
        Parameters(CheckCipherSuitesParams { hostname, port }): Parameters<CheckCipherSuitesParams>,
    ) -> String {
        let req = CipherSuitesRequest {
            hostname,
            port,
            timeout_secs: 10,
            probe_weak: false,
        };
        match shohei::api::check_cipher_suites(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check RPKI (Resource Public Key Infrastructure) validity for an IP prefix")]
    async fn check_rpki(
        &self,
        Parameters(CheckRpkiParams { ip }): Parameters<CheckRpkiParams>,
    ) -> String {
        let req = RpkiCheckRequest { ip };
        match shohei::api::check_rpki(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check DNS amplification risk (query/response size ratio)")]
    async fn check_dns_amplification(
        &self,
        Parameters(CheckDnsAmplificationParams { domain }): Parameters<CheckDnsAmplificationParams>,
    ) -> String {
        let req = DnsAmplificationRequest {
            nameserver: "8.8.8.8".to_string(),
            port: 53,
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_dns_amplification(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Trace route to a host using ICMP echo requests")]
    async fn check_traceroute(
        &self,
        Parameters(CheckTracerouteParams { host, max_hops }): Parameters<CheckTracerouteParams>,
    ) -> String {
        let req = TracerouteRequest {
            hostname: host,
            max_hops: max_hops.unwrap_or(30),
            timeout_secs: 30,
        };
        match shohei::api::check_traceroute(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check for wildcard DNS records that could mask domain enumeration")]
    async fn check_wildcard_dns(
        &self,
        Parameters(CheckWildcardDnsParams { domain }): Parameters<CheckWildcardDnsParams>,
    ) -> String {
        let req = WildcardDnsRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_wildcard_dns(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Attempt DNS zone transfer (AXFR) against authoritative nameservers")]
    async fn check_zone_transfer(
        &self,
        Parameters(CheckZoneTransferParams { domain }): Parameters<CheckZoneTransferParams>,
    ) -> String {
        let req = shohei::api::zone_transfer::ZoneTransferRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::zone_transfer::check_zone_transfer(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Classify IP address using GreyNoise community API (no API key required)")]
    async fn check_ip_noise(
        &self,
        Parameters(CheckIpNoiseParams { ip }): Parameters<CheckIpNoiseParams>,
    ) -> String {
        let req = shohei::api::greynoise::GreyNoiseRequest {
            ip,
            timeout_secs: 10,
        };
        match shohei::api::greynoise::check_ip_noise(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Evaluate domain registration risk for phishing and squatting")]
    async fn check_domain_risk(
        &self,
        Parameters(CheckDomainRiskParams { domain }): Parameters<CheckDomainRiskParams>,
    ) -> String {
        let req = shohei::api::domain_risk::DomainRiskRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::domain_risk::check_domain_risk(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Identify web technologies (web server, language, CMS, frameworks)")]
    async fn check_tech_stack(
        &self,
        Parameters(CheckTechStackParams { url }): Parameters<CheckTechStackParams>,
    ) -> String {
        let req = shohei::api::TechFingerprintRequest {
            url,
            timeout_secs: 10,
        };
        match shohei::api::check_tech_stack(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Search for known CVEs in the NVD database (no API key required)")]
    async fn check_cve(
        &self,
        Parameters(CheckCveParams { keyword, max_results }): Parameters<CheckCveParams>,
    ) -> String {
        let req = shohei::api::CveLookupRequest {
            keyword,
            max_results: max_results.unwrap_or(10),
            timeout_secs: 10,
        };
        match shohei::api::check_cve(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Detect typosquatting variants of a domain")]
    async fn check_typosquatting(
        &self,
        Parameters(CheckTyposquattingParams { domain, max_mutations }): Parameters<CheckTyposquattingParams>,
    ) -> String {
        let req = shohei::api::TyposquatRequest {
            domain,
            timeout_secs: 10,
            max_mutations: max_mutations.unwrap_or(200),
        };
        match shohei::api::check_typosquatting(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Trace HTTP redirect chain from a URL")]
    async fn check_redirect_chain(
        &self,
        Parameters(CheckRedirectChainParams { url, max_hops, check_domain_age }): Parameters<CheckRedirectChainParams>,
    ) -> String {
        let req = shohei::api::RedirectChainRequest {
            url,
            timeout_secs: 10,
            max_hops: max_hops.unwrap_or(20),
            check_domain_age: check_domain_age.unwrap_or(false),
        };
        match shohei::api::check_redirect_chain(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check if a domain is parked for sale")]
    async fn check_parked_domain(
        &self,
        Parameters(CheckParkedDomainParams { domain }): Parameters<CheckParkedDomainParams>,
    ) -> String {
        let req = shohei::api::ParkedDomainRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_parked_domain(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check if a domain impersonates known brands")]
    async fn check_brand_impersonation(
        &self,
        Parameters(CheckBrandImpersonationParams { domain }): Parameters<CheckBrandImpersonationParams>,
    ) -> String {
        let req = shohei::api::BrandImpersonationRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_brand_impersonation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check URL against URLhaus malware/phishing database (no API key required)")]
    async fn check_url_reputation(
        &self,
        Parameters(CheckUrlReputationParams { url }): Parameters<CheckUrlReputationParams>,
    ) -> String {
        let req = shohei::api::UrlhausRequest {
            url,
            timeout_secs: 10,
        };
        match shohei::api::check_url_reputation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Analyze URL structure for phishing and brand impersonation signals")]
    async fn check_url_analysis(
        &self,
        Parameters(CheckUrlAnalysisParams { url }): Parameters<CheckUrlAnalysisParams>,
    ) -> String {
        let req = shohei::api::UrlAnalysisRequest { url };
        match shohei::api::check_url_analysis(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Query Shodan InternetDB for open ports, CPEs, tags, and CVE associations (no API key required)")]
    async fn check_shodan_ip(
        &self,
        Parameters(CheckShodanIpParams { ip }): Parameters<CheckShodanIpParams>,
    ) -> String {
        let req = shohei::api::ShodanInternetDbRequest {
            ip,
            timeout_secs: 10,
        };
        match shohei::api::check_shodan_ip(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Compute HASSH SSH fingerprint from server KEXINIT packet")]
    async fn check_ssh_fingerprint(
        &self,
        Parameters(CheckSshFingerprintParams { host, port }): Parameters<CheckSshFingerprintParams>,
    ) -> String {
        let req = shohei::api::SshFingerprintRequest {
            host,
            port: port.unwrap_or(22),
            timeout_secs: 10,
        };
        match shohei::api::check_ssh_fingerprint(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Assess domain compliance against CIS, PCI-DSS, HIPAA, and OWASP controls")]
    async fn check_compliance(
        &self,
        Parameters(CheckComplianceParams { domain, url }): Parameters<CheckComplianceParams>,
    ) -> String {
        let req = shohei::api::ComplianceRequest {
            domain,
            url,
            timeout_secs: 15,
        };
        match shohei::api::check_compliance(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Query RIPE STAT for BGP route, AS name, prefix visibility, and routing status (no API key required)")]
    async fn check_bgp_route(
        &self,
        Parameters(CheckBgpRouteParams { ip }): Parameters<CheckBgpRouteParams>,
    ) -> String {
        let req = shohei::api::BgpRouteRequest {
            ip,
            timeout_secs: 10,
        };
        match shohei::api::check_bgp_route(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Compare authoritative DNS answers vs public resolvers to detect DNS hijacking, cache poisoning, or split-horizon configuration")]
    async fn check_dns_hijacking(
        &self,
        Parameters(CheckDnsHijackingParams { domain, record_type }): Parameters<CheckDnsHijackingParams>,
    ) -> String {
        let req = shohei::api::DnsHijackingRequest {
            domain,
            record_type: record_type.unwrap_or_else(|| "A".to_string()),
            timeout_secs: 10,
        };
        match shohei::api::check_dns_hijacking(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Recursively resolve SPF include chains and count total DNS lookups against RFC 7208 limit of 10 (no API key required)")]
    async fn check_spf_deep(
        &self,
        Parameters(CheckSpfDeepParams { domain }): Parameters<CheckSpfDeepParams>,
    ) -> String {
        let req = shohei::api::SpfAnalysisRequest {
            domain,
            timeout_secs: 10,
        };
        match shohei::api::check_spf_deep(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Aggregate threat intelligence from 5+ sources (GreyNoise, Shodan, URLhaus, Brand Impersonation, CT) with unified risk scoring")]
    async fn check_threat_intel_aggregate(
        &self,
        Parameters(CheckThreatIntelParams { target, include_sources }): Parameters<CheckThreatIntelParams>,
    ) -> String {
        let req = shohei::api::ThreatIntelRequest {
            target,
            include_sources,
            timeout_secs: 30,
        };
        match shohei::api::check_threat_intel_aggregate(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Get detailed risk score breakdown (0-100) with per-source confidence and actionable recommendation")]
    async fn threat_intel_risk_score(
        &self,
        Parameters(ThreatIntelRiskScoreParams { target }): Parameters<ThreatIntelRiskScoreParams>,
    ) -> String {
        match shohei::api::threat_intel_risk_score(&target).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Detect phishing indicators (brand impersonation, suspicious URLs, new domain registration) with phishing score")]
    async fn phishing_detection_aggregate(
        &self,
        Parameters(PhishingDetectionParams { domain }): Parameters<PhishingDetectionParams>,
    ) -> String {
        match shohei::api::phishing_detection_aggregate(&domain, 30).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "List all threat intelligence sources that flagged an IP as malicious with confidence levels")]
    async fn malware_detected_sources(
        &self,
        Parameters(MalwareSourcesParams { ip }): Parameters<MalwareSourcesParams>,
    ) -> String {
        match shohei::api::malware_detected_sources(&ip, 30).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Calculate 5-dimensional domain trust score (0-100): DNS consistency, TLS validity, threat reputation, registration age, infrastructure maturity")]
    async fn check_domain_trust_score(
        &self,
        Parameters(DomainTrustScoreParams { domain }): Parameters<DomainTrustScoreParams>,
    ) -> String {
        let req = shohei::api::DomainTrustScoreRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::check_domain_trust_score(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Calculate 5-dimensional IP trust score (0-100): reverse DNS, TLS presence, threat reputation, BGP status, RPKI validity")]
    async fn check_ip_trust_score(
        &self,
        Parameters(IpTrustScoreParams { ip }): Parameters<IpTrustScoreParams>,
    ) -> String {
        let req = shohei::api::IpTrustScoreRequest {
            ip,
            timeout_secs: 30,
        };
        match shohei::api::check_ip_trust_score(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Enumerate subdomains via Certificate Transparency, WHOIS nameservers, and DNS resolution")]
    async fn enumerate_subdomains(
        &self,
        Parameters(SubdomainEnumerationParams { domain }): Parameters<SubdomainEnumerationParams>,
    ) -> String {
        let req = shohei::api::SubdomainEnumerationRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::enumerate_subdomains(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Enrich WHOIS data with registration details, nameservers, and DNSSEC status")]
    async fn enrich_whois(
        &self,
        Parameters(WhoisEnrichmentParams { domain }): Parameters<WhoisEnrichmentParams>,
    ) -> String {
        let req = shohei::api::WhoisEnrichmentRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::enrich_whois(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Map DNS domain to threat sources (GreyNoise, Shodan, URLhaus, etc.) with risk scoring")]
    async fn map_dns_threats(
        &self,
        Parameters(DnsThreatMappingParams { domain }): Parameters<DnsThreatMappingParams>,
    ) -> String {
        let req = shohei::api::DnsThreatMappingRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::map_dns_threats(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Assess DNS takeover risk by checking nameserver redundancy, responsiveness, and dangling records")]
    async fn assess_dns_takeover_risk(
        &self,
        Parameters(DnsTakeoverRiskParams { domain }): Parameters<DnsTakeoverRiskParams>,
    ) -> String {
        let req = shohei::api::DnsTakeoverRiskRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::assess_dns_takeover_risk(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Brute-force common subdomain prefixes (www, mail, api, admin, staging, etc.)")]
    async fn bruteforce_subdomains(
        &self,
        Parameters(SubdomainBruteforceParams { domain }): Parameters<SubdomainBruteforceParams>,
    ) -> String {
        let req = shohei::api::SubdomainBruteforceRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::bruteforce_subdomains(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Detect typosquat domain variants (character omission, swaps, vowel substitution)")]
    async fn detect_typosquats(
        &self,
        Parameters(TyposquatDetectionParams { domain }): Parameters<TyposquatDetectionParams>,
    ) -> String {
        let req = shohei::api::TyposquatDetectionRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::detect_typosquats(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Enrich IP address with WHOIS, BGP, and ASN information")]
    async fn enrich_ip_whois(
        &self,
        Parameters(IpWhoisEnrichmentParams { ip }): Parameters<IpWhoisEnrichmentParams>,
    ) -> String {
        let req = shohei::api::IpWhoisEnrichmentRequest {
            ip,
            timeout_secs: 30,
        };
        match shohei::api::enrich_ip_whois(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Analyze domain age and registration timeline (new/young/established/legacy)")]
    async fn analyze_domain_age(
        &self,
        Parameters(DomainAgeTimelineParams { domain }): Parameters<DomainAgeTimelineParams>,
    ) -> String {
        let req = shohei::api::DomainAgeTimelineRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::analyze_domain_age(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Retrieve domain certificate history from Certificate Transparency logs")]
    async fn get_certificate_history(
        &self,
        Parameters(CertificateHistoryParams { domain }): Parameters<CertificateHistoryParams>,
    ) -> String {
        let req = shohei::api::CertificateHistoryRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::get_certificate_history(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Map threat actor infrastructure (IPs, nameservers, ASNs) and threat scoring")]
    async fn map_threat_actor_infra(
        &self,
        Parameters(ThreatActorInfraParams { domain }): Parameters<ThreatActorInfraParams>,
    ) -> String {
        let req = shohei::api::ThreatActorInfraRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::map_threat_actor_infra(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Analyze current DNS configuration as historical snapshot for forensics")]
    async fn analyze_dns_history(
        &self,
        Parameters(DnsHistoryParams { domain }): Parameters<DnsHistoryParams>,
    ) -> String {
        let req = shohei::api::DnsHistoryRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::analyze_dns_history(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Get IP geolocation: country, region, city, coordinates, timezone, ISP")]
    async fn get_ip_geolocation(
        &self,
        Parameters(IpGeolocationParams { ip }): Parameters<IpGeolocationParams>,
    ) -> String {
        let req = shohei::api::IpGeolocationRequest {
            ip,
            timeout_secs: 30,
        };
        match shohei::api::get_ip_geolocation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Look up ASN (Autonomous System Number) and organization for IP address")]
    async fn lookup_asn(
        &self,
        Parameters(AsnLookupParams { ip }): Parameters<AsnLookupParams>,
    ) -> String {
        let req = shohei::api::AsnLookupRequest {
            ip,
            timeout_secs: 30,
        };
        match shohei::api::lookup_asn(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Detect WHOIS privacy protection (redacted/anonymized registrant information)")]
    async fn detect_whois_privacy(
        &self,
        Parameters(WhoisPrivacyDetectionParams { domain }): Parameters<WhoisPrivacyDetectionParams>,
    ) -> String {
        let req = shohei::api::WhoisPrivacyDetectionRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::detect_whois_privacy(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Assess email spoofing risk (SPF/DKIM/DMARC configuration analysis)")]
    async fn assess_email_spoofing_risk(
        &self,
        Parameters(EmailSpoofingRiskParams { domain }): Parameters<EmailSpoofingRiskParams>,
    ) -> String {
        let req = shohei::api::EmailSpoofingRiskRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::assess_email_spoofing_risk(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Validate TLS certificate: issuer, signature algorithm, expiry, trust level")]
    async fn validate_tls_cert(
        &self,
        Parameters(TlsCertValidationParams { domain }): Parameters<TlsCertValidationParams>,
    ) -> String {
        let req = shohei::api::TlsCertValidationRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::validate_tls_cert(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Detect infrastructure overlap between multiple domains (shared IPs, nameservers, ASNs)")]
    async fn detect_infrastructure_overlap(
        &self,
        Parameters(InfrastructureOverlapParams { domains }): Parameters<InfrastructureOverlapParams>,
    ) -> String {
        let req = shohei::api::InfrastructureOverlapRequest {
            domains,
            timeout_secs: 30,
        };
        match shohei::api::detect_infrastructure_overlap(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Fingerprint domain technology stack (web servers, frameworks, languages, tools)")]
    async fn fingerprint_tech_stack(
        &self,
        Parameters(TechStackFingerprintingParams { domain }): Parameters<TechStackFingerprintingParams>,
    ) -> String {
        let req = shohei::api::TechStackFingerprintingRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::fingerprint_tech_stack(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Analyze domain reputation: trust score, health, threats, age, email security")]
    async fn analyze_domain_reputation(
        &self,
        Parameters(DomainReputationAnalysisParams { domain }): Parameters<DomainReputationAnalysisParams>,
    ) -> String {
        let req = shohei::api::DomainReputationAnalysisRequest {
            domain,
            timeout_secs: 30,
        };
        match shohei::api::analyze_domain_reputation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Define governance policy (blocklist, allowlist, rate limit, approval gate)")]
    async fn define_policy(
        &self,
        Parameters(PolicyDefinitionParams { policy_name, policy_type }): Parameters<PolicyDefinitionParams>,
    ) -> String {
        let req = shohei::api::PolicyDefinitionRequest {
            policy_name,
            policy_type,
            rules: Vec::new(),
            enabled: true,
        };
        match shohei::api::define_policy(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Add domains to blocklist (malicious, phishing, spam, malware)")]
    async fn add_domain_blocklist(
        &self,
        Parameters(DomainBlocklistParams { domains }): Parameters<DomainBlocklistParams>,
    ) -> String {
        let req = shohei::api::DomainBlocklistRequest {
            domains,
            reason: None,
            expires_at: None,
        };
        match shohei::api::add_domain_blocklist(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Add IPs to reputation blocklist with threat level classification")]
    async fn add_ip_blocklist(
        &self,
        Parameters(IpBlocklistParams { ips, threat_level }): Parameters<IpBlocklistParams>,
    ) -> String {
        let req = shohei::api::IpReputationBlocklistRequest {
            ips,
            threat_level,
            reason: None,
        };
        match shohei::api::add_ip_blocklist(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Add domains to allowlist (trusted, verified partners)")]
    async fn add_allowlist(
        &self,
        Parameters(AllowlistParams { domains, reason }): Parameters<AllowlistParams>,
    ) -> String {
        let req = shohei::api::AllowlistRequest {
            domains,
            reason,
            trusted_until: None,
        };
        match shohei::api::add_allowlist(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Set rate limit policy for user (requests per minute/hour/day)")]
    async fn set_rate_limit_policy(
        &self,
        Parameters(RateLimitPolicyParams { user_id, requests_per_minute }): Parameters<RateLimitPolicyParams>,
    ) -> String {
        let req = shohei::api::RateLimitPolicyRequest {
            user_id,
            requests_per_minute,
            requests_per_hour: requests_per_minute * 60,
            requests_per_day: requests_per_minute * 1440,
        };
        match shohei::api::set_rate_limit_policy(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Create approval gate for sensitive operations (requires 2+ approvals)")]
    async fn create_approval_gate(
        &self,
        Parameters(ApprovalGateParams { operation, requester }): Parameters<ApprovalGateParams>,
    ) -> String {
        let req = shohei::api::ApprovalGateRequest {
            operation,
            requester,
            justification: "Governance operation".to_string(),
            urgency: "medium".to_string(),
        };
        match shohei::api::create_approval_gate(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Query audit logs for user actions and system events")]
    async fn query_audit_logs(
        &self,
        Parameters(AuditLogQueryParams { days }): Parameters<AuditLogQueryParams>,
    ) -> String {
        let req = shohei::api::AuditLogQueryRequest {
            user: None,
            action: None,
            days,
        };
        match shohei::api::query_audit_logs(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Generate compliance report (SOC2, ISO27001, HIPAA, GDPR, PCI-DSS)")]
    async fn generate_compliance_report(
        &self,
        Parameters(ComplianceReportParams { framework }): Parameters<ComplianceReportParams>,
    ) -> String {
        let req = shohei::api::ComplianceReportRequest {
            framework,
            period: "monthly".to_string(),
        };
        match shohei::api::generate_compliance_report(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Set tool call access control (restrict by user, domain, or rate limit)")]
    async fn set_tool_call_control(
        &self,
        Parameters(ToolCallControlParams { tool_name, allowed_users }): Parameters<ToolCallControlParams>,
    ) -> String {
        let users: Vec<String> = allowed_users
            .map(|u| u.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let req = shohei::api::ToolCallControlRequest {
            tool_name,
            allowed_users: users,
            allowed_domains: None,
            max_calls_per_day: None,
        };
        match shohei::api::set_tool_call_control(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Classify domain/IP by risk level (critical, high, medium, low, unknown)")]
    async fn classify_risk(
        &self,
        Parameters(RiskClassificationParams { target }): Parameters<RiskClassificationParams>,
    ) -> String {
        let req = shohei::api::RiskClassificationRequest {
            target,
            historical_data: true,
        };
        match shohei::api::classify_risk(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Quarantine suspicious domains/IPs pending review")]
    async fn quarantine_targets(
        &self,
        Parameters(QuarantineParams { targets, reason }): Parameters<QuarantineParams>,
    ) -> String {
        let req = shohei::api::QuarantineRequest {
            targets,
            reason,
            duration_hours: 72,
        };
        match shohei::api::quarantine_targets(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Alert on policy violations (blocklist match, rate limit, unauthorized access)")]
    async fn alert_policy_violation(
        &self,
        Parameters(PolicyViolationAlertParams { domain, violation_type }): Parameters<PolicyViolationAlertParams>,
    ) -> String {
        let req = shohei::api::PolicyViolationAlertRequest {
            domain,
            violation_type,
        };
        match shohei::api::alert_policy_violation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Check data residency compliance (EU, US, APAC, CA)")]
    async fn check_data_residency(
        &self,
        Parameters(DataResidencyComplianceParams { domain, required_region }): Parameters<DataResidencyComplianceParams>,
    ) -> String {
        let req = shohei::api::DataResidencyComplianceRequest {
            domain,
            required_region,
        };
        match shohei::api::check_data_residency(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Verify encryption status (TLS version, cipher strength, compliance)")]
    async fn verify_encryption_status(
        &self,
        Parameters(EncryptionStatusParams { domain }): Parameters<EncryptionStatusParams>,
    ) -> String {
        let req = shohei::api::EncryptionStatusRequest {
            domain,
        };
        match shohei::api::verify_encryption_status(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Create policy exception (temporary or permanent)")]
    async fn create_policy_exception(
        &self,
        Parameters(PolicyExceptionParams { target, exception_type }): Parameters<PolicyExceptionParams>,
    ) -> String {
        let req = shohei::api::PolicyExceptionRequest {
            target,
            exception_type,
            duration_days: Some(30),
            justification: "Governance exception".to_string(),
        };
        match shohei::api::create_policy_exception(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Verify audit trail integrity and completeness")]
    async fn verify_audit_trail(
        &self,
        Parameters(AuditTrailVerificationParams { domain }): Parameters<AuditTrailVerificationParams>,
    ) -> String {
        let req = shohei::api::AuditTrailVerificationRequest {
            domain,
            days: 30,
        };
        match shohei::api::verify_audit_trail(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Measure governance policy effectiveness and ROI")]
    async fn measure_policy_effectiveness(
        &self,
        Parameters(PolicyEffectivenessParams { days }): Parameters<PolicyEffectivenessParams>,
    ) -> String {
        let req = shohei::api::PolicyEffectivenessRequest {
            days,
        };
        match shohei::api::measure_policy_effectiveness(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Get incident response playbook with escalation procedures")]
    async fn get_incident_response_playbook(
        &self,
        Parameters(IncidentResponsePlaybookParams { incident_type, severity }): Parameters<IncidentResponsePlaybookParams>,
    ) -> String {
        let req = shohei::api::IncidentResponsePlaybookRequest {
            incident_type,
            severity,
        };
        match shohei::api::get_incident_response_playbook(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Assess security posture maturity level and improvement areas")]
    async fn assess_security_posture(
        &self,
        Parameters(SecurityPostureAssessmentParams { domain }): Parameters<SecurityPostureAssessmentParams>,
    ) -> String {
        let req = shohei::api::SecurityPostureAssessmentRequest {
            domain,
        };
        match shohei::api::assess_security_posture(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Run breach simulation / tabletop exercise (phishing, credential theft, data exfil, lateral movement)")]
    async fn run_breach_simulation(
        &self,
        Parameters(BreachSimulationParams { simulation_type }): Parameters<BreachSimulationParams>,
    ) -> String {
        let req = shohei::api::BreachSimulationRequest {
            simulation_type,
            scope: "organization_wide".to_string(),
        };
        match shohei::api::run_breach_simulation(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Detect personally identifiable information (PII) in domain/system")]
    async fn detect_pii(
        &self,
        Parameters(PiiDetectionParams { domain }): Parameters<PiiDetectionParams>,
    ) -> String {
        let req = shohei::api::PiiDetectionRequest {
            domain,
            scan_depth: "deep".to_string(),
        };
        match shohei::api::detect_pii(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Anonymize PII (redaction, pseudonymization, generalization)")]
    async fn anonymize_pii(
        &self,
        Parameters(PiiAnonymizationParams { domain }): Parameters<PiiAnonymizationParams>,
    ) -> String {
        let req = shohei::api::PiiAnonymizationRequest {
            domain,
            pii_types: vec!["email".to_string(), "phone".to_string(), "ssn".to_string()],
            retention_days: None,
        };
        match shohei::api::anonymize_pii(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Define data retention policy and auto-purge schedule")]
    async fn define_retention_policy(
        &self,
        Parameters(DataRetentionPolicyParams { domain }): Parameters<DataRetentionPolicyParams>,
    ) -> String {
        let req = shohei::api::DataRetentionPolicyRequest {
            domain,
            data_type: "customer_data".to_string(),
            retention_days: 365,
        };
        match shohei::api::define_retention_policy(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Assess GDPR compliance (processing, consent, DPIA, documentation)")]
    async fn assess_gdpr_compliance(
        &self,
        Parameters(GdprComplianceParams { domain }): Parameters<GdprComplianceParams>,
    ) -> String {
        let req = shohei::api::GdprComplianceRequest {
            domain,
            assessment_scope: "processing".to_string(),
        };
        match shohei::api::assess_gdpr_compliance(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Assess HIPAA compliance (technical, administrative, physical controls)")]
    async fn assess_hipaa_compliance(
        &self,
        Parameters(HipaaComplianceParams { domain }): Parameters<HipaaComplianceParams>,
    ) -> String {
        let req = shohei::api::HipaaComplianceRequest {
            domain,
            check_type: "technical".to_string(),
        };
        match shohei::api::assess_hipaa_compliance(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Assess PCI-DSS compliance for payment systems")]
    async fn assess_pci_dss_compliance(
        &self,
        Parameters(PciDssComplianceParams { domain }): Parameters<PciDssComplianceParams>,
    ) -> String {
        let req = shohei::api::PciDssComplianceRequest {
            domain,
            requirement: None,
        };
        match shohei::api::assess_pci_dss_compliance(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Classify data by sensitivity level (public, internal, confidential, restricted)")]
    async fn classify_data(
        &self,
        Parameters(DataClassificationParams { domain }): Parameters<DataClassificationParams>,
    ) -> String {
        let req = shohei::api::DataClassificationRequest {
            domain,
            data_inventory_provided: true,
        };
        match shohei::api::classify_data(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Apply data masking rules to sensitive fields")]
    async fn apply_data_masking(
        &self,
        Parameters(DataMaskingParams { domain }): Parameters<DataMaskingParams>,
    ) -> String {
        let req = shohei::api::DataMaskingRequest {
            domain,
            masking_rules: vec!["email_mask".to_string(), "phone_mask".to_string()],
        };
        match shohei::api::apply_data_masking(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Delete expired data according to retention policies")]
    async fn delete_expired_data(
        &self,
        Parameters(DataDeletionParams { domain }): Parameters<DataDeletionParams>,
    ) -> String {
        let req = shohei::api::DataDeletionRequest {
            domain,
            data_types: vec!["logs".to_string(), "backups".to_string()],
            reason: "retention_expired".to_string(),
        };
        match shohei::api::delete_expired_data(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Process data subject access request (DSAR / subject access rights)")]
    async fn process_data_subject_access(
        &self,
        Parameters(DataSubjectAccessParams { domain, subject_identifier }): Parameters<DataSubjectAccessParams>,
    ) -> String {
        let req = shohei::api::DataSubjectAccessRequest {
            domain,
            subject_identifier,
            data_types: None,
        };
        match shohei::api::process_data_subject_access(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Manage user consent preferences (marketing, analytics, processing)")]
    async fn manage_consent(
        &self,
        Parameters(ConsentManagementParams { domain }): Parameters<ConsentManagementParams>,
    ) -> String {
        let req = shohei::api::ConsentManagementRequest {
            domain,
            consent_type: "processing".to_string(),
        };
        match shohei::api::manage_consent(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Create cryptographic signature for audit trail (RSA, ECDSA, EdDSA)")]
    async fn sign_audit_trail(
        &self,
        Parameters(CryptographicSignatureParams { domain }): Parameters<CryptographicSignatureParams>,
    ) -> String {
        let req = shohei::api::CryptographicSignatureRequest {
            domain,
            algorithm: "ECDSA".to_string(),
            document_hash: "sha256".to_string(),
        };
        match shohei::api::sign_audit_trail(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Verify audit trail immutability (hash chain, blockchain, HSM)")]
    async fn verify_audit_immutability(
        &self,
        Parameters(AuditTrailImmutabilityParams { domain }): Parameters<AuditTrailImmutabilityParams>,
    ) -> String {
        let req = shohei::api::AuditTrailImmutabilityRequest {
            domain,
            days: 90,
        };
        match shohei::api::verify_audit_immutability(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Conduct privacy impact assessment (DPIA/PIA)")]
    async fn conduct_privacy_assessment(
        &self,
        Parameters(PrivacyImpactAssessmentParams { domain }): Parameters<PrivacyImpactAssessmentParams>,
    ) -> String {
        let req = shohei::api::PrivacyImpactAssessmentRequest {
            domain,
            processing_activity: "Data processing".to_string(),
        };
        match shohei::api::conduct_privacy_assessment(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Notify affected individuals of privacy breach (GDPR 72-hour requirement)")]
    async fn notify_privacy_breach(
        &self,
        Parameters(PrivacyBreachNotificationParams { domain, breach_scope, breach_type }): Parameters<PrivacyBreachNotificationParams>,
    ) -> String {
        let req = shohei::api::PrivacyBreachNotificationRequest {
            domain,
            breach_scope,
            breach_type,
        };
        match shohei::api::notify_privacy_breach(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Request RFC 3161 timestamp from TSA (timestamp authority)")]
    async fn request_rfc3161_timestamp(
        &self,
        Parameters(Rfc3161TimestampParams { document_hash }): Parameters<Rfc3161TimestampParams>,
    ) -> String {
        let req = shohei::api::Rfc3161TimestampRequest {
            document_hash,
            hash_algorithm: "SHA256".to_string(),
            tsa_url: None,
        };
        match shohei::api::request_rfc3161_timestamp(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Validate RFC 3161 timestamp token and TSA signature")]
    async fn validate_timestamp(
        &self,
        Parameters(TimestampValidationParams { timestamp_token }): Parameters<TimestampValidationParams>,
    ) -> String {
        let req = shohei::api::TimestampValidationRequest {
            timestamp_token,
            document_hash: "".to_string(),
        };
        match shohei::api::validate_timestamp(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Add entry to Sigstore Rekor transparency log (immutable audit trail)")]
    async fn add_sigstore_rekor_entry(
        &self,
        Parameters(SignstoreRekorParams { artifact_hash }): Parameters<SignstoreRekorParams>,
    ) -> String {
        let req = shohei::api::SignstoreRekorEntryRequest {
            artifact_hash,
            signature: "".to_string(),
            certificate: "".to_string(),
        };
        match shohei::api::add_sigstore_rekor_entry(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Verify Sigstore Rekor entry consistency and inclusion proofs")]
    async fn verify_rekor_entry(
        &self,
        Parameters(RekorVerificationParams { entry_uuid }): Parameters<RekorVerificationParams>,
    ) -> String {
        let req = shohei::api::RekorEntryVerificationRequest {
            entry_uuid,
            merkle_tree_leaf_hash: "".to_string(),
        };
        match shohei::api::verify_rekor_entry(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Generate zero-knowledge proof (merkle, range, authentication proofs)")]
    async fn generate_zk_proof(
        &self,
        Parameters(ZkProofGenerationParams { circuit_type }): Parameters<ZkProofGenerationParams>,
    ) -> String {
        let req = shohei::api::ZkProofGenerationRequest {
            statement: "".to_string(),
            witness: "".to_string(),
            circuit_type,
        };
        match shohei::api::generate_zk_proof(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Verify zero-knowledge proof (correctness and security)")]
    async fn verify_zk_proof(
        &self,
        Parameters(ZkProofVerificationParams { proof }): Parameters<ZkProofVerificationParams>,
    ) -> String {
        let req = shohei::api::ZkProofVerificationRequest {
            proof,
            verification_key: "".to_string(),
            statement: "".to_string(),
        };
        match shohei::api::verify_zk_proof(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Create escrow agreement with release conditions")]
    async fn create_escrow_agreement(
        &self,
        Parameters(EscrowAgreementParams { payer, payee, amount }): Parameters<EscrowAgreementParams>,
    ) -> String {
        let req = shohei::api::EscrowAgreementRequest {
            payer,
            payee,
            amount,
            release_conditions: Vec::new(),
        };
        match shohei::api::create_escrow_agreement(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Release funds from escrow upon condition satisfaction")]
    async fn release_escrow(
        &self,
        Parameters(EscrowReleaseParams { escrow_id }): Parameters<EscrowReleaseParams>,
    ) -> String {
        let req = shohei::api::EscrowReleaseRequest {
            escrow_id,
            release_reason: "Conditions satisfied".to_string(),
        };
        match shohei::api::release_escrow(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Notarize document digitally (blockchain, TSA, or ledger)")]
    async fn notarize_document(
        &self,
        Parameters(DigitalNotarizationParams { document_hash }): Parameters<DigitalNotarizationParams>,
    ) -> String {
        let req = shohei::api::DigitalNotarizationRequest {
            document_hash,
            document_type: "".to_string(),
            notary_type: "public_blockchain".to_string(),
        };
        match shohei::api::notarize_document(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Verify digital notarization (integrity and authenticity)")]
    async fn verify_notarization(
        &self,
        Parameters(NotarizationVerificationParams { notarization_id }): Parameters<NotarizationVerificationParams>,
    ) -> String {
        let req = shohei::api::NotarizationVerificationRequest {
            notarization_id,
            document_hash: "".to_string(),
        };
        match shohei::api::verify_notarization(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Generate and manage cryptographic keys (RSA, ECDSA, EdDSA)")]
    async fn manage_cryptographic_key(
        &self,
        Parameters(KeyManagementParams { key_type }): Parameters<KeyManagementParams>,
    ) -> String {
        let req = shohei::api::KeyManagementRequest {
            key_type,
            key_size: 2048,
            usage: "signing".to_string(),
        };
        match shohei::api::manage_cryptographic_key(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Rotate cryptographic key with transition period")]
    async fn rotate_key(
        &self,
        Parameters(KeyRotationParams { key_id }): Parameters<KeyRotationParams>,
    ) -> String {
        let req = shohei::api::KeyRotationRequest {
            key_id,
            new_key_size: None,
        };
        match shohei::api::rotate_key(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Bind audit trail entries cryptographically (hash chain, merkle tree)")]
    async fn bind_audit_trail(
        &self,
        Parameters(AuditTrailBindingParams { audit_entries }): Parameters<AuditTrailBindingParams>,
    ) -> String {
        let req = shohei::api::AuditTrailBindingRequest {
            audit_entries,
            binding_type: "hash_chain".to_string(),
        };
        match shohei::api::bind_audit_trail(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Perform cryptographic operations via Hardware Security Module (HSM)")]
    async fn integrate_hsm(
        &self,
        Parameters(HsmIntegrationParams { operation }): Parameters<HsmIntegrationParams>,
    ) -> String {
        let req = shohei::api::HsmIntegrationRequest {
            operation,
            hsm_slot: 0,
        };
        match shohei::api::integrate_hsm(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }

    #[tool(description = "Verify cryptographic compliance (FIPS140-2/3, Common Criteria)")]
    async fn verify_crypto_compliance(
        &self,
        Parameters(CryptographicComplianceParams { domain }): Parameters<CryptographicComplianceParams>,
    ) -> String {
        let req = shohei::api::CryptographicComplianceRequest {
            domain,
            standard: "FIPS140-3".to_string(),
        };
        match shohei::api::verify_crypto_compliance(&req).await {
            Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_default(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[shohei-mcp] Server started");
    ShoheiServer
        .serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    eprintln!("[shohei-mcp] Server exiting");
    Ok(())
}
