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
