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
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct BenchmarkLatencyParams {
    /// Domain to benchmark
    domain: String,
    /// Transports to test (comma-separated: System, DoH, DoT, DoQ, or IP address) (optional)
    #[serde(default)]
    transports: Option<String>,
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
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct CheckPortsParams {
    /// Host to check ports on
    host: String,
    /// Custom ports to check (comma-separated, optional)
    #[serde(default)]
    ports: Option<String>,
}

#[derive(Clone)]
struct ShoheiServer;

#[tool_router(server_handler)]
impl ShoheiServer {
    #[tool(description = "Check DNS records for a domain")]
    async fn check_dns(
        &self,
        Parameters(CheckDnsParams { domain, record_types }): Parameters<CheckDnsParams>,
    ) -> String {
        let req = DnsCheckRequest {
            domain,
            record_types: record_types.unwrap_or_else(|| vec!["A".to_string()]),
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
        Parameters(CheckEmailSecurityParams { domain }): Parameters<CheckEmailSecurityParams>,
    ) -> String {
        let req = EmailSecurityRequest {
            domain,
            timeout_secs: 5,
            dkim_selectors: vec![
                "default".to_string(),
                "google".to_string(),
                "selector1".to_string(),
                "selector2".to_string(),
            ],
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
        Parameters(CheckCtParams { hostname, port }): Parameters<CheckCtParams>,
    ) -> String {
        let req = CtCheckRequest {
            hostname,
            port,
            timeout_secs: 10,
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
        Parameters(BenchmarkLatencyParams { domain, transports }): Parameters<
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
            record_type: "A".to_string(),
            transports: bench_transports,
            rounds: 3,
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
        Parameters(CheckSubdomainsParams { domain }): Parameters<CheckSubdomainsParams>,
    ) -> String {
        let req = SubdomainCheckRequest {
            domain,
            timeout_secs: 10,
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
