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
struct CheckPropagationGlobalParams {
    /// Domain to check
    domain: String,
}

#[derive(Deserialize, schemars::JsonSchema, Clone)]
struct BenchmarkLatencyParams {
    /// Domain to benchmark
    domain: String,
    /// Transports to test (optional)
    #[serde(default)]
    transports: Option<Vec<String>>,
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
            Ok(results) => format!("{:#?}", results),
            Err(e) => format!("Error: {}", e),
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
            Ok(result) => format!("{:#?}", result),
            Err(e) => format!("Error: {}", e),
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
            Ok(result) => format!(
                "Score: {}/100, MX: {}, SPF: {}, DMARC: {}, DKIM: {}",
                result.score,
                result.mx.valid,
                result.spf.valid,
                result.dmarc.valid,
                result.dkim.iter().filter(|d| d.present).count()
            ),
            Err(e) => format!("Error: {}", e),
        }
    }

    #[tool(description = "Check DNS propagation across 6 global resolvers")]
    async fn check_propagation_global(
        &self,
        Parameters(CheckPropagationGlobalParams { domain }): Parameters<
            CheckPropagationGlobalParams,
        >,
    ) -> String {
        match shohei::api::check_propagation_global(&domain).await {
            Ok(result) => format!(
                "Propagation check: consistent={}, resolvers={}",
                result.consistent,
                result.results.len()
            ),
            Err(e) => format!("Error: {}", e),
        }
    }

    #[tool(description = "Benchmark DNS latency across transports")]
    async fn benchmark_latency(
        &self,
        Parameters(BenchmarkLatencyParams { domain, transports: _ }): Parameters<
            BenchmarkLatencyParams,
        >,
    ) -> String {
        let req = LatencyBenchRequest {
            domain,
            record_type: "A".to_string(),
            transports: vec![
                BenchTransport {
                    transport: Transport::System,
                    label: "System".to_string(),
                },
                BenchTransport {
                    transport: Transport::Doh("https://1.1.1.1/dns-query".to_string()),
                    label: "DoH-Cloudflare".to_string(),
                },
            ],
            rounds: 3,
            timeout_secs: 5,
        };
        match shohei::api::benchmark_latency(&req).await {
            Ok(result) => format!("{:#?}", result),
            Err(e) => format!("Error: {}", e),
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
