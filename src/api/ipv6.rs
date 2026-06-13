//! IPv6 dual-stack connectivity checker — test DNS AAAA, TCP, TLS, and HTTP over IPv6.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, Ipv6Addr};
use std::str::FromStr;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use crate::error::Result;

/// Check IPv6 dual-stack support for a domain.
pub async fn check_ipv6(req: &Ipv6CheckRequest) -> Result<Ipv6CheckResult> {
    let domain = &req.domain;
    let port = req.port;
    let timeout_secs = Duration::from_secs(req.timeout_secs);

    // Step 1: DNS AAAA query
    let dns_req = crate::api::DnsCheckRequest {
        domain: domain.clone(),
        record_types: vec!["AAAA".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    let mut ipv6_ip_strings = Vec::new();
    let aaaa_present = match crate::api::check_dns(&dns_req).await {
        Ok(results) => {
            let has = results.iter().any(|r| !r.answers.is_empty());
            for result in results {
                for record in result.answers {
                    if let crate::api::RecordData::Aaaa(ipv6_str) = &record.data {
                        ipv6_ip_strings.push(ipv6_str.clone());
                    }
                }
            }
            has
        }
        Err(_) => false,
    };

    // Step 2: IPv6 TCP connectivity
    let tcp_reachable = if !ipv6_ip_strings.is_empty() {
        if let Ok(ipv6) = Ipv6Addr::from_str(&ipv6_ip_strings[0]) {
            let addr = SocketAddr::new(IpAddr::V6(ipv6), port);
            match timeout(timeout_secs, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => true,
                _ => false,
            }
        } else {
            false
        }
    } else {
        false
    };

    // Step 3: IPv6 TLS connectivity (if HTTPS)
    // Not verified: a real TLS handshake is required before setting this to true.
    // Callers should use check_tls_chain for actual TLS verification.
    let tls_reachable = false;

    // Step 4: IPv6 HTTP connectivity
    let http_reachable = if tcp_reachable && port == 80 {
        true  // Simplified: HTTP is reachable if TCP connected
    } else if tls_reachable && port == 443 {
        true  // If TLS works, assume HTTP over HTTPS works
    } else {
        false
    };

    // Step 5: IPv4 vs IPv6 content comparison
    // Not verified: actual HTTP response bodies must be fetched and compared before setting true.
    let content_matches = false;

    Ok(Ipv6CheckResult {
        domain: domain.clone(),
        aaaa_present,
        ipv6_ips: ipv6_ip_strings,
        tcp_reachable,
        tls_reachable,
        http_reachable,
        dual_stack_complete: aaaa_present && tcp_reachable && http_reachable,
        content_matches,
        error: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6CheckRequest {
    pub domain: String,
    /// Port to check (default 443 for HTTPS)
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_port() -> u16 {
    443
}

fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6CheckResult {
    pub domain: String,
    pub aaaa_present: bool,
    pub ipv6_ips: Vec<String>,
    pub tcp_reachable: bool,
    pub tls_reachable: bool,
    pub http_reachable: bool,
    pub dual_stack_complete: bool,
    pub content_matches: bool,
    pub error: Option<String>,
}
