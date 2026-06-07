//! High-level library API for DNS diagnostics.
//!
//! This module provides clean, user-friendly entry points for library consumers.
//! All input types are serializable and easy to construct.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use shohei::api::{check_dns, DnsCheckRequest};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let results = check_dns(&DnsCheckRequest {
//!     domain: "example.com".to_string(),
//!     ..Default::default()
//! }).await?;
//! println!("Got {} answers", results[0].answers.len());
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

use crate::error::{Result, ShoheError};
use crate::resolver::QueryOptions;
use hickory_proto::rr::RecordType;

// ── Re-export key result types for library consumers ─────────────────────────
pub use crate::resolver::{DnsQueryResult, DnsQuery, DnsRecord, RecordData, TrustState};
pub use crate::resolver::iterative::{ResolutionTrace, ResolutionStep, StepResponseType};
pub use crate::dnssec::chain::{DnssecChain, DnssecStep, DnssecStepType};

// ── Transport: Serializable abstraction over hickory's ResolverConfig ────────
/// Transport layer for DNS queries.
///
/// Abstracts over UDP/TCP, DoH, DoT, and DoQ in a serializable enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "config")]
pub enum Transport {
    /// System resolver (default).
    #[serde(rename = "system")]
    System,

    /// Custom DNS server address (IP:port or IP with default port 53).
    #[serde(rename = "server")]
    Server(String),

    /// DNS-over-HTTPS URL (e.g., "https://dns.google/dns-query").
    #[serde(rename = "doh")]
    Doh(String),

    /// DNS-over-TLS server address (e.g., "1.1.1.1:853").
    #[serde(rename = "dot")]
    Dot(String),

    /// DNS-over-QUIC server address (e.g., "1.1.1.1:853").
    #[serde(rename = "doq")]
    Doq(String),
}

impl Default for Transport {
    fn default() -> Self {
        Transport::System
    }
}

// ── DnsCheckRequest: Clean, serializable input type ──────────────────────────
/// Request for a DNS query with multiple record types.
///
/// All fields are serializable and have sensible defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCheckRequest {
    /// Domain name to query.
    pub domain: String,

    /// Record types to query (e.g., "A", "AAAA", "MX", "TXT").
    /// If empty, defaults to ["A"].
    #[serde(default = "default_record_types")]
    pub record_types: Vec<String>,

    /// Transport layer configuration.
    #[serde(default)]
    pub transport: Transport,

    /// Enable DNSSEC validation in the response.
    #[serde(default)]
    pub validate_dnssec: bool,

    /// Query timeout in seconds (1–60).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Restrict to IPv4 only.
    #[serde(default)]
    pub ipv4_only: bool,

    /// Restrict to IPv6 only.
    #[serde(default)]
    pub ipv6_only: bool,

    /// Clear the Recursion Desired (RD) bit.
    #[serde(default)]
    pub no_recurse: bool,

    /// Force TCP transport (instead of UDP).
    #[serde(default)]
    pub force_tcp: bool,
}

fn default_record_types() -> Vec<String> {
    vec!["A".to_string()]
}

fn default_timeout() -> u64 {
    5
}

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

// ── DnssecCheckRequest ───────────────────────────────────────────────────────
/// Request to build and validate a DNSSEC chain of trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecCheckRequest {
    /// Domain name to validate.
    pub domain: String,

    /// Record type to validate (e.g., "A", "MX"). Defaults to "A".
    #[serde(default = "default_record_type")]
    pub record_type: String,

    /// Optional resolver IP to use (e.g., "8.8.8.8"). If None, uses system resolver.
    #[serde(default)]
    pub resolver_ip: Option<String>,

    /// Show verbose DNSSEC details (key tags, algorithms, etc.).
    #[serde(default)]
    pub verbose: bool,
}

fn default_record_type() -> String {
    "A".to_string()
}

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

// ── Entry-point functions ────────────────────────────────────────────────────

/// Query one or more DNS record types concurrently.
///
/// Returns one `DnsQueryResult` per record type, in the same order as requested.
///
/// # Example
///
/// ```rust,no_run
/// use shohei::api::{check_dns, DnsCheckRequest};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let results = check_dns(&DnsCheckRequest {
///     domain: "google.com".to_string(),
///     record_types: vec!["A".to_string(), "AAAA".to_string()],
///     ..Default::default()
/// }).await?;
/// # Ok(())
/// # }
/// ```
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

/// Build and validate the DNSSEC chain of trust from root to the target domain.
///
/// # Example
///
/// ```rust,no_run
/// use shohei::api::{check_dnssec, DnssecCheckRequest};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let chain = check_dnssec(&DnssecCheckRequest {
///     domain: "example.com".to_string(),
///     verbose: true,
///     ..Default::default()
/// }).await?;
/// # Ok(())
/// # }
/// ```
pub async fn check_dnssec(req: &DnssecCheckRequest) -> Result<DnssecChain> {
    if req.domain.is_empty() {
        return Err(ShoheError::Parse("domain cannot be empty".to_string()));
    }

    let rtype = RecordType::from_str(&req.record_type)
        .map_err(|_| ShoheError::Parse(format!("invalid record type: {}", req.record_type)))?;

    let resolver_ip = if let Some(ref ip_str) = req.resolver_ip {
        Some(
            IpAddr::from_str(ip_str)
                .map_err(|_| ShoheError::Parse(format!("invalid IP address: {}", ip_str)))?,
        )
    } else {
        None
    };

    crate::dnssec::chain::build_chain(&req.domain, rtype, resolver_ip, req.verbose).await
}

/// Walk the iterative resolution path from root servers to the authoritative nameserver.
///
/// # Example
///
/// ```rust,no_run
/// use shohei::api::trace_resolution;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let trace = trace_resolution("example.com", "A").await?;
/// # Ok(())
/// # }
/// ```
pub async fn trace_resolution(domain: &str, record_type: &str) -> Result<ResolutionTrace> {
    if domain.is_empty() {
        return Err(ShoheError::Parse("domain cannot be empty".to_string()));
    }

    let rtype = RecordType::from_str(record_type)
        .map_err(|_| ShoheError::Parse(format!("invalid record type: {}", record_type)))?;

    crate::resolver::iterative::trace(domain, rtype, None).await
}

// ── Helper functions ────────────────────────────────────────────────────────

/// Build transport configuration from the Transport enum.
async fn build_transport_config(
    transport: &Transport,
) -> Result<Option<(hickory_resolver::config::ResolverConfig, String)>> {
    match transport {
        Transport::System => Ok(None),
        Transport::Server(_) => Ok(None), // Server addr is handled separately
        Transport::Doh(url) => {
            let (config, label) = crate::transport::doh::build_doh_config(url)
                .await
                .map_err(|e| ShoheError::Transport(format!("DoH config failed: {}", e)))?;
            Ok(Some((config, label)))
        }
        Transport::Dot(addr) => {
            let (config, label) = crate::transport::dot::build_dot_config(addr)
                .await
                .map_err(|e| ShoheError::Transport(format!("DoT config failed: {}", e)))?;
            Ok(Some((config, label)))
        }
        Transport::Doq(addr) => {
            let (config, label) = crate::transport::doq::build_doq_config(addr)
                .await
                .map_err(|e| ShoheError::Transport(format!("DoQ config failed: {}", e)))?;
            Ok(Some((config, label)))
        }
    }
}

/// Parse server address from Transport enum.
fn parse_server_addr(transport: &Transport) -> Option<std::net::SocketAddr> {
    match transport {
        Transport::Server(addr_str) => {
            std::net::SocketAddr::from_str(addr_str)
                .or_else(|_| {
                    // Try parsing as IP without port (add default port 53)
                    std::net::IpAddr::from_str(addr_str).map(|ip| {
                        std::net::SocketAddr::new(ip, 53)
                    })
                })
                .ok()
        }
        _ => None,
    }
}
