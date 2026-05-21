use std::net::IpAddr;
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};

use crate::error::{Result, ShoheError};
use crate::transport::dot::parse_host_port;

/// Parse a DoQ address (`IP:PORT`, `[::1]:PORT`, or bare `IP`) and build a ResolverConfig.
/// Uses port 853 if omitted (same default as DoT).
pub async fn build_doq_config(addr_str: &str) -> Result<(ResolverConfig, String)> {
    let (host, port) = parse_host_port(addr_str, 853)?;

    let ip: IpAddr = host
        .parse()
        .map_err(|_| ShoheError::Parse(format!(
            "DoQ requires an IP address, not a hostname. Got: '{host}'. \
             Try: --doq 1.1.1.1:853"
        )))?;

    let server_name: Arc<str> = host.clone().into();
    let ns = NameServerConfig::quic(ip, server_name);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);

    Ok((config, format!("{host}:{port} (DoQ)")))
}
