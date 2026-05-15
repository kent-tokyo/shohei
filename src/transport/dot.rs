use std::net::IpAddr;
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};

use crate::error::{Result, ShoheError};

/// Parse a DoT address (HOST:PORT or just HOST) and build a ResolverConfig.
pub fn build_dot_config(addr_str: &str) -> Result<(ResolverConfig, String)> {
    let (host, _port) = if let Some(colon) = addr_str.rfind(':') {
        let port: u16 = addr_str[colon + 1..]
            .parse()
            .map_err(|_| ShoheError::Parse(format!("Invalid port in DoT address: {addr_str}")))?;
        (addr_str[..colon].to_string(), port)
    } else {
        (addr_str.to_string(), 853u16)
    };

    let ip: IpAddr = host
        .parse()
        .map_err(|e| ShoheError::Parse(format!("Invalid IP address for DoT '{host}': {e}")))?;

    let server_name: Arc<str> = host.clone().into();
    let ns = NameServerConfig::tls(ip, server_name);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);

    Ok((config, format!("{host}:{_port} (DoT)")))
}
