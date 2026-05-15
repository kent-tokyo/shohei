use std::net::SocketAddr;
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};

use crate::error::{Result, ShoheError};

/// Parse a DoH URL and build a ResolverConfig pointing at that endpoint.
pub fn build_doh_config(url: &str) -> Result<(ResolverConfig, String)> {
    let (host, port, path) = parse_doh_url(url)?;
    let addr = resolve_host_sync(&host, port)?;
    let ip = addr.ip();

    let server_name: Arc<str> = host.clone().into();
    let path_arc: Option<Arc<str>> = if path == "/dns-query" {
        None
    } else {
        Some(path.into())
    };

    let ns = NameServerConfig::https(ip, server_name, path_arc);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);

    Ok((config, format!("{host}:{port} (DoH)")))
}

fn parse_doh_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        ShoheError::Parse(format!("DoH URL must start with https://: {url}"))
    })?;

    // Split authority (host[:port]) from path
    let (authority, path) = if let Some(slash) = rest.find('/') {
        (&rest[..slash], rest[slash..].to_string())
    } else {
        (rest, "/dns-query".to_string())
    };

    // Handle IPv6 bracketed literals: [::1] or [::1]:443
    let (host, port) = if authority.starts_with('[') {
        let bracket_end = authority.find(']').ok_or_else(|| {
            ShoheError::Parse(format!("Unclosed '[' in DoH URL: {url}"))
        })?;
        let host = authority[1..bracket_end].to_string();
        let port = if let Some(colon_after) = authority[bracket_end + 1..].strip_prefix(':') {
            colon_after.parse::<u16>().map_err(|_| {
                ShoheError::Parse(format!("Invalid port in DoH URL: {url}"))
            })?
        } else {
            443u16
        };
        (host, port)
    } else if let Some(colon) = authority.rfind(':') {
        // Distinguish hostname:port from bare hostname
        let port_str = &authority[colon + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            (authority[..colon].to_string(), port)
        } else {
            (authority.to_string(), 443u16)
        }
    } else {
        (authority.to_string(), 443u16)
    };

    Ok((host, port, path))
}

fn resolve_host_sync(host: &str, port: u16) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    // Format IPv6 addresses with brackets for ToSocketAddrs
    let addr_str = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    addr_str
        .to_socket_addrs()
        .map_err(|e| ShoheError::Transport(format!("Cannot resolve DoH host '{host}': {e}")))?
        .next()
        .ok_or_else(|| ShoheError::Transport(format!("No addresses for DoH host '{host}'")))
}
