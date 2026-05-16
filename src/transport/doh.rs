use std::net::SocketAddr;
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};

use crate::error::{Result, ShoheError};
use crate::transport::dot::parse_host_port;

/// Parse a DoH URL and build a ResolverConfig pointing at that endpoint.
pub async fn build_doh_config(url: &str) -> Result<(ResolverConfig, String)> {
    let (host, port, path) = parse_doh_url(url)?;
    let addr = resolve_host_async(&host, port).await?;
    let ip = addr.ip();

    let server_name: Arc<str> = host.clone().into();
    let path_arc: Option<Arc<str>> =
        if path.trim_end_matches('/').eq_ignore_ascii_case("/dns-query") {
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

    let (authority, path) = if let Some(slash) = rest.find('/') {
        (&rest[..slash], rest[slash..].to_string())
    } else {
        (rest, "/dns-query".to_string())
    };

    let (host, port) = parse_host_port(authority, 443)
        .map_err(|_| ShoheError::Parse(format!("Invalid DoH URL authority: {url}")))?;

    Ok((host, port, path))
}

async fn resolve_host_async(host: &str, port: u16) -> Result<SocketAddr> {
    // Use bracketed form for IPv6 literals
    let addr_str = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut addrs = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host(addr_str),
    )
    .await
    .map_err(|_| ShoheError::Transport(format!("Timeout resolving DoH host '{host}'")))?
    .map_err(|e| ShoheError::Transport(format!("Cannot resolve DoH host '{host}': {e}")))?;
    addrs
        .next()
        .ok_or_else(|| ShoheError::Transport(format!("No addresses for DoH host '{host}'")))
}
