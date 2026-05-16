use std::net::IpAddr;
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};

use crate::error::{Result, ShoheError};

/// Parse a DoT address (`IP:PORT`, `[::1]:PORT`, or bare `IP`) and build a ResolverConfig.
/// The address must be an IP (not a hostname) because TLS cert validation requires
/// the IP SAN. Use port 853 if omitted.
pub async fn build_dot_config(addr_str: &str) -> Result<(ResolverConfig, String)> {
    let (host, port) = parse_host_port(addr_str, 853)?;

    let ip: IpAddr = host
        .parse()
        .map_err(|_| ShoheError::Parse(format!(
            "DoT requires an IP address, not a hostname. Got: '{host}'. \
             Try: --dot 1.1.1.1:853"
        )))?;

    // For TLS, use the IP string as the server_name (IP SAN on public DoT servers).
    let server_name: Arc<str> = host.clone().into();
    let ns = NameServerConfig::tls(ip, server_name);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);

    Ok((config, format!("{host}:{port} (DoT)")))
}

/// Parse `host:port`, `[ipv6]:port`, or bare host (uses default_port).
pub(crate) fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    // IPv6 bracketed: [::1]:port or [::1]
    if s.starts_with('[') {
        let bracket_end = s.find(']').ok_or_else(|| {
            ShoheError::Parse(format!("Unclosed '[' in address: {s}"))
        })?;
        let host = s[1..bracket_end].to_string();
        let port = if let Some(rest) = s[bracket_end + 1..].strip_prefix(':') {
            rest.parse::<u16>().map_err(|_| {
                ShoheError::Parse(format!("Invalid port in address: {s}"))
            })?
        } else {
            default_port
        };
        return Ok((host, port));
    }

    // hostname:port or bare IPv4 — only treat as host:port when the host part contains no
    // colons (i.e. it is not a bare IPv6 address).  An alphanumeric but non-numeric port
    // string is an error rather than a silent fallback.
    if let Some(colon) = s.rfind(':') {
        let host_part = &s[..colon];
        let port_str = &s[colon + 1..];
        if !host_part.contains(':') {
            let port = port_str.parse::<u16>().map_err(|_| {
                ShoheError::Parse(format!(
                    "Invalid port in address '{s}': '{port_str}' is not a valid port number (1–65535)"
                ))
            })?;
            return Ok((host_part.to_string(), port));
        }
    }

    // Bare host or bare IPv6 without brackets (no port)
    Ok((s.to_string(), default_port))
}
