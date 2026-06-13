//! DNSBL / IP reputation checker — query multiple DNS blocklists in parallel.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest};
use std::net::IpAddr;
use std::str::FromStr;

/// Check IP reputation against multiple DNSBL services.
pub async fn check_dnsbl(req: &DnsblCheckRequest) -> Result<DnsblCheckResult> {
    // Parse the IP address
    let ip_addr = match IpAddr::from_str(&req.ip) {
        Ok(addr) => addr,
        Err(_) => {
            return Ok(DnsblCheckResult {
                ip: req.ip.clone(),
                listed: false,
                services: vec![],
                error: Some(format!("Invalid IP address: {}", req.ip)),
            });
        }
    };

    // Reverse IP for DNSBL query format
    let reversed_ip = reverse_ip(&ip_addr);
    let timeout = req.timeout_secs;

    // List of major DNSBL services
    let dnsbl_services = vec![
        ("zen.spamhaus.org", "Spamhaus ZEN"),
        ("b.barracudacentral.org", "Barracuda BRBL"),
        ("dnsbl.sorbs.net", "SORBS DNSBL"),
    ];

    // Query all DNSBL services in parallel
    let futures = dnsbl_services.iter().map(|(zone, name)| {
        let query_domain = format!("{}.{}", reversed_ip, zone);
        let name = name.to_string();
        async move {
            let dns_req = DnsCheckRequest {
                domain: query_domain,
                record_types: vec!["A".to_string()],
                timeout_secs: timeout,
                ..Default::default()
            };

            let is_listed = match check_dns(&dns_req).await {
                Ok(results) => {
                    !results.is_empty() && !results[0].answers.is_empty()
                }
                Err(_) => false,
            };

            DnsblServiceResult {
                service: name,
                listed: is_listed,
            }
        }
    });

    let handles: Vec<_> = futures.map(tokio::spawn).collect();
    let mut services = Vec::with_capacity(handles.len());
    for h in handles { if let Ok(v) = h.await { services.push(v); } }
    let listed = services.iter().any(|s| s.listed);

    Ok(DnsblCheckResult {
        ip: req.ip.clone(),
        listed,
        services,
        error: None,
    })
}

fn reverse_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut result = String::new();
            for segment in segments.iter().rev() {
                for nibble in (0..4).rev() {
                    let hex = (segment >> (nibble * 4)) & 0xF;
                    result.push(char::from_digit(hex as u32, 16).unwrap());
                    result.push('.');
                }
            }
            result.push_str("ip6.arpa");
            result
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblCheckRequest {
    /// IP address to check (IPv4 or IPv6)
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblCheckResult {
    pub ip: String,
    /// True if the IP is listed on any DNSBL service
    pub listed: bool,
    /// Results from each DNSBL service queried
    pub services: Vec<DnsblServiceResult>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblServiceResult {
    pub service: String,
    pub listed: bool,
}
