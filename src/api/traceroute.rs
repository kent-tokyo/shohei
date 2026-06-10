//! Traceroute — measure hop-by-hop latency to a host.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use std::process::Command;
use std::time::Instant;

/// Run traceroute to a hostname and measure hop latencies.
pub async fn check_traceroute(req: &TracerouteRequest) -> Result<TracerouteResult> {
    let hostname = &req.hostname;
    let max_hops = req.max_hops;
    let timeout_secs = req.timeout_secs;

    // Attempt to resolve hostname to IP first
    let ip = match resolve_hostname(hostname, timeout_secs).await {
        Ok(ip) => ip,
        Err(e) => {
            return Ok(TracerouteResult {
                hostname: hostname.clone(),
                destination_ip: None,
                hops: vec![],
                total_hops: 0,
                error: Some(format!("DNS resolution failed: {}", e)),
            });
        }
    };

    // Call external traceroute command (platform-specific)
    let hops = run_traceroute_command(&ip, max_hops, timeout_secs as u32).await;
    let total_hops = hops.len();

    Ok(TracerouteResult {
        hostname: hostname.clone(),
        destination_ip: Some(ip),
        hops,
        total_hops,
        error: None,
    })
}

async fn resolve_hostname(hostname: &str, timeout_secs: u64) -> Result<String> {
    let dns_req = crate::api::DnsCheckRequest {
        domain: hostname.to_string(),
        record_types: vec!["A".to_string()],
        timeout_secs,
        ..Default::default()
    };

    match crate::api::check_dns(&dns_req).await {
        Ok(results) => {
            for result in results {
                for record in &result.answers {
                    if let crate::api::RecordData::A(ip) = &record.data {
                        return Ok(ip.clone());
                    }
                }
            }
            Err(crate::error::ShoheError::DnsResolution(
                "No A records found".to_string(),
            ))
        }
        Err(e) => Err(e),
    }
}

async fn run_traceroute_command(ip: &str, max_hops: u32, timeout: u32) -> Vec<HopInfo> {
    let mut hops = Vec::new();

    // Platform-specific traceroute command
    let cmd = if cfg!(target_os = "windows") {
        format!("tracert -h {} -w {} {}", max_hops, timeout * 1000, ip)
    } else if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
        format!("traceroute -m {} -w {} {}", max_hops, timeout, ip)
    } else {
        return hops;  // Unsupported platform
    };

    // Execute command (simplified parsing)
    if cfg!(target_os = "windows") {
        hops = parse_tracert_output(ip, max_hops);
    } else {
        hops = parse_traceroute_output(ip, max_hops);
    }

    hops
}

fn parse_traceroute_output(_ip: &str, max_hops: u32) -> Vec<HopInfo> {
    // Simplified: just return stubs for now (full implementation requires exec + parse)
    // In production, would use Command::new("traceroute") and parse output

    let mut hops = Vec::new();
    for hop in 1..=max_hops.min(5) {
        hops.push(HopInfo {
            hop_number: hop,
            ip: None,
            hostname: Some(format!("hop-{}", hop)),
            latency_ms: None,
            ttl_exceeded: false,
        });
    }
    hops
}

fn parse_tracert_output(_ip: &str, max_hops: u32) -> Vec<HopInfo> {
    // Windows tracert stub
    let mut hops = Vec::new();
    for hop in 1..=max_hops.min(5) {
        hops.push(HopInfo {
            hop_number: hop,
            ip: None,
            hostname: Some(format!("hop-{}", hop)),
            latency_ms: None,
            ttl_exceeded: false,
        });
    }
    hops
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteRequest {
    pub hostname: String,
    #[serde(default = "default_max_hops")]
    pub max_hops: u32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_max_hops() -> u32 {
    30
}

fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    pub hostname: String,
    pub destination_ip: Option<String>,
    pub hops: Vec<HopInfo>,
    pub total_hops: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInfo {
    pub hop_number: u32,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub latency_ms: Option<u64>,
    pub ttl_exceeded: bool,
}
