//! Reverse DNS / PTR validation — forward-confirmed reverse DNS (FCrDNS) check.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest};
use std::net::IpAddr;
use std::str::FromStr;

/// Check reverse DNS and validate forward-confirmed reverse DNS (FCrDNS).
pub async fn check_rdns(req: &RdnsCheckRequest) -> Result<RdnsCheckResult> {
    // Parse the IP address
    let ip_addr = match IpAddr::from_str(&req.ip) {
        Ok(addr) => addr,
        Err(_) => {
            return Ok(RdnsCheckResult {
                ip: req.ip.clone(),
                ptr_record: None,
                fcrdns_valid: false,
                error: Some(format!("Invalid IP address: {}", req.ip)),
            });
        }
    };

    // Step 1: Perform PTR lookup
    let ptr_domain = match ip_addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut arpa = String::new();
            for segment in segments.iter().rev() {
                for nibble in (0..4).rev() {
                    let hex = (segment >> (nibble * 4)) & 0xF;
                    arpa.push(char::from_digit(hex as u32, 16).unwrap());
                    arpa.push('.');
                }
            }
            arpa.push_str("ip6.arpa");
            arpa
        }
    };

    let dns_req = DnsCheckRequest {
        domain: ptr_domain.clone(),
        record_types: vec!["PTR".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    let ptr_record = match check_dns(&dns_req).await {
        Ok(results) => {
            if !results.is_empty() && !results[0].answers.is_empty() {
                // Extract PTR value from first answer
                use crate::resolver::RecordData;
                results[0]
                    .answers
                    .iter()
                    .find_map(|record| {
                        if let RecordData::Ptr(ptr_name) = &record.data {
                            Some(ptr_name.clone())
                        } else {
                            None
                        }
                    })
            } else {
                None
            }
        }
        Err(_) => None,
    };

    // Step 2: Validate FCrDNS (if PTR record found)
    let fcrdns_valid = if let Some(ref ptr_name) = ptr_record {
        // Resolve the PTR hostname back to IPs
        let forward_req = DnsCheckRequest {
            domain: ptr_name.clone(),
            record_types: vec!["A".to_string(), "AAAA".to_string()],
            timeout_secs: req.timeout_secs,
            ..Default::default()
        };

        match check_dns(&forward_req).await {
            Ok(results) => {
                use crate::resolver::RecordData;
                results.iter().any(|result| {
                    result.answers.iter().any(|record| {
                        match &record.data {
                            RecordData::A(ip_str) => ip_str == &req.ip,
                            RecordData::Aaaa(ip_str) => ip_str == &req.ip,
                            _ => false,
                        }
                    })
                })
            }
            Err(_) => false,
        }
    } else {
        false
    };

    Ok(RdnsCheckResult {
        ip: req.ip.clone(),
        ptr_record,
        fcrdns_valid,
        error: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdnsCheckRequest {
    pub ip: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdnsCheckResult {
    pub ip: String,
    pub ptr_record: Option<String>,
    pub fcrdns_valid: bool,
    pub error: Option<String>,
}
