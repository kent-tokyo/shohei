//! DNS amplification attack potential checker — measure response size ratio.

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use crate::error::Result;

/// Check DNS amplification potential for a nameserver.
pub async fn check_dns_amplification(req: &DnsAmplificationRequest) -> Result<DnsAmplificationResult> {
    let nameserver = &req.nameserver;
    let port = req.port;
    let domain = &req.domain;
    let timeout_secs = Duration::from_secs(req.timeout_secs);

    // Build DNS query for domain (A record)
    let query = build_dns_query(domain, 1)?;  // 1 = A record type
    let query_size = query.len();

    // Send UDP query to nameserver
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            return Ok(DnsAmplificationResult {
                nameserver: nameserver.clone(),
                domain: domain.clone(),
                query_size: query_size as u32,
                response_size: 0,
                amplification_factor: 0.0,
                risk_level: "error".to_string(),
                error: Some(format!("Socket bind failed: {}", e)),
            });
        }
    };

    let addr = format!("{}:{}", nameserver, port);
    if let Err(e) = socket.connect(&addr).await {
        return Ok(DnsAmplificationResult {
            nameserver: nameserver.clone(),
            domain: domain.clone(),
            query_size: query_size as u32,
            response_size: 0,
            amplification_factor: 0.0,
            risk_level: "error".to_string(),
            error: Some(format!("Connect failed: {}", e)),
        });
    }

    // Send query
    if let Err(e) = socket.send(&query).await {
        return Ok(DnsAmplificationResult {
            nameserver: nameserver.clone(),
            domain: domain.clone(),
            query_size: query_size as u32,
            response_size: 0,
            amplification_factor: 0.0,
            risk_level: "error".to_string(),
            error: Some(format!("Send failed: {}", e)),
        });
    }

    // Receive response
    let mut buf = vec![0; 4096];  // DNS responses up to 4KB (UDP limit)
    let response_size = match timeout(timeout_secs, socket.recv(&mut buf)).await {
        Ok(Ok(size)) => size,
        Ok(Err(e)) => {
            return Ok(DnsAmplificationResult {
                nameserver: nameserver.clone(),
                domain: domain.clone(),
                query_size: query_size as u32,
                response_size: 0,
                amplification_factor: 0.0,
                risk_level: "error".to_string(),
                error: Some(format!("Receive failed: {}", e)),
            });
        }
        Err(_) => {
            return Ok(DnsAmplificationResult {
                nameserver: nameserver.clone(),
                domain: domain.clone(),
                query_size: query_size as u32,
                response_size: 0,
                amplification_factor: 0.0,
                risk_level: "error".to_string(),
                error: Some("Timeout".to_string()),
            });
        }
    };

    // Calculate amplification factor
    let amplification_factor = response_size as f64 / query_size as f64;

    // Risk assessment
    let risk_level = if amplification_factor > 50.0 {
        "critical".to_string()
    } else if amplification_factor > 20.0 {
        "high".to_string()
    } else if amplification_factor > 10.0 {
        "medium".to_string()
    } else if amplification_factor > 1.0 {
        "low".to_string()
    } else {
        "none".to_string()
    };

    Ok(DnsAmplificationResult {
        nameserver: nameserver.clone(),
        domain: domain.clone(),
        query_size: query_size as u32,
        response_size: response_size as u32,
        amplification_factor,
        risk_level,
        error: None,
    })
}

fn build_dns_query(domain: &str, record_type: u8) -> Result<Vec<u8>> {
    // Validate domain name before constructing query
    if domain.is_empty() {
        return Err(crate::error::ShoheError::Parse("Domain cannot be empty".to_string()));
    }
    if domain.len() > 253 {
        return Err(crate::error::ShoheError::Parse("Domain length exceeds 253 bytes".to_string()));
    }

    // Validate domain labels
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(crate::error::ShoheError::Parse("Domain contains empty label".to_string()));
        }
        if label.len() > 63 {
            return Err(crate::error::ShoheError::Parse("Label exceeds 63 bytes".to_string()));
        }
        // Validate label characters: only alphanumeric, hyphen, and underscore
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(crate::error::ShoheError::Parse("Label contains invalid characters".to_string()));
        }
        // Labels cannot start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(crate::error::ShoheError::Parse("Label cannot start or end with hyphen".to_string()));
        }
    }

    // Simplified DNS query builder (valid minimal DNS query)
    let mut query = Vec::new();

    // Transaction ID (2 bytes): random
    query.push(0x12);
    query.push(0x34);

    // Flags (2 bytes): standard query (0x0000)
    query.push(0x00);
    query.push(0x00);

    // Question count (2 bytes): 1
    query.push(0x00);
    query.push(0x01);

    // Answer count (2 bytes): 0
    query.push(0x00);
    query.push(0x00);

    // Authority count (2 bytes): 0
    query.push(0x00);
    query.push(0x00);

    // Additional count (2 bytes): 0
    query.push(0x00);
    query.push(0x00);

    // Question section: encode domain name
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);  // Root label

    // Question type (2 bytes): record_type
    query.push(0x00);
    query.push(record_type);

    // Question class (2 bytes): IN (0x0001)
    query.push(0x00);
    query.push(0x01);

    Ok(query)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAmplificationRequest {
    /// Nameserver IP address (IPv4 or IPv6)
    pub nameserver: String,
    /// Port (default 53)
    #[serde(default = "default_port")]
    pub port: u16,
    /// Domain to query
    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_port() -> u16 {
    53
}

fn default_domain() -> String {
    "example.com".to_string()
}

fn default_timeout() -> u64 {
    crate::api::helpers::DEFAULT_REQUEST_TIMEOUT_SECS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAmplificationResult {
    pub nameserver: String,
    pub domain: String,
    pub query_size: u32,
    pub response_size: u32,
    pub amplification_factor: f64,
    /// "none", "low", "medium", "high", "critical", "error"
    pub risk_level: String,
    pub error: Option<String>,
}
