//! Port reachability checker — TCP connection attempts and service detection.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Check port reachability and detect common services.
pub async fn check_ports(req: &PortCheckRequest) -> Result<PortCheckResult> {
    let ports = if let Some(ref port_list) = req.ports {
        port_list.clone()
    } else {
        // Default common ports
        vec![
            22,   // SSH
            25,   // SMTP
            53,   // DNS
            80,   // HTTP
            110,  // POP3
            143,  // IMAP
            443,  // HTTPS
            465,  // SMTPS
            587,  // SMTP TLS
            993,  // IMAPS
            995,  // POP3S
            3306, // MySQL
            5432, // PostgreSQL
            6379, // Redis
            8080, // HTTP Alt
        ]
    };

    let mut results = Vec::new();

    for port in ports {
        let status = check_port_status(&req.host, port, req.timeout_secs).await;
        results.push(status);
    }

    Ok(PortCheckResult {
        host: req.host.clone(),
        ports: results,
    })
}

async fn check_port_status(host: &str, port: u16, timeout_secs: u64) -> PortStatus {
    let addr = format!("{}:{}", host, port);

    match timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => {
            let service = guess_service(port);
            PortStatus {
                port,
                status: "open".to_string(),
                service,
            }
        }
        Ok(Err(_)) => {
            PortStatus {
                port,
                status: "closed".to_string(),
                service: None,
            }
        }
        Err(_) => {
            PortStatus {
                port,
                status: "filtered".to_string(),  // Timeout = likely filtered by firewall
                service: None,
            }
        }
    }
}

fn guess_service(port: u16) -> Option<String> {
    match port {
        22 => Some("SSH".to_string()),
        25 => Some("SMTP".to_string()),
        53 => Some("DNS".to_string()),
        80 => Some("HTTP".to_string()),
        110 => Some("POP3".to_string()),
        143 => Some("IMAP".to_string()),
        443 => Some("HTTPS".to_string()),
        465 => Some("SMTPS".to_string()),
        587 => Some("SMTP TLS".to_string()),
        993 => Some("IMAPS".to_string()),
        995 => Some("POP3S".to_string()),
        3306 => Some("MySQL".to_string()),
        5432 => Some("PostgreSQL".to_string()),
        6379 => Some("Redis".to_string()),
        8080 => Some("HTTP (Alt)".to_string()),
        8443 => Some("HTTPS (Alt)".to_string()),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortCheckRequest {
    pub host: String,
    /// Custom ports to check (default: common ports)
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortCheckResult {
    pub host: String,
    pub ports: Vec<PortStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStatus {
    pub port: u16,
    pub status: String,  // "open", "closed", "filtered"
    #[serde(default)]
    pub service: Option<String>,
}
