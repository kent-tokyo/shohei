//! Port reachability checker — TCP connection attempts and service detection.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::AsyncReadExt;

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

    let host = req.host.clone();
    let timeout_secs = req.timeout_secs;

    let handles: Vec<_> = ports
        .into_iter()
        .map(|port| {
            let h = host.clone();
            tokio::spawn(async move { check_port_status(&h, port, timeout_secs).await })
        })
        .collect();

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(status) = handle.await {
            results.push(status);
        }
    }
    results.sort_by_key(|s| s.port);

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
        Ok(Ok(mut stream)) => {
            let service = guess_service(port);
            let banner = grab_banner(&mut stream, timeout_secs).await;
            PortStatus {
                port,
                status: "open".to_string(),
                service,
                banner,
            }
        }
        Ok(Err(_)) => {
            PortStatus {
                port,
                status: "closed".to_string(),
                service: None,
                banner: None,
            }
        }
        Err(_) => {
            PortStatus {
                port,
                status: "filtered".to_string(),  // Timeout = likely filtered by firewall
                service: None,
                banner: None,
            }
        }
    }
}

async fn grab_banner(stream: &mut TcpStream, timeout_secs: u64) -> Option<String> {
    const MAX_BANNER_LEN: usize = 256;

    let mut buf = vec![0u8; 512];
    match timeout(
        Duration::from_secs(timeout_secs),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n]);
            // Sanitize: take first line, filter non-printable chars, truncate to safe length
            banner
                .trim()
                .lines()
                .next()
                .map(|s| {
                    s.chars()
                        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                        .take(MAX_BANNER_LEN)
                        .collect::<String>()
                })
        }
        _ => None,
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

fn default_timeout() -> u64 { crate::api::helpers::DEFAULT_REQUEST_TIMEOUT_SECS }

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
    #[serde(default)]
    pub banner: Option<String>,
}
