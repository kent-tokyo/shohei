//! STARTTLS capability checker for email protocols.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Check STARTTLS capability and upgrade to TLS.
pub async fn check_starttls(req: &StartTlsCheckRequest) -> Result<StartTlsCheckResult> {
    let addr = format!("{}:{}", req.hostname, req.port);

    // Step 1: Connect via TCP
    let stream = match timeout(
        Duration::from_secs(req.timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            return Ok(StartTlsCheckResult {
                hostname: req.hostname.clone(),
                port: req.port,
                protocol: req.protocol.clone(),
                starttls_supported: false,
                tls_chain: None,
                error: Some("TCP connection timeout".to_string()),
            });
        }
    };

    // Step 2: Protocol-specific handshake
    let starttls_supported = match req.protocol {
        StartTlsProtocol::Smtp => check_smtp_starttls(stream, req.timeout_secs).await,
        StartTlsProtocol::Imap => check_imap_starttls(stream, req.timeout_secs).await,
        StartTlsProtocol::Pop3 => check_pop3_starttls(stream, req.timeout_secs).await,
    };

    // Step 3: If STARTTLS is supported, fetch TLS certificate chain via regular TLS check
    let tls_chain = if starttls_supported {
        match crate::api::check_tls_chain(&crate::api::TlsCheckRequest {
            hostname: req.hostname.clone(),
            port: req.port,
            check_dane: false,
            timeout_secs: req.timeout_secs,
        }).await {
            Ok(tls_result) => Some(tls_result),
            Err(_) => None,
        }
    } else {
        None
    };

    Ok(StartTlsCheckResult {
        hostname: req.hostname.clone(),
        port: req.port,
        protocol: req.protocol.clone(),
        starttls_supported,
        tls_chain,
        error: None,
    })
}

async fn check_smtp_starttls(stream: TcpStream, timeout_secs: u64) -> bool {
    const MAX_LINE_LEN: usize = 8192;  // Prevent unbounded memory allocation
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read server greeting (220 ...)
    if timeout(Duration::from_secs(timeout_secs), reader.read_line(&mut line))
        .await
        .is_err()
    {
        return false;
    }
    if line.len() > MAX_LINE_LEN {
        return false;  // Line too long: reject
    }

    // Send EHLO command
    if writer.write_all(b"EHLO test\r\n").await.is_err() {
        return false;
    }

    // Read EHLO response and check for STARTTLS
    let mut response = String::new();
    loop {
        line.clear();
        match timeout(Duration::from_secs(timeout_secs), reader.read_line(&mut line)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                if line.len() > MAX_LINE_LEN || response.len() + line.len() > MAX_LINE_LEN {
                    return false;  // Total response too long: reject
                }
                response.push_str(&line);
                // SMTP: continue-line starts with space/dash, final line starts with status code followed by space
                if line.len() > 4 && line.chars().nth(3) == Some(' ') {
                    break;
                }
            }
            _ => return false,
        }
    }

    response.to_lowercase().contains("starttls")
}

async fn check_imap_starttls(stream: TcpStream, timeout_secs: u64) -> bool {
    const MAX_LINE_LEN: usize = 8192;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read server greeting (* OK [CAPABILITY ...])
    if timeout(Duration::from_secs(timeout_secs), reader.read_line(&mut line))
        .await
        .is_err()
    {
        return false;
    }
    if line.len() > MAX_LINE_LEN {
        return false;
    }

    // Send CAPABILITY command (IMAP requires tag prefix)
    if writer.write_all(b"A001 CAPABILITY\r\n").await.is_err() {
        return false;
    }

    // Read CAPABILITY response until we get our tag response
    let mut response = String::new();
    loop {
        line.clear();
        match timeout(Duration::from_secs(timeout_secs), reader.read_line(&mut line)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                if line.len() > MAX_LINE_LEN || response.len() + line.len() > MAX_LINE_LEN {
                    return false;
                }
                response.push_str(&line);
                // IMAP: response ends when we see our tag (A001) followed by status
                if line.starts_with("A001 ") {
                    break;
                }
            }
            _ => return false,
        }
    }

    response.to_uppercase().contains("STARTTLS")
}

async fn check_pop3_starttls(stream: TcpStream, timeout_secs: u64) -> bool {
    const MAX_LINE_LEN: usize = 8192;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read server greeting (+OK ...)
    if timeout(Duration::from_secs(timeout_secs), reader.read_line(&mut line))
        .await
        .is_err()
    {
        return false;
    }
    if line.len() > MAX_LINE_LEN {
        return false;
    }

    // Send CAPA command
    if writer.write_all(b"CAPA\r\n").await.is_err() {
        return false;
    }

    // Read CAPA response until we get end-of-list marker
    let mut response = String::new();
    loop {
        line.clear();
        match timeout(Duration::from_secs(timeout_secs), reader.read_line(&mut line)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                if line.len() > MAX_LINE_LEN || response.len() + line.len() > MAX_LINE_LEN {
                    return false;
                }
                response.push_str(&line);
                // POP3: multi-line response ends with ".\r\n"
                if line.trim() == "." {
                    break;
                }
            }
            _ => return false,
        }
    }

    response.to_uppercase().contains("STLS")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartTlsCheckRequest {
    pub hostname: String,
    pub port: u16,
    pub protocol: StartTlsProtocol,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartTlsCheckResult {
    pub hostname: String,
    pub port: u16,
    pub protocol: StartTlsProtocol,
    pub starttls_supported: bool,
    #[serde(default)]
    pub tls_chain: Option<crate::api::tls::TlsCheckResult>,  // TODO: Full TLS inspection after STARTTLS upgrade
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StartTlsProtocol {
    Smtp,
    Imap,
    Pop3,
}
