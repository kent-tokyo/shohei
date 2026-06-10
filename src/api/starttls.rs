//! STARTTLS capability checker for email protocols.

use serde::{Deserialize, Serialize};
use crate::error::{Result, ShoheError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    Ok(StartTlsCheckResult {
        hostname: req.hostname.clone(),
        port: req.port,
        protocol: req.protocol.clone(),
        starttls_supported,
        error: None,
    })
}

async fn check_smtp_starttls(mut stream: TcpStream, timeout_secs: u64) -> bool {
    // Read server greeting (220 ...)
    let mut buf = vec![0; 1024];
    if timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf))
        .await
        .is_err()
    {
        return false;
    }

    // Send EHLO command
    if stream.write_all(b"EHLO test\r\n").await.is_err() {
        return false;
    }

    // Read EHLO response and check for STARTTLS
    buf.clear();
    buf.resize(2048, 0);
    if timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf))
        .await
        .is_err()
    {
        return false;
    }

    let response = String::from_utf8_lossy(&buf);
    response.to_lowercase().contains("starttls")
}

async fn check_imap_starttls(mut stream: TcpStream, timeout_secs: u64) -> bool {
    // Read server greeting (* OK [CAPABILITY ...])
    let mut buf = vec![0; 1024];
    if timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf))
        .await
        .is_err()
    {
        return false;
    }

    // Send CAPABILITY command
    if stream.write_all(b"CAPABILITY\r\n").await.is_err() {
        return false;
    }

    // Read CAPABILITY response
    buf.clear();
    buf.resize(2048, 0);
    if timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf))
        .await
        .is_err()
    {
        return false;
    }

    let response = String::from_utf8_lossy(&buf);
    response.to_uppercase().contains("STARTTLS")
}

async fn check_pop3_starttls(mut stream: TcpStream, timeout_secs: u64) -> bool {
    // Read server greeting (+OK ...)
    let mut buf = vec![0; 1024];
    if timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf))
        .await
        .is_err()
    {
        return false;
    }

    // Send CAPA command
    if stream.write_all(b"CAPA\r\n").await.is_err() {
        return false;
    }

    // Read CAPA response
    buf.clear();
    buf.resize(2048, 0);
    if timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf))
        .await
        .is_err()
    {
        return false;
    }

    let response = String::from_utf8_lossy(&buf);
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
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StartTlsProtocol {
    Smtp,
    Imap,
    Pop3,
}
