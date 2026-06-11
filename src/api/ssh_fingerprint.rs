//! SSH fingerprinting — compute HASSH from SSH KEXINIT packet.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

/// Request to compute SSH fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshFingerprintRequest {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_port() -> u16 { 22 }
fn default_timeout() -> u64 { 10 }

/// SSH fingerprint result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshFingerprintResult {
    pub host: String,
    pub port: u16,
    pub banner: Option<String>,
    pub software: Option<String>,
    pub hassh: Option<String>,
    pub hassh_algorithms: Option<String>,
    pub kex_algorithms: Option<Vec<String>>,
    pub encryption_algorithms: Option<Vec<String>>,
    pub mac_algorithms: Option<Vec<String>>,
    pub compression_algorithms: Option<Vec<String>>,
    pub error: Option<String>,
}

/// Compute HASSH SSH fingerprint from KEXINIT packet.
pub async fn check_ssh_fingerprint(req: &SshFingerprintRequest) -> Result<SshFingerprintResult> {
    let addr = format!("{}:{}", req.host, req.port);

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(req.timeout_secs),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Ok(SshFingerprintResult {
                host: req.host.clone(),
                port: req.port,
                banner: None,
                software: None,
                hassh: None,
                hassh_algorithms: None,
                kex_algorithms: None,
                encryption_algorithms: None,
                mac_algorithms: None,
                compression_algorithms: None,
                error: Some(format!("Connection failed: {}", e)),
            });
        }
        Err(_) => {
            return Ok(SshFingerprintResult {
                host: req.host.clone(),
                port: req.port,
                banner: None,
                software: None,
                hassh: None,
                hassh_algorithms: None,
                kex_algorithms: None,
                encryption_algorithms: None,
                mac_algorithms: None,
                compression_algorithms: None,
                error: Some("Connection timeout".to_string()),
            });
        }
    };

    // Step 1: Read SSH banner
    let mut banner_buf = vec![0u8; 512];
    let banner = match tokio::time::timeout(
        Duration::from_secs(req.timeout_secs),
        stream.read(&mut banner_buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            let s = String::from_utf8_lossy(&banner_buf[..n])
                .trim()
                .lines()
                .next()
                .map(|s| s.to_string());
            s
        }
        _ => None,
    };

    // Send client banner to continue SSH handshake
    if let Err(e) = stream.write_all(b"SSH-2.0-shohei-mcp_1.6.0\r\n").await {
        return Ok(SshFingerprintResult {
            host: req.host.clone(),
            port: req.port,
            banner,
            software: None,
            hassh: None,
            hassh_algorithms: None,
            kex_algorithms: None,
            encryption_algorithms: None,
            mac_algorithms: None,
            compression_algorithms: None,
            error: Some(format!("Failed to send client banner: {}", e)),
        });
    }

    // Step 2: Read KEXINIT packet
    let mut len_buf = [0u8; 4];
    if let Err(e) = tokio::time::timeout(
        Duration::from_secs(req.timeout_secs),
        stream.read_exact(&mut len_buf),
    )
    .await
    {
        return Ok(SshFingerprintResult {
            host: req.host.clone(),
            port: req.port,
            banner,
            software: None,
            hassh: None,
            hassh_algorithms: None,
            kex_algorithms: None,
            encryption_algorithms: None,
            mac_algorithms: None,
            compression_algorithms: None,
            error: Some(format!("Failed to read KEXINIT length: {}", e)),
        });
    }

    let packet_len = u32::from_be_bytes(len_buf) as usize;
    if packet_len > 1024 * 1024 {
        return Ok(SshFingerprintResult {
            host: req.host.clone(),
            port: req.port,
            banner,
            software: None,
            hassh: None,
            hassh_algorithms: None,
            kex_algorithms: None,
            encryption_algorithms: None,
            mac_algorithms: None,
            compression_algorithms: None,
            error: Some("KEXINIT packet too large".to_string()),
        });
    }

    let mut packet_buf = vec![0u8; packet_len];
    if let Err(e) = tokio::time::timeout(
        Duration::from_secs(req.timeout_secs),
        stream.read_exact(&mut packet_buf),
    )
    .await
    {
        return Ok(SshFingerprintResult {
            host: req.host.clone(),
            port: req.port,
            banner,
            software: None,
            hassh: None,
            hassh_algorithms: None,
            kex_algorithms: None,
            encryption_algorithms: None,
            mac_algorithms: None,
            compression_algorithms: None,
            error: Some(format!("Failed to read KEXINIT packet: {}", e)),
        });
    }

    // Step 3: Parse KEXINIT
    if packet_buf.len() < 20 {
        return Ok(SshFingerprintResult {
            host: req.host.clone(),
            port: req.port,
            banner,
            software: None,
            hassh: None,
            hassh_algorithms: None,
            kex_algorithms: None,
            encryption_algorithms: None,
            mac_algorithms: None,
            compression_algorithms: None,
            error: Some("KEXINIT packet too short".to_string()),
        });
    }

    let _padding_len = packet_buf[0] as usize;
    let msg_type = packet_buf[1];

    if msg_type != 20 {
        return Ok(SshFingerprintResult {
            host: req.host.clone(),
            port: req.port,
            banner,
            software: None,
            hassh: None,
            hassh_algorithms: None,
            kex_algorithms: None,
            encryption_algorithms: None,
            mac_algorithms: None,
            compression_algorithms: None,
            error: Some(format!("Expected SSH_MSG_KEXINIT (20), got {}", msg_type)),
        });
    }

    let payload = &packet_buf[2..];
    if payload.len() < 16 {
        return Ok(SshFingerprintResult {
            host: req.host.clone(),
            port: req.port,
            banner,
            software: None,
            hassh: None,
            hassh_algorithms: None,
            kex_algorithms: None,
            encryption_algorithms: None,
            mac_algorithms: None,
            compression_algorithms: None,
            error: Some("KEXINIT payload too short (missing cookie)".to_string()),
        });
    }

    // Skip cookie (16 bytes)
    let mut offset = 16;

    // Parse 10 name-list fields
    let mut name_lists = Vec::new();
    for _ in 0..10 {
        if offset + 4 > payload.len() {
            return Ok(SshFingerprintResult {
                host: req.host.clone(),
                port: req.port,
                banner,
                software: None,
                hassh: None,
                hassh_algorithms: None,
                kex_algorithms: None,
                encryption_algorithms: None,
                mac_algorithms: None,
                compression_algorithms: None,
                error: Some("KEXINIT payload truncated at name-list length".to_string()),
            });
        }

        let len = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + len > payload.len() {
            return Ok(SshFingerprintResult {
                host: req.host.clone(),
                port: req.port,
                banner,
                software: None,
                hassh: None,
                hassh_algorithms: None,
                kex_algorithms: None,
                encryption_algorithms: None,
                mac_algorithms: None,
                compression_algorithms: None,
                error: Some("KEXINIT payload truncated at name-list value".to_string()),
            });
        }

        let name_list_str = String::from_utf8_lossy(&payload[offset..offset + len]).to_string();
        name_lists.push(name_list_str);
        offset += len;
    }

    if name_lists.len() < 4 {
        return Ok(SshFingerprintResult {
            host: req.host.clone(),
            port: req.port,
            banner,
            software: None,
            hassh: None,
            hassh_algorithms: None,
            kex_algorithms: None,
            encryption_algorithms: None,
            mac_algorithms: None,
            compression_algorithms: None,
            error: Some("Insufficient name-lists in KEXINIT".to_string()),
        });
    }

    // Extract algorithm fields: 0=kex, 2=enc_c2s, 4=mac_c2s, 6=comp_c2s
    let kex_algs = name_lists[0].clone();
    let enc_algs = name_lists[2].clone();
    let mac_algs = name_lists[4].clone();
    let comp_algs = name_lists[6].clone();

    // Compute HASSH
    let hassh_str = format!("{};{};{};{}", kex_algs, enc_algs, mac_algs, comp_algs);
    let hassh_digest = md5::compute(hassh_str.as_bytes());
    let hassh = format!("{:x}", hassh_digest);

    // Extract software version from banner
    let software = banner.as_ref().and_then(|b| {
        b.split_whitespace().next_back().map(|s| s.to_string())
    });

    Ok(SshFingerprintResult {
        host: req.host.clone(),
        port: req.port,
        banner,
        software,
        hassh: Some(hassh),
        hassh_algorithms: Some(hassh_str),
        kex_algorithms: Some(kex_algs.split(',').map(|s| s.to_string()).collect()),
        encryption_algorithms: Some(enc_algs.split(',').map(|s| s.to_string()).collect()),
        mac_algorithms: Some(mac_algs.split(',').map(|s| s.to_string()).collect()),
        compression_algorithms: Some(comp_algs.split(',').map(|s| s.to_string()).collect()),
        error: None,
    })
}
