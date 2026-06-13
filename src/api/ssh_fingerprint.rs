//! SSH fingerprinting — compute HASSH from SSH KEXINIT packet.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

/// Minimal RFC 1321 MD5 implementation (replaces the `md5` crate).
fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    ];
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0usize..64 {
            let (f, g) = match i {
                0..=15  => (d ^ (b & (c ^ d)), i),
                16..=31 => (c ^ (d & (b ^ c)), (5*i + 1) % 16),
                32..=47 => (b ^ c ^ d,          (3*i + 5) % 16),
                _       => (c ^ (b | !d),        (7*i)     % 16),
            };
            let temp = d;
            d = c; c = b;
            b = b.wrapping_add((a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g])).rotate_left(S[i]));
            a = temp;
        }
        a0 = a0.wrapping_add(a); b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c); d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes()); out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes()); out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

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
    const MAX_SSH_PACKET: usize = 32 * 1024;  // SSH KEXINIT typically ~200 bytes; 32KB is safe limit
    if packet_len > MAX_SSH_PACKET {
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
    let hassh_bytes = md5(hassh_str.as_bytes());
    let hassh = crate::api::helpers::hex_encode(&hassh_bytes);

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
