//! Advanced Email Security — DKIM key strength, MX server deep security.

use serde::{Deserialize, Serialize};
use crate::error::Result;

fn default_timeout() -> u64 { 10 }

// ── DKIM Key Strength ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimKeyStrengthRequest {
    pub domain: String,
    #[serde(default)]
    pub selectors: Option<Vec<String>>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimKeyResult {
    pub selector: String,
    pub key_type: String,
    pub key_bits: Option<usize>,
    pub strength: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimKeyStrengthResult {
    pub domain: String,
    pub keys: Vec<DkimKeyResult>,
    pub weakest_strength: String,
    pub risk_level: String,
    pub recommendations: Vec<String>,
}

fn estimate_rsa_bits_from_b64_len(b64_len: usize) -> usize {
    // Approximate: RSA-1024 ≈ 216 chars, RSA-2048 ≈ 392, RSA-4096 ≈ 736
    match b64_len {
        0..=224 => 1024,
        225..=404 => 2048,
        405..=740 => 4096,
        _ => 8192,
    }
}

fn parse_dkim_txt(txt: &str) -> Option<DkimKeyResult> {
    if !txt.contains("v=DKIM1") && !txt.contains("p=") { return None; }

    let key_type = if txt.contains("k=ed25519") { "Ed25519" }
        else { "RSA" }.to_string();

    let p_value: Option<String> = txt.split(';').find_map(|part| {
        let t = part.trim();
        if let Some(v) = t.strip_prefix("p=") {
            Some(v.replace([' ', '\t', '\n', '\r'], ""))
        } else {
            None
        }
    });

    let (key_bits, strength) = if key_type == "Ed25519" {
        (Some(256usize), "excellent".to_string())
    } else if let Some(ref p) = p_value {
        if p.is_empty() {
            return None; // revoked key
        }
        let bits = estimate_rsa_bits_from_b64_len(p.len());
        let strength = match bits {
            b if b < 1024 => "weak",
            1024 => "weak",
            2048 => "good",
            _ => "excellent",
        }.to_string();
        (Some(bits), strength)
    } else {
        (None, "unknown".to_string())
    };

    Some(DkimKeyResult { selector: String::new(), key_type, key_bits, strength })
}

pub async fn check_dkim_key_strength(req: &DkimKeyStrengthRequest) -> Result<DkimKeyStrengthResult> {
    let default_selectors = vec![
        "default", "google", "mail", "dkim", "selector1", "selector2",
        "k1", "k2", "s1", "s2", "smtp", "key1", "protonmail",
        "20230601", "20221208", "20240101",
    ];
    let mut selectors: Vec<String> = req.selectors.clone()
        .unwrap_or_else(|| default_selectors.iter().map(|s| s.to_string()).collect());
    selectors.truncate(32);

    let domain = req.domain.clone();
    let timeout = req.timeout_secs;
    let mut handles = Vec::new();

    for selector in selectors {
        let domain = domain.clone();
        handles.push(tokio::spawn(async move {
            let dkim_domain = format!("{}._domainkey.{}", selector, domain);
            let dns_req = crate::api::DnsCheckRequest {
                domain: dkim_domain,
                record_types: vec!["TXT".to_string()],
                timeout_secs: timeout,
                ..Default::default()
            };
            if let Ok(results) = crate::api::check_dns(&dns_req).await {
                for result in results {
                    for record in &result.answers {
                        if let crate::api::RecordData::Txt(texts) = &record.data {
                            let joined = texts.join("");
                            if let Some(mut key) = parse_dkim_txt(&joined) {
                                key.selector = selector.clone();
                                return Some(key);
                            }
                        }
                    }
                }
            }
            None
        }));
    }

    let mut keys = Vec::new();
    for h in handles {
        if let Ok(Some(k)) = h.await { keys.push(k); }
    }

    let mut recommendations = Vec::new();

    let weakest_strength = if keys.is_empty() {
        recommendations.push("No DKIM records found — implement DKIM signing for outbound email".to_string());
        "none".to_string()
    } else if keys.iter().any(|k| k.strength == "weak") {
        recommendations.push("Upgrade all weak DKIM keys to 2048-bit RSA or Ed25519 immediately".to_string());
        "weak".to_string()
    } else if keys.iter().any(|k| k.strength == "good") {
        "good".to_string()
    } else {
        "excellent".to_string()
    };

    let risk_level = match weakest_strength.as_str() {
        "weak" | "none" => "high",
        _ => "low",
    }.to_string();

    Ok(DkimKeyStrengthResult {
        domain: req.domain.clone(),
        keys,
        weakest_strength,
        risk_level,
        recommendations,
    })
}

// ── MX Server Security ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxSecurityRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxServerSecurity {
    pub hostname: String,
    pub priority: u16,
    pub reachable: bool,
    pub banner: Option<String>,
    pub starttls_available: bool,
    pub esmtp_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxSecurityResult {
    pub domain: String,
    pub mx_servers: Vec<MxServerSecurity>,
    pub all_support_starttls: bool,
    pub risk_level: String,
    pub findings: Vec<String>,
}

pub async fn check_mx_security(req: &MxSecurityRequest) -> Result<MxSecurityResult> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use std::time::Duration;

    // Resolve MX records
    let dns_req = crate::api::DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["MX".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    let mx_entries: Vec<(String, u16)> = match crate::api::check_dns(&dns_req).await {
        Ok(results) => results.into_iter().flat_map(|r| r.answers).filter_map(|rec| {
            if let crate::api::RecordData::Mx { priority, exchange } = rec.data {
                Some((exchange.trim_end_matches('.').to_string(), priority))
            } else {
                None
            }
        }).take(3).collect(),
        Err(_) => vec![],
    };

    let mut mx_servers = Vec::new();
    let mut findings = Vec::new();

    for (host, priority) in &mx_entries {
        // Resolve hostname and validate IPs to prevent SSRF before connecting
        let addr_str = format!("{}:25", host);
        let resolved = {
            let addr_str_clone = addr_str.clone();
            match tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                addr_str_clone.to_socket_addrs().map(|a| a.collect::<Vec<_>>())
            }).await {
                Ok(Ok(a)) => a,
                _ => {
                    findings.push(format!("MX server {} could not be resolved", host));
                    mx_servers.push(MxServerSecurity {
                        hostname: host.clone(),
                        priority: *priority,
                        reachable: false,
                        banner: None,
                        starttls_available: false,
                        esmtp_features: vec![],
                    });
                    continue;
                }
            }
        };
        let safe_addrs: Vec<_> = resolved.iter()
            .filter(|sa| !crate::api::helpers::is_private_or_special_ip(&sa.ip()))
            .cloned()
            .collect();
        if safe_addrs.is_empty() {
            findings.push(format!("MX server {} resolves to a private/reserved address — blocked for security", host));
            mx_servers.push(MxServerSecurity {
                hostname: host.clone(),
                priority: *priority,
                reachable: false,
                banner: None,
                starttls_available: false,
                esmtp_features: vec![],
            });
            continue;
        }
        // Connect to the first validated SocketAddr to avoid TOCTOU re-resolution
        let conn = tokio::time::timeout(
            Duration::from_secs(req.timeout_secs.min(8)),
            TcpStream::connect(safe_addrs[0]),
        ).await;

        match conn {
            Ok(Ok(stream)) => {
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = BufReader::new(read_half);

                // Read banner
                let mut banner = String::new();
                let _ = tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut banner)).await;
                let banner = banner.trim().to_string();

                // Send EHLO
                let _ = write_half.write_all(b"EHLO shohei-mcp.security\r\n").await;

                let mut starttls_available = false;
                let mut esmtp_features = Vec::new();

                // Read EHLO response (multi-line)
                for _ in 0..25 {
                    let mut line = String::new();
                    if tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
                        .await.is_err() || line.is_empty() { break; }
                    let trimmed = line.trim().to_string();
                    if trimmed.to_uppercase().contains("STARTTLS") { starttls_available = true; }
                    if trimmed.starts_with("250") {
                        let feat = trimmed.trim_start_matches("250").trim_start_matches('-').trim().to_string();
                        if !feat.is_empty() { esmtp_features.push(feat); }
                    }
                    if line.starts_with("250 ") { break; }
                }

                // QUIT gracefully
                let _ = write_half.write_all(b"QUIT\r\n").await;

                if !starttls_available {
                    findings.push(format!("MX server {} does not support STARTTLS — email transmitted unencrypted", host));
                }

                mx_servers.push(MxServerSecurity {
                    hostname: host.clone(),
                    priority: *priority,
                    reachable: true,
                    banner: if banner.is_empty() { None } else { Some(banner.chars().take(120).collect()) },
                    starttls_available,
                    esmtp_features,
                });
            }
            _ => {
                findings.push(format!("MX server {} port 25 is unreachable", host));
                mx_servers.push(MxServerSecurity {
                    hostname: host.clone(),
                    priority: *priority,
                    reachable: false,
                    banner: None,
                    starttls_available: false,
                    esmtp_features: vec![],
                });
            }
        }
    }

    let reachable: Vec<_> = mx_servers.iter().filter(|s| s.reachable).collect();
    let all_support_starttls = !reachable.is_empty() && reachable.iter().all(|s| s.starttls_available);

    let risk_level = if !reachable.is_empty() && !all_support_starttls { "high" }
        else { "low" }.to_string();

    Ok(MxSecurityResult {
        domain: req.domain.clone(),
        mx_servers,
        all_support_starttls,
        risk_level,
        findings,
    })
}
