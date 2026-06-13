//! Service Exposure Detection — exposed databases, containers, service fingerprinting, DGA risk.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use std::time::Duration;

fn default_timeout() -> u64 { 10 }

async fn probe_tcp_banner(host: &str, port: u16, timeout_secs: u64) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs.min(4)),
        TcpStream::connect(&addr),
    ).await.ok()?.ok()?;

    let mut buf = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    let banner = String::from_utf8_lossy(&buf).trim_matches('\0').trim().to_string();
    if banner.is_empty() { None } else { Some(banner) }
}

async fn http_get_succeeds(host: &str, port: u16, path: &str, timeout_secs: u64) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.min(4)))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("http://{}:{}{}", host, port, path);
    client.get(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false)
}

// ── Exposed Databases ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedDatabasesRequest {
    pub host: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedService {
    pub service: String,
    pub port: u16,
    pub banner: Option<String>,
    pub unauthenticated: bool,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedDatabasesResult {
    pub host: String,
    pub exposed_services: Vec<ExposedService>,
    pub risk_level: String,
    pub findings: Vec<String>,
}

pub async fn check_exposed_databases(req: &ExposedDatabasesRequest) -> Result<ExposedDatabasesResult> {
    crate::api::helpers::validate_url_safety(&format!("http://{}/", req.host))
        .map_err(crate::error::ShoheError::Parse)?;

    let timeout = req.timeout_secs.min(5);
    let host = &req.host;
    let mut exposed_services = Vec::new();
    let mut findings = Vec::new();

    // Redis 6379 — sends PING, check for +PONG
    let redis_handle = {
        let h = host.to_string();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let addr = format!("{}:6379", h);
            if let Ok(Ok(mut stream)) = tokio::time::timeout(
                Duration::from_secs(timeout), TcpStream::connect(&addr)
            ).await {
                let _ = stream.write_all(b"PING\r\n").await;
                let mut buf = [0u8; 128];
                let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
                let resp = String::from_utf8_lossy(&buf).to_string();
                if resp.contains("+PONG") || resp.contains("redis_version") {
                    return Some((true, resp));
                } else if !resp.trim_matches('\0').is_empty() {
                    return Some((false, resp));
                }
            }
            None
        })
    };

    // MongoDB 27017 — wire protocol hello (binary), just check TCP open
    let mongo_handle = {
        let h = host.to_string();
        tokio::spawn(async move { probe_tcp_banner(&h, 27017, timeout).await })
    };

    // Elasticsearch 9200 — HTTP REST
    let es_handle = {
        let h = host.to_string();
        tokio::spawn(async move { http_get_succeeds(&h, 9200, "/_cluster/health", timeout).await })
    };

    // Memcached 11211
    let mc_handle = {
        let h = host.to_string();
        tokio::spawn(async move { probe_tcp_banner(&h, 11211, timeout).await })
    };

    // CouchDB 5984 — HTTP REST
    let couch_handle = {
        let h = host.to_string();
        tokio::spawn(async move { http_get_succeeds(&h, 5984, "/_all_dbs", timeout).await })
    };

    if let Ok(Some((unauth, banner))) = redis_handle.await {
        let risk = if unauth { "critical" } else { "high" }.to_string();
        let msg = format!("Redis port 6379 open{}", if unauth { " — unauthenticated PING/PONG confirmed" } else { "" });
        findings.push(msg);
        exposed_services.push(ExposedService {
            service: "Redis".to_string(),
            port: 6379,
            banner: Some(banner.chars().take(120).collect()),
            unauthenticated: unauth,
            risk_level: risk,
        });
    }

    if let Ok(Some(banner)) = mongo_handle.await {
        findings.push("MongoDB port 27017 open — may allow unauthenticated access".to_string());
        exposed_services.push(ExposedService {
            service: "MongoDB".to_string(),
            port: 27017,
            banner: Some(banner.chars().take(60).collect()),
            unauthenticated: true,
            risk_level: "critical".to_string(),
        });
    }

    if let Ok(unauth) = es_handle.await {
        if unauth {
            findings.push("Elasticsearch port 9200 open with unauthenticated /_cluster/health".to_string());
            exposed_services.push(ExposedService {
                service: "Elasticsearch".to_string(),
                port: 9200,
                banner: None,
                unauthenticated: true,
                risk_level: "critical".to_string(),
            });
        }
    }

    if let Ok(Some(banner)) = mc_handle.await {
        findings.push("Memcached port 11211 open — data accessible without authentication".to_string());
        exposed_services.push(ExposedService {
            service: "Memcached".to_string(),
            port: 11211,
            banner: Some(banner.chars().take(60).collect()),
            unauthenticated: true,
            risk_level: "high".to_string(),
        });
    }

    if let Ok(unauth) = couch_handle.await {
        if unauth {
            findings.push("CouchDB port 5984 open with unauthenticated /_all_dbs access".to_string());
            exposed_services.push(ExposedService {
                service: "CouchDB".to_string(),
                port: 5984,
                banner: None,
                unauthenticated: true,
                risk_level: "critical".to_string(),
            });
        }
    }

    let risk_level = if exposed_services.iter().any(|s| s.risk_level == "critical") { "critical" }
        else if !exposed_services.is_empty() { "high" }
        else { "low" }.to_string();

    Ok(ExposedDatabasesResult {
        host: req.host.clone(),
        exposed_services,
        risk_level,
        findings,
    })
}

// ── Container Exposure ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerExposureRequest {
    pub host: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerExposureResult {
    pub host: String,
    pub docker_api_exposed: bool,
    pub docker_tls_port_open: bool,
    pub kubernetes_api_exposed: bool,
    pub etcd_exposed: bool,
    pub risk_level: String,
    pub findings: Vec<String>,
}

pub async fn check_container_exposure(req: &ContainerExposureRequest) -> Result<ContainerExposureResult> {
    crate::api::helpers::validate_url_safety(&format!("http://{}/", req.host))
        .map_err(crate::error::ShoheError::Parse)?;

    let timeout = req.timeout_secs.min(5);
    let host = req.host.clone();
    let mut findings = Vec::new();

    let (docker_plain, docker_tls, k8s, etcd) = tokio::join!(
        http_get_succeeds(&host, 2375, "/version", timeout),
        async {
            let addr = format!("{}:2376", host);
            tokio::time::timeout(Duration::from_secs(timeout.min(4)), TcpStream::connect(&addr))
                .await.map(|r| r.is_ok()).unwrap_or(false)
        },
        async {
            // Self-signed certs are common on k8s API servers; we only check port reachability
            // via 401/403 responses, so cert validity is intentionally skipped here.
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout.min(4)))
                .danger_accept_invalid_certs(true)
                .build();
            match client {
                Ok(c) => {
                    let url = format!("https://{}:6443/api", host);
                    c.get(&url).send().await
                        .map(|r| {
                            let s = r.status().as_u16();
                            s == 200 || s == 403 || s == 401
                        })
                        .unwrap_or(false)
                }
                Err(_) => false,
            }
        },
        http_get_succeeds(&host, 2379, "/health", timeout),
    );

    if docker_plain {
        findings.push("Docker API port 2375 (no TLS) is responding — full container control possible".to_string());
    }
    if docker_tls {
        findings.push("Docker TLS port 2376 is open — verify mTLS certificate authentication".to_string());
    }
    if k8s {
        findings.push("Kubernetes API port 6443 is responding — verify authentication configuration".to_string());
    }
    if etcd {
        findings.push("etcd port 2379 accessible — cluster secrets may be readable".to_string());
    }

    let risk_level = if docker_plain || etcd { "critical" }
        else if k8s || docker_tls { "high" }
        else { "low" }.to_string();

    Ok(ContainerExposureResult {
        host: req.host.clone(),
        docker_api_exposed: docker_plain,
        docker_tls_port_open: docker_tls,
        kubernetes_api_exposed: k8s,
        etcd_exposed: etcd,
        risk_level,
        findings,
    })
}

// ── Service Fingerprinting ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprintRequest {
    pub host: String,
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub security_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprintResult {
    pub host: String,
    pub services: Vec<ServiceFingerprint>,
    pub outdated_services: Vec<String>,
    pub risk_level: String,
}

fn parse_banner(port: u16, banner: &str) -> (String, Option<String>, Vec<String>) {
    let bl = banner.to_lowercase();
    let mut notes = Vec::new();

    let (service, version) = match port {
        22 => {
            let ver = banner.split_whitespace()
                .find(|s| s.to_lowercase().starts_with("openssh"))
                .map(|s| s.to_string());
            if let Some(ref v) = ver {
                if v.contains("OpenSSH_6") || v.contains("OpenSSH_7.") {
                    notes.push(format!("Outdated {} — check for known CVEs", v));
                }
            }
            ("SSH".to_string(), ver)
        }
        21 => {
            if !bl.contains("tls") && !bl.contains("ftps") && !bl.contains("auth tls") {
                notes.push("FTP without TLS — credentials transmitted in plaintext".to_string());
            }
            ("FTP".to_string(), banner.lines().next().map(|l| l.trim().to_string()))
        }
        25 | 587 | 465 => {
            let ver = if bl.contains("postfix") { Some("Postfix".to_string()) }
                else if bl.contains("exim") { Some("Exim".to_string()) }
                else if bl.contains("sendmail") { Some("Sendmail".to_string()) }
                else { None };
            ("SMTP".to_string(), ver)
        }
        3306 => {
            // MySQL greets with a binary protocol packet; version often in bytes 5-15
            let ver = banner.chars().skip(5).take(10)
                .collect::<String>()
                .split('\0').next()
                .map(|s| format!("MySQL {}", s.trim()));
            ("MySQL".to_string(), ver)
        }
        5432 => ("PostgreSQL".to_string(), None),
        6379 => ("Redis".to_string(), None),
        _ => ("Unknown".to_string(), None),
    };

    (service, version, notes)
}

pub async fn check_service_fingerprint(req: &ServiceFingerprintRequest) -> Result<ServiceFingerprintResult> {
    crate::api::helpers::validate_url_safety(&format!("http://{}/", req.host))
        .map_err(crate::error::ShoheError::Parse)?;

    let default_ports = vec![21u16, 22, 25, 587, 3306, 5432, 6379, 27017];
    let mut ports = req.ports.clone().unwrap_or(default_ports);
    ports.truncate(64);
    let timeout = req.timeout_secs.min(5);

    let mut handles = Vec::new();
    for port in ports {
        let host = req.host.clone();
        handles.push(tokio::spawn(async move {
            probe_tcp_banner(&host, port, timeout).await.map(|banner| (port, banner))
        }));
    }

    let mut services = Vec::new();
    let mut outdated_services = Vec::new();

    for h in handles {
        if let Ok(Some((port, banner))) = h.await {
            let (service, version, notes) = parse_banner(port, &banner);
            if !notes.is_empty() {
                outdated_services.push(format!("{} on port {}", service, port));
            }
            services.push(ServiceFingerprint {
                port,
                service,
                version,
                banner: Some(banner.chars().take(200).collect()),
                security_notes: notes,
            });
        }
    }

    let risk_level = if services.iter().any(|s| !s.security_notes.is_empty()) { "high" }
        else if !services.is_empty() { "medium" }
        else { "low" }.to_string();

    Ok(ServiceFingerprintResult {
        host: req.host.clone(),
        services,
        outdated_services,
        risk_level,
    })
}

// ── DGA Risk Detection ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaRiskRequest {
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaRiskResult {
    pub domain: String,
    pub dga_score: f64,
    pub entropy: f64,
    pub vowel_ratio: f64,
    pub digit_ratio: f64,
    pub max_consonant_cluster: usize,
    pub label_length: usize,
    pub risk_level: String,
    pub indicators: Vec<String>,
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0usize; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    let len = s.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

pub async fn check_dga_risk(req: &DgaRiskRequest) -> Result<DgaRiskResult> {
    let label = req.domain.split('.').next().unwrap_or(&req.domain);
    let label_lower = label.to_lowercase();
    let vowels = "aeiou";

    let entropy = shannon_entropy(&label_lower);
    let len = label_lower.len();
    let vowel_count = label_lower.chars().filter(|c| vowels.contains(*c)).count();
    let digit_count = label_lower.chars().filter(|c| c.is_ascii_digit()).count();

    let vowel_ratio = if len > 0 { vowel_count as f64 / len as f64 } else { 0.0 };
    let digit_ratio = if len > 0 { digit_count as f64 / len as f64 } else { 0.0 };

    let mut max_cluster = 0usize;
    let mut cur_cluster = 0usize;
    for c in label_lower.chars() {
        if c.is_alphabetic() && !vowels.contains(c) {
            cur_cluster += 1;
            max_cluster = max_cluster.max(cur_cluster);
        } else {
            cur_cluster = 0;
        }
    }

    let mut score = 0.0f64;
    let mut indicators = Vec::new();

    if entropy > 3.5 {
        score += 30.0;
        indicators.push(format!("High entropy ({:.2} bits) — random-looking name", entropy));
    } else if entropy > 2.8 {
        score += 15.0;
    }

    if vowel_ratio < 0.20 {
        score += 25.0;
        indicators.push(format!("Very low vowel ratio ({:.0}%) — difficult to pronounce", vowel_ratio * 100.0));
    } else if vowel_ratio > 0.55 {
        score += 8.0;
    }

    if digit_ratio > 0.30 {
        score += 20.0;
        indicators.push(format!("High digit ratio ({:.0}%) — may be algorithmically generated", digit_ratio * 100.0));
    }

    if max_cluster >= 5 {
        score += 15.0;
        indicators.push(format!("Long consonant cluster ({} chars) — uncommon in natural language", max_cluster));
    }

    if len > 20 {
        score += 20.0;
        indicators.push(format!("Very long label ({} chars)", len));
    } else if len >= 12 {
        score += 8.0;
    }

    let risk_level = if score >= 60.0 { "high" }
        else if score >= 30.0 { "medium" }
        else { "low" }.to_string();

    Ok(DgaRiskResult {
        domain: req.domain.clone(),
        dga_score: score.min(100.0),
        entropy,
        vowel_ratio,
        digit_ratio,
        max_consonant_cluster: max_cluster,
        label_length: len,
        risk_level,
        indicators,
    })
}
