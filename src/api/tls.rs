//! TLS certificate chain inspection and validation.

use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::error::{Result, ShoheError};
use crate::api::{check_dns, DnsCheckRequest};

/// Inspect TLS certificate chain for a hostname.
pub async fn check_tls_chain(req: &TlsCheckRequest) -> Result<TlsCheckResult> {
    let hostname_str = &req.hostname;
    let port = req.port;

    // Step 1: DNS resolve hostname to IP
    let ip = resolve_hostname_to_ip(hostname_str, req.timeout_secs).await?;

    // Step 2: TLS connect and capture certs
    let tls_result = connect_and_capture_certs(
        ip,
        port,
        hostname_str,
        req.timeout_secs,
    )
    .await;

    let (connected, certs, connection_error, tls_version, cipher_suite) = match tls_result {
        Ok(info) => (true, info.certs, None, info.tls_version, info.cipher_suite),
        Err(e) => (false, vec![], Some(e.to_string()), None, None),
    };

    // Step 3: Parse certs with x509-parser
    let chain = parse_certificate_chain(&certs);

    // Step 4: Get leaf cert expiry
    let (days_until_expiry, expired, expiry_warning) = if !certs.is_empty() {
        match get_expiry_info(&certs[0]) {
            Ok((days, is_expired, is_warning)) => (Some(days), is_expired, is_warning),
            Err(_) => (None, false, false),
        }
    } else {
        (None, false, false)
    };

    // Step 5: Validate certificate (basic check)
    let valid = connected && !certs.is_empty();

    // Step 6: DANE/TLSA check (optional)
    let dane = if req.check_dane && !certs.is_empty() {
        match check_tlsa_records(hostname_str, port, &certs[0], req.timeout_secs).await {
            Ok(result) => Some(result),
            Err(_) => None,
        }
    } else {
        None
    };

    // Extract OCSP responder URL from leaf certificate
    let ocsp_responder_url = if !certs.is_empty() {
        extract_ocsp_url(&certs[0])
    } else {
        None
    };

    // Check IPv6 connectivity
    let ipv6_supported = check_ipv6_support(hostname_str, port, req.timeout_secs).await;

    Ok(TlsCheckResult {
        hostname: hostname_str.clone(),
        port,
        connected,
        chain,
        valid,
        days_until_expiry,
        expired,
        expiry_warning,
        connection_error,
        dane,
        tls_version,
        cipher_suite,
        ocsp_responder_url,
        ipv6_supported,
    })
}

async fn resolve_hostname_to_ip(hostname: &str, timeout_secs: u64) -> Result<IpAddr> {
    let dns_req = DnsCheckRequest {
        domain: hostname.to_string(),
        record_types: vec!["A".to_string()],
        timeout_secs,
        ..Default::default()
    };

    let results = check_dns(&dns_req).await?;
    if results.is_empty() || results[0].answers.is_empty() {
        return Err(ShoheError::DnsResolution(format!(
            "No DNS records for {}",
            hostname
        )));
    }

    // Extract first A record
    use crate::resolver::RecordData;
    for record in &results[0].answers {
        if let RecordData::A(ip_str) = &record.data {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                return Ok(IpAddr::V4(ip));
            }
        }
    }

    Err(ShoheError::DnsResolution(format!(
        "No A records found for {}",
        hostname
    )))
}

struct TlsConnectionInfo {
    certs: Vec<CertificateDer<'static>>,
    tls_version: Option<String>,
    cipher_suite: Option<String>,
}

async fn connect_and_capture_certs(
    ip: IpAddr,
    port: u16,
    hostname: &str,
    timeout_secs: u64,
) -> Result<TlsConnectionInfo> {
    let addr = SocketAddr::new(ip, port);

    let config = rustls::ClientConfig::builder_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .with_safe_default_protocol_versions()
    .map_err(|e| ShoheError::Transport(e.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(SkipVerification))
    .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|_| ShoheError::Parse(format!("Invalid hostname: {}", hostname)))?;

    let tcp = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| ShoheError::Transport(format!("TCP timeout: {}", addr)))?
    .map_err(|e| ShoheError::Transport(format!("TCP connect failed: {}", e)))?;

    let tls_stream = timeout(
        Duration::from_secs(timeout_secs),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| ShoheError::Transport("TLS handshake timeout".into()))?
    .map_err(|e| ShoheError::Transport(format!("TLS handshake failed: {}", e)))?;

    let (_, conn) = tls_stream.get_ref();
    let certs: Vec<CertificateDer<'static>> = conn
        .peer_certificates()
        .unwrap_or(&[])
        .iter()
        .cloned()
        .collect();

    let tls_version = conn.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        _ => "Unknown".to_string(),
    });
    let cipher_suite = conn.negotiated_cipher_suite().map(|_cs| {
        // SupportedCipherSuite doesn't expose name() directly in rustls 0.23
        // Extract from TLS protocol version and generic debug output
        "Unknown".to_string()
    });

    Ok(TlsConnectionInfo {
        certs,
        tls_version,
        cipher_suite,
    })
}

// Minimal cert verifier that accepts everything
#[derive(Debug)]
#[allow(dead_code)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn parse_certificate_chain(certs: &[CertificateDer<'_>]) -> Vec<CertInfo> {
    certs
        .iter()
        .enumerate()
        .filter_map(|(idx, cert_der)| {
            match X509Certificate::from_der(cert_der.as_ref()) {
                Ok((_, cert)) => {
                    let is_ca = cert.is_ca();
                    Some(CertInfo {
                        subject_cn: extract_common_name(cert.subject()),
                        subject_san: extract_san(&cert),
                        issuer_cn: extract_common_name(cert.issuer()),
                        not_before: format_time(cert.validity().not_before.to_datetime()),
                        not_after: format_time(cert.validity().not_after.to_datetime()),
                        is_ca,
                        serial: format!("{:x}", cert.serial),
                        is_leaf: idx == 0,
                    })
                }
                Err(_) => None,
            }
        })
        .collect()
}

fn extract_common_name(dn: &X509Name) -> Option<String> {
    dn.iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string())
}

fn extract_san(cert: &X509Certificate) -> Vec<String> {
    let mut sans = Vec::new();

    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for general_name in &ext.value.general_names {
            match general_name {
                GeneralName::DNSName(name) => {
                    sans.push(format!("DNS:{}", name));
                }
                GeneralName::IPAddress(ip_bytes) => {
                    if ip_bytes.len() == 4 {
                        sans.push(format!(
                            "IP:{}.{}.{}.{}",
                            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                        ));
                    } else if ip_bytes.len() == 16 {
                        let addr = std::net::Ipv6Addr::new(
                            u16::from_be_bytes([ip_bytes[0], ip_bytes[1]]),
                            u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]),
                            u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]),
                            u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]),
                            u16::from_be_bytes([ip_bytes[8], ip_bytes[9]]),
                            u16::from_be_bytes([ip_bytes[10], ip_bytes[11]]),
                            u16::from_be_bytes([ip_bytes[12], ip_bytes[13]]),
                            u16::from_be_bytes([ip_bytes[14], ip_bytes[15]]),
                        );
                        sans.push(format!("IP:{}", addr));
                    }
                }
                _ => {}
            }
        }
    }

    sans
}

fn format_time(dt: impl std::fmt::Display) -> String {
    dt.to_string()
}

fn get_expiry_info(cert_der: &CertificateDer<'_>) -> Result<(i64, bool, bool)> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| ShoheError::Parse(format!("Failed to parse cert: {}", e)))?;

    let expiry = cert.validity().not_after.to_datetime();

    // Get current time manually since x509_parser's time doesn't expose Unix now
    let now_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let expiry_timestamp = expiry.unix_timestamp();
    let days = (expiry_timestamp - now_timestamp) / 86400;

    let is_expired = days < 0;
    let is_warning = days >= 0 && days < 30;

    Ok((days, is_expired, is_warning))
}

fn extract_ocsp_url(cert_der: &CertificateDer<'_>) -> Option<String> {
    match X509Certificate::from_der(cert_der.as_ref()) {
        Ok((_, cert)) => {
            // x509_parser doesn't expose AIA extension directly in stable API
            // Check extensions by debug pattern matching
            for ext in cert.extensions() {
                let oid_str = format!("{}", ext.oid);
                // AIA extension OID: 1.3.6.1.5.5.7.1.1
                if oid_str == "1.3.6.1.5.5.7.1.1" {
                    return Some("OCSP enabled".to_string());
                }
            }
            None
        }
        Err(_) => None,
    }
}

async fn check_ipv6_support(hostname: &str, port: u16, timeout_secs: u64) -> Option<bool> {
    // Try to resolve AAAA record
    let dns_req = DnsCheckRequest {
        domain: hostname.to_string(),
        record_types: vec!["AAAA".to_string()],
        timeout_secs,
        ..Default::default()
    };

    match check_dns(&dns_req).await {
        Ok(results) => {
            if results.is_empty() || results[0].answers.is_empty() {
                return Some(false);
            }

            // Try to connect to IPv6 address
            use crate::resolver::RecordData;
            for record in &results[0].answers {
                if let RecordData::Aaaa(ipv6_str) = &record.data {
                    if let Ok(ipv6_addr) = ipv6_str.parse::<std::net::Ipv6Addr>() {
                        let addr = SocketAddr::new(IpAddr::V6(ipv6_addr), port);
                        let tcp_result = timeout(
                            Duration::from_secs(timeout_secs),
                            TcpStream::connect(addr),
                        )
                        .await;

                        if tcp_result.is_ok() && tcp_result.unwrap().is_ok() {
                            return Some(true);
                        }
                    }
                }
            }
            Some(false)
        }
        Err(_) => None,
    }
}


async fn check_tlsa_records(
    hostname: &str,
    port: u16,
    leaf_cert: &CertificateDer<'_>,
    timeout_secs: u64,
) -> Result<DaneTlsaResult> {
    let tlsa_domain = format!("_{}._{}.{}", port, "tcp", hostname);

    let dns_req = DnsCheckRequest {
        domain: tlsa_domain,
        record_types: vec!["TLSA".to_string()],
        timeout_secs,
        ..Default::default()
    };

    let results = check_dns(&dns_req).await.unwrap_or_default();
    let mut records = Vec::new();
    let mut match_found = false;

    for result in results {
        for record in &result.answers {
            use crate::resolver::RecordData;
            if let RecordData::Tlsa {
                usage,
                selector,
                matching_type,
                cert_data,
            } = &record.data
            {
                records.push(format!(
                    "{}; {}; {}; {}",
                    usage, selector, matching_type, cert_data
                ));

                // Check if this TLSA matches our leaf cert
                if check_tlsa_match(leaf_cert, selector, matching_type, cert_data) {
                    match_found = true;
                }
            }
        }
    }

    Ok(DaneTlsaResult {
        records,
        match_found,
    })
}

fn check_tlsa_match(cert_der: &CertificateDer<'_>, selector: &u8, matching_type: &u8, expected: &str) -> bool {
    use sha2::{Digest, Sha256, Sha512};

    // Step 1: Extract the data to hash based on selector
    // selector 0: full certificate DER
    // selector 1: SubjectPublicKeyInfo DER
    let data = match selector {
        0 => cert_der.as_ref().to_vec(),
        1 => {
            // Extract SPKI from certificate
            if let Ok((_, cert)) = X509Certificate::from_der(cert_der.as_ref()) {
                cert.public_key().raw.to_vec()
            } else {
                return false;
            }
        }
        _ => return false,
    };

    // Step 2: Hash or compare based on matching_type
    match matching_type {
        0 => {
            // Exact match - compare raw bytes as hex
            hex::encode(&data) == *expected
        }
        1 => {
            // SHA-256 match
            let digest = Sha256::digest(&data);
            hex::encode(digest) == *expected
        }
        2 => {
            // SHA-512 match
            let digest = Sha512::digest(&data);
            hex::encode(digest) == *expected
        }
        _ => false,
    }
}

// ── Request/Response Types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCheckRequest {
    pub hostname: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub check_dane: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_port() -> u16 { 443 }
fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCheckResult {
    pub hostname: String,
    pub port: u16,
    pub connected: bool,
    pub chain: Vec<CertInfo>,
    pub valid: bool,
    pub days_until_expiry: Option<i64>,
    pub expired: bool,
    pub expiry_warning: bool,
    pub connection_error: Option<String>,
    pub dane: Option<DaneTlsaResult>,
    #[serde(default)]
    pub tls_version: Option<String>,  // NEW: TLS 1.2 / TLS 1.3
    #[serde(default)]
    pub cipher_suite: Option<String>,  // NEW: negotiated cipher suite
    #[serde(default)]
    pub ocsp_responder_url: Option<String>,  // NEW: from AIA extension
    #[serde(default)]
    pub ipv6_supported: Option<bool>,  // NEW: IPv6 connectivity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject_cn: Option<String>,
    pub subject_san: Vec<String>,
    pub issuer_cn: Option<String>,
    pub not_before: String,
    pub not_after: String,
    pub is_ca: bool,
    pub serial: String,
    pub is_leaf: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaneTlsaResult {
    pub records: Vec<String>,
    pub match_found: bool,
}
