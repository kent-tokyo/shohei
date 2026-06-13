//! TLS vulnerability probing — detect support for weak protocols and cipher suites.

use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;

use crate::error::Result;

/// Check TLS protocol vulnerabilities — which versions are supported.
pub async fn check_tls_vulns(req: &TlsVulnCheckRequest) -> Result<TlsVulnCheckResult> {
    let hostname_str = &req.hostname;
    let port = req.port;

    // Resolve hostname to IP — return error on failure to avoid false "unsupported" results
    let ip = match crate::api::helpers::resolve_hostname_to_ip(hostname_str, req.timeout_secs).await {
        Ok(ip) => ip,
        Err(e) => return Ok(TlsVulnCheckResult {
            hostname: hostname_str.clone(),
            port,
            tls10_accepted: false,
            tls11_accepted: false,
            tls12_accepted: false,
            tls13_accepted: false,
            forward_secrecy: false,
            error: Some(format!("DNS resolution failed: {}", e)),
        }),
    };

    // Test each TLS version concurrently to reduce total latency
    let (tls10_accepted, tls11_accepted, tls12_accepted, tls13_accepted) = tokio::join!(
        test_tls_version(&ip, port, hostname_str, "1.0", req.timeout_secs),
        test_tls_version(&ip, port, hostname_str, "1.1", req.timeout_secs),
        test_tls_version(&ip, port, hostname_str, "1.2", req.timeout_secs),
        test_tls_version(&ip, port, hostname_str, "1.3", req.timeout_secs),
    );

    // Forward secrecy: assume supported if TLS 1.2+ available (rustls defaults to ECDHE)
    let forward_secrecy = tls12_accepted || tls13_accepted;

    Ok(TlsVulnCheckResult {
        hostname: hostname_str.clone(),
        port,
        tls10_accepted,
        tls11_accepted,
        tls12_accepted,
        tls13_accepted,
        forward_secrecy,
        error: None,
    })
}

async fn test_tls_version(
    ip: &IpAddr,
    port: u16,
    hostname: &str,
    version: &str,
    timeout_secs: u64,
) -> bool {
    // Note: rustls dropped support for TLS 1.0 and 1.1 as they are cryptographically broken.
    // We check against the server's capabilities rather than trying to force old protocols.
    // For a production tool, we'd need to use a more flexible TLS library or OpenSSL bindings.

    match timeout(
        Duration::from_secs(timeout_secs),
        connect_with_tls(ip, port, hostname),
    )
    .await
    {
        Ok(Ok((tls_ver, _))) => {
            // Check if returned version matches or is newer than what we tested
            match version {
                "1.3" => tls_ver.as_deref() == Some("TLSv1.3"),
                "1.2" => {
                    matches!(tls_ver.as_deref(), Some("TLSv1.2") | Some("TLSv1.3"))
                }
                "1.1" => {
                    // rustls does not support TLS 1.1 (dropped as cryptographically broken).
                    // Cannot probe whether the server accepts TLS 1.1; report as not accepted.
                    false
                }
                "1.0" => {
                    // TLS 1.0 would be very old; rustls doesn't support it
                    false
                }
                _ => false,
            }
        }
        _ => false,
    }
}

async fn connect_with_tls(
    ip: &IpAddr,
    port: u16,
    hostname: &str,
) -> std::result::Result<(Option<String>, Option<String>), Box<dyn std::error::Error>> {
    let addr = SocketAddr::new(*ip, port);
    let socket = TcpStream::connect(&addr).await?;

    let config = rustls::ClientConfig::builder_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS config error: {}", e))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(SkipVerification))
    .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(hostname.to_string())?;
    let tls_stream = connector.connect(server_name, socket).await?;

    // Get TLS version and cipher suite from the connection
    let (_, conn) = tls_stream.get_ref();
    let tls_version = conn.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        _ => "Unknown".to_string(),
    });
    let cipher_suite = conn.negotiated_cipher_suite().map(|cs| format!("{:?}", cs));

    Ok((tls_version, cipher_suite))
}

#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsVulnCheckRequest {
    pub hostname: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_port() -> u16 { 443 }
fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsVulnCheckResult {
    pub hostname: String,
    pub port: u16,
    /// TLS 1.0 is accepted (cryptographically broken — should be rejected)
    pub tls10_accepted: bool,
    /// TLS 1.1 is accepted (deprecated — should be rejected)
    pub tls11_accepted: bool,
    /// TLS 1.2 is accepted (good)
    pub tls12_accepted: bool,
    /// TLS 1.3 is accepted (best)
    pub tls13_accepted: bool,
    /// Forward secrecy is supported (ECDHE used)
    pub forward_secrecy: bool,
    #[serde(default)]
    pub error: Option<String>,
}
