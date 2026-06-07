//! Verify TLS certificate chain for a domain (Phase 2 feature).
//!
//! This example demonstrates shohei's integrated DNS + TLS inspection,
//! validating the complete trust chain from domain name to certificate chain.
//!
//! Run with: cargo run --example tls_chain_verify -- example.com

use std::env;
use shohei::api::{check_tls_chain, TlsCheckRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hostname = env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());

    println!("TLS Certificate Chain Inspection for {}\n", hostname);

    let result = check_tls_chain(&TlsCheckRequest {
        hostname: hostname.clone(),
        port: 443,
        check_dane: false,
        timeout_secs: 10,
    })
    .await?;

    println!("Connection: {}", if result.connected { "✓ Connected" } else { "✗ Failed" });
    println!("Valid:      {}", if result.valid { "✓ Yes" } else { "✗ No" });

    if let Some(err) = result.connection_error {
        println!("Error: {}", err);
    }

    if result.expired {
        println!("⚠ Certificate is EXPIRED");
    } else if result.expiry_warning {
        if let Some(days) = result.days_until_expiry {
            println!("⚠ Certificate expires in {} days", days);
        }
    }

    if !result.chain.is_empty() {
        println!("\nCertificate Chain ({} certs):", result.chain.len());
        for (idx, cert) in result.chain.iter().enumerate() {
            println!("\n  [{}] {}", idx, if cert.is_leaf { "LEAF" } else { "INTERMEDIATE" });
            if let Some(cn) = &cert.subject_cn {
                println!("      Subject CN: {}", cn);
            }
            if !cert.subject_san.is_empty() {
                println!("      SANs: {}", cert.subject_san.join(", "));
            }
            if let Some(issuer) = &cert.issuer_cn {
                println!("      Issuer CN: {}", issuer);
            }
            println!("      Valid: {} → {}", cert.not_before, cert.not_after);
        }
    } else {
        println!("\nNo certificates found");
    }

    if let Some(dane) = result.dane {
        println!("\nDANE/TLSA:");
        println!("  Records found: {}", dane.records.len());
        println!("  Match: {}", if dane.match_found { "✓ Yes" } else { "✗ No" });
    }

    Ok(())
}
