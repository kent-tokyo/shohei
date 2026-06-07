//! Verify TLS certificate chain for a domain (Phase 2 feature).
//!
//! This example shows how shohei will integrate DNS resolution with TLS certificate
//! inspection—validating the complete trust chain from domain name to cert chain.
//!
//! Currently demonstrates the planned API structure; full TLS implementation coming in Phase 2.
//!
//! Run with: cargo run --example tls_chain_verify -- example.com

use std::env;
use shohei::api::{check_dns, DnsCheckRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());

    println!("TLS Certificate Chain Verification for {}\n", domain);

    // Step 1: Resolve domain to IP
    println!("Step 1: Resolving {} via DNS...", domain);
    let results = check_dns(&DnsCheckRequest {
        domain: domain.clone(),
        record_types: vec!["A".to_string(), "AAAA".to_string()],
        ..Default::default()
    })
    .await?;

    if results[0].answers.is_empty() {
        println!("  ✗ No A records found");
        return Ok(());
    }

    for record in &results[0].answers {
        println!("  ✓ Found: {} -> {:?}", record.name, record.data);
    }

    println!("\nStep 2: (Phase 2) Connect to resolved IP on port 443");
    println!("Step 3: (Phase 2) Extract TLS certificate chain");
    println!("Step 4: (Phase 2) Validate cert expiry and chain");
    println!("Step 5: (Phase 2) Check DANE/TLSA records in DNS for cross-validation\n");

    println!("Full TLS integration will be available in v0.5.0+ (Phase 2)");

    Ok(())
}
