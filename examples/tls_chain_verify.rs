//! Verify TLS certificate chain for a domain (Phase 2 feature).
//!
//! This example shows how shohei will integrate DNS resolution with TLS certificate
//! inspection—validating the complete trust chain from domain name to cert chain.
//!
//! Run with: cargo run --example tls_chain_verify -- example.com

use std::env;

#[tokio::main]
async fn main() {
    let domain = env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());

    println!("TLS Certificate Chain Verification for {}\n", domain);
    println!("Steps:");
    println!("  1. Resolve {} via DNS (standard query)", domain);
    println!("  2. Connect to resolved IP on port 443");
    println!("  3. Extract TLS certificate chain");
    println!("  4. Validate cert expiry and chain");
    println!("  5. Check DANE/TLSA records in DNS for cross-validation\n");

    println!("This feature will be available in v0.5.0+ (Phase 2)");
    println!("See docs/PHASE_ROADMAP.md for implementation timeline");
}
