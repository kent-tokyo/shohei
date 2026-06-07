//! Check DNS propagation across multiple global resolvers.
//!
//! This example demonstrates how to use shohei as a library to check if a domain
//! is propagated across different DNS resolvers worldwide.
//!
//! Run with: cargo run --example propagation_check -- google.com

use std::env;
use shohei::api::{check_dns, DnsCheckRequest, Transport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = env::args()
        .nth(1)
        .unwrap_or_else(|| "google.com".to_string());

    println!("Checking propagation of {} across global resolvers...\n", domain);

    let resolvers = vec![
        ("Google", "8.8.8.8"),
        ("Cloudflare", "1.1.1.1"),
        ("Quad9", "9.9.9.9"),
        ("OpenDNS", "208.67.222.222"),
    ];

    for (name, ip) in resolvers {
        let results = check_dns(&DnsCheckRequest {
            domain: domain.clone(),
            transport: Transport::Server(ip.to_string()),
            ..Default::default()
        })
        .await?;

        if !results.is_empty() && !results[0].answers.is_empty() {
            println!("✓ [{}] {} — {} answers", name, ip, results[0].answers.len());
            for record in &results[0].answers {
                println!("  {} → {:?}", record.name, record.data);
            }
        } else {
            println!("✗ [{}] {} — no answers", name, ip);
        }
    }

    Ok(())
}
