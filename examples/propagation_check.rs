//! Check DNS propagation across multiple global resolvers.
//!
//! This example demonstrates how to use shohei as a library to check if a domain
//! is propagated across different DNS resolvers worldwide.
//!
//! Run with: cargo run --example propagation_check -- google.com

use std::env;

#[tokio::main]
async fn main() {
    let domain = env::args()
        .nth(1)
        .unwrap_or_else(|| "google.com".to_string());

    println!("Checking propagation of {} across global resolvers...\n", domain);

    // Example resolvers (in Phase 1, shohei will have a built-in propagation check function)
    let resolvers = vec![
        ("Google", "8.8.8.8"),
        ("Cloudflare", "1.1.1.1"),
        ("Quad9", "9.9.9.9"),
        ("OpenDNS", "208.67.222.222"),
    ];

    for (name, ip) in resolvers {
        // Placeholder: when shohei library is ready, this will call the actual resolver
        println!("[{}] {}: <would query {}> ", name, ip, domain);
    }

    println!("\nNote: Full implementation available in v0.5.0 with Phase 1 library API");
}
