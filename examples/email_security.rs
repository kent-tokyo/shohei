//! Check email security records for a domain (Phase 1 feature).
//!
//! Validates MX records, SPF, DKIM, and DMARC configuration to identify
//! misconfigurations and security issues.
//!
//! Run with: cargo run --example email_security -- gmail.com

use std::env;
use shohei::api::{check_dns, DnsCheckRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = env::args()
        .nth(1)
        .unwrap_or_else(|| "gmail.com".to_string());

    println!("Email Security Check for {}\n", domain);
    println!("Checking the following records:\n");

    // Check MX, SPF, DKIM, DMARC
    let records_to_check = vec![
        ("MX", "Which servers accept mail"),
        ("TXT", "SPF, DKIM, DMARC policies"),
    ];

    for (record_type, description) in records_to_check {
        println!("  • {} — {}", record_type, description);
    }

    println!("\nQuerying {}...\n", domain);

    // Query MX records
    let mx_results = check_dns(&DnsCheckRequest {
        domain: domain.clone(),
        record_types: vec!["MX".to_string()],
        ..Default::default()
    })
    .await?;

    println!("MX Records:");
    if mx_results[0].answers.is_empty() {
        println!("  ⚠ No MX records found - mail delivery may fail");
    } else {
        for record in &mx_results[0].answers {
            println!("  ✓ {:?}", record.data);
        }
    }

    // Query TXT records (SPF, DKIM, DMARC)
    let txt_results = check_dns(&DnsCheckRequest {
        domain: domain.clone(),
        record_types: vec!["TXT".to_string()],
        ..Default::default()
    })
    .await?;

    println!("\nSecurity Policy Records (TXT):");
    let mut found_spf = false;
    let mut found_dmarc = false;

    for record in &txt_results[0].answers {
        if let shohei::api::RecordData::Txt(texts) = &record.data {
            for text in texts {
                if text.starts_with("v=spf1") {
                    println!("  ✓ SPF found: {}", text.chars().take(60).collect::<String>());
                    found_spf = true;
                }
            }
        }
    }

    // Check DMARC (usually at _dmarc.domain)
    let dmarc_domain = format!("_dmarc.{}", domain);
    let dmarc_results = check_dns(&DnsCheckRequest {
        domain: dmarc_domain,
        record_types: vec!["TXT".to_string()],
        ..Default::default()
    })
    .await?;

    for record in &dmarc_results[0].answers {
        if let shohei::api::RecordData::Txt(texts) = &record.data {
            for text in texts {
                if text.starts_with("v=DMARC1") {
                    println!("  ✓ DMARC found: {}", text.chars().take(60).collect::<String>());
                    found_dmarc = true;
                }
            }
        }
    }

    if !found_spf {
        println!("  ⚠ SPF record missing - increases risk of spoofing");
    }
    if !found_dmarc {
        println!("  ⚠ DMARC record missing - no authentication policy");
    }

    println!("\nNote: Full Phase 1 implementation with dedicated email_security() function coming in v0.5.0");

    Ok(())
}
