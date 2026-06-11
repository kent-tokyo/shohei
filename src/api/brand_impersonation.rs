//! Brand impersonation detection — detect domains impersonating known brands.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to check for brand impersonation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandImpersonationRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// A single brand match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandMatch {
    pub brand: String,           // "google", "paypal", etc.
    pub brand_domain: String,    // "google.com", "paypal.com"
    pub edit_distance: u32,      // Levenshtein distance
    pub match_type: String,      // "exact" | "close" | "contains" | "tld_variant"
    pub risk: String,            // "high" | "medium" | "low"
}

/// Result of brand impersonation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandImpersonationResult {
    pub domain: String,
    pub is_impersonating: bool,
    pub matches: Vec<BrandMatch>,
    pub error: Option<String>,
}

const BRANDS: &[(&str, &str)] = &[
    ("google", "google.com"),
    ("apple", "apple.com"),
    ("microsoft", "microsoft.com"),
    ("amazon", "amazon.com"),
    ("paypal", "paypal.com"),
    ("facebook", "facebook.com"),
    ("twitter", "twitter.com"),
    ("instagram", "instagram.com"),
    ("netflix", "netflix.com"),
    ("spotify", "spotify.com"),
    ("linkedin", "linkedin.com"),
    ("github", "github.com"),
    ("dropbox", "dropbox.com"),
    ("adobe", "adobe.com"),
    ("chase", "chase.com"),
    ("wellsfargo", "wellsfargo.com"),
    ("bankofamerica", "bankofamerica.com"),
    ("citibank", "citibank.com"),
    ("dhl", "dhl.com"),
    ("fedex", "fedex.com"),
    ("ups", "ups.com"),
    ("usps", "usps.com"),
    ("steam", "steampowered.com"),
    ("discord", "discord.com"),
    ("cloudflare", "cloudflare.com"),
    ("stripe", "stripe.com"),
    ("shopify", "shopify.com"),
    ("wordpress", "wordpress.com"),
    ("zoom", "zoom.us"),
    ("slack", "slack.com"),
];

const SUSPICIOUS_TLDS: &[&str] = &[".xyz", ".tk", ".ml", ".ga", ".cf", ".pw", ".top", ".click", ".info", ".biz"];

/// Calculate Levenshtein distance between two strings.
fn levenshtein_distance(s1: &str, s2: &str) -> u32 {
    let len1 = s1.len();
    let len2 = s2.len();

    if len1 == 0 {
        return len2 as u32;
    }
    if len2 == 0 {
        return len1 as u32;
    }

    let mut matrix = vec![vec![0u32; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i as u32;
    }
    for j in 0..=len2 {
        matrix[0][j] = j as u32;
    }

    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] { 0 } else { 1 };
            matrix[i][j] = std::cmp::min(
                std::cmp::min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1),
                matrix[i - 1][j - 1] + cost,
            );
        }
    }

    matrix[len1][len2]
}

/// Extract the second-level domain (e.g., "google" from "google.com").
fn extract_sld(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2].to_lowercase()
    } else {
        domain.to_lowercase()
    }
}

/// Get TLD from domain (e.g., ".com" from "google.com").
fn get_tld(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        format!(".{}", parts[parts.len() - 1])
    } else {
        String::new()
    }
}

/// Check if domain impersonates known brands.
pub async fn check_brand_impersonation(req: &BrandImpersonationRequest) -> Result<BrandImpersonationResult> {
    let domain_lower = req.domain.to_lowercase();
    let sld = extract_sld(&domain_lower);
    let tld = get_tld(&domain_lower);
    let mut matches = Vec::new();

    for (brand_name, brand_domain) in BRANDS {
        let brand_sld = extract_sld(brand_domain);

        // Check 1: Exact match (TLD swap)
        if sld == brand_sld {
            matches.push(BrandMatch {
                brand: brand_name.to_string(),
                brand_domain: brand_domain.to_string(),
                edit_distance: 0,
                match_type: "exact".to_string(),
                risk: "high".to_string(),
            });
            continue;
        }

        // Check 2: Close match (Levenshtein distance <= 2)
        let dist = levenshtein_distance(&sld, &brand_sld);
        if dist <= 2 && dist > 0 {
            matches.push(BrandMatch {
                brand: brand_name.to_string(),
                brand_domain: brand_domain.to_string(),
                edit_distance: dist,
                match_type: "close".to_string(),
                risk: "high".to_string(),
            });
            continue;
        }

        // Check 3: Brand contained within domain (e.g., "paypal-secure.com")
        if sld.contains(&brand_sld) && sld != brand_sld {
            matches.push(BrandMatch {
                brand: brand_name.to_string(),
                brand_domain: brand_domain.to_string(),
                edit_distance: 0,
                match_type: "contains".to_string(),
                risk: "medium".to_string(),
            });
            continue;
        }

        // Check 4: TLD variant (suspicious TLD)
        if sld == brand_sld && !tld.is_empty() && SUSPICIOUS_TLDS.iter().any(|st| tld.ends_with(st)) {
            matches.push(BrandMatch {
                brand: brand_name.to_string(),
                brand_domain: brand_domain.to_string(),
                edit_distance: 0,
                match_type: "tld_variant".to_string(),
                risk: "medium".to_string(),
            });
        }
    }

    let is_impersonating = !matches.is_empty();

    Ok(BrandImpersonationResult {
        domain: req.domain.clone(),
        is_impersonating,
        matches,
        error: None,
    })
}
