//! Typosquatting detection — generate domain variants and check if they resolve.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use futures_util::future::join_all;

/// Request to check for typosquatting variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_mutations")]
    pub max_mutations: u32,
}

fn default_timeout() -> u64 { 10 }
fn default_max_mutations() -> u32 { 200 }

/// A single typosquatting variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatHit {
    pub mutation: String,
    pub strategy: String,
    pub ips: Vec<String>,
    pub live: bool,
}

/// Result of typosquatting check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatResult {
    pub domain: String,
    pub mutations_checked: u32,
    pub live_count: u32,
    pub hits: Vec<TyposquatHit>,
    pub error: Option<String>,
}

/// Generate typosquatting variants for a domain.
pub async fn check_typosquatting(req: &TyposquatRequest) -> Result<TyposquatResult> {
    let domain = req.domain.clone();
    let timeout_secs = req.timeout_secs;

    // Split domain into label and TLD (assume last dot separates them)
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.is_empty() {
        return Ok(TyposquatResult {
            domain,
            mutations_checked: 0,
            live_count: 0,
            hits: vec![],
            error: Some("Invalid domain format".to_string()),
        });
    }

    let label = if parts.len() >= 2 {
        parts[..parts.len() - 1].join(".")
    } else {
        parts[0].to_string()
    };
    let tld = parts[parts.len() - 1];

    // Generate mutations
    let mutations = generate_mutations(&label, tld, req.max_mutations);
    let mutations_checked = mutations.len() as u32;

    // Parallel DNS resolution for all mutations
    let handles: Vec<_> = mutations
        .iter()
        .map(|(mutation, strategy)| {
            let mutation_clone = mutation.clone();
            let strategy_clone = strategy.clone();
            let timeout = timeout_secs;

            async move {
                let dns_req = crate::api::helpers::dns_request_for_record_type(
                    mutation_clone.clone(),
                    "A",
                    timeout,
                );

                match crate::api::check_dns(&dns_req).await {
                    Ok(results) => {
                        let mut ips = Vec::new();
                        for result in results {
                            for record in &result.answers {
                                if let crate::api::RecordData::A(ip_str) = &record.data {
                                    ips.push(ip_str.clone());
                                }
                            }
                        }
                        let live = !ips.is_empty();
                        Some(TyposquatHit {
                            mutation: mutation_clone,
                            strategy: strategy_clone,
                            ips,
                            live,
                        })
                    }
                    Err(_) => None,
                }
            }
        })
        .collect();

    let results = join_all(handles).await;
    let hits: Vec<TyposquatHit> = results.into_iter().filter_map(|r| r).collect();
    let live_count = hits.iter().filter(|h| h.live).count() as u32;

    Ok(TyposquatResult {
        domain,
        mutations_checked,
        live_count,
        hits,
        error: None,
    })
}

/// Generate typosquatting mutation variants.
fn generate_mutations(label: &str, tld: &str, max_count: u32) -> Vec<(String, String)> {
    let mut mutations = Vec::new();

    // TLD swaps (fixed list of common TLDs)
    let tld_swaps = [
        "com", "net", "org", "io", "co", "info", "biz", "de", "uk", "ru", "cn", "jp",
    ];
    for alt_tld in &tld_swaps {
        if alt_tld != &tld && mutations.len() < max_count as usize {
            mutations.push((
                format!("{}.{}", label, alt_tld),
                "tld_swap".to_string(),
            ));
        }
    }

    // Missing character (remove each char one at a time)
    for (byte_i, _) in label.char_indices() {
        if mutations.len() >= max_count as usize {
            break;
        }
        let mut mutated = label.to_string();
        mutated.remove(byte_i);
        if !mutated.is_empty() {
            mutations.push((
                format!("{}.{}", mutated, tld),
                "missing_char".to_string(),
            ));
        }
    }

    // Transposition (swap adjacent characters)
    for i in 0..label.len().saturating_sub(1) {
        if mutations.len() >= max_count as usize {
            break;
        }
        let mut chars: Vec<char> = label.chars().collect();
        chars.swap(i, i + 1);
        let mutated: String = chars.iter().collect();
        mutations.push((
            format!("{}.{}", mutated, tld),
            "transposition".to_string(),
        ));
    }

    // Double character (duplicate each char)
    for i in 0..label.len() {
        if mutations.len() >= max_count as usize {
            break;
        }
        let mut mutated = String::new();
        for (idx, ch) in label.chars().enumerate() {
            mutated.push(ch);
            if idx == i {
                mutated.push(ch);
            }
        }
        mutations.push((
            format!("{}.{}", mutated, tld),
            "double_char".to_string(),
        ));
    }

    // Hyphen insertion (between characters)
    for (byte_i, _) in label.char_indices().skip(1) {
        if mutations.len() >= max_count as usize {
            break;
        }
        let mut mutated = label.to_string();
        mutated.insert(byte_i, '-');
        mutations.push((
            format!("{}.{}", mutated, tld),
            "hyphen".to_string(),
        ));
    }

    // Homoglyph (character substitution)
    let homoglyphs = [('o', '0'), ('l', '1'), ('i', '1'), ('e', '3'), ('a', '4'), ('s', '5'), ('g', '9')];
    for (byte_i, ch) in label.char_indices() {
        if mutations.len() >= max_count as usize {
            break;
        }
        for (from, to) in &homoglyphs {
            if ch == *from {
                let mut mutated = label.to_string();
                let char_len = ch.len_utf8();
                mutated.replace_range(byte_i..byte_i + char_len, &to.to_string());
                mutations.push((
                    format!("{}.{}", mutated, tld),
                    "homoglyph".to_string(),
                ));
                break;
            }
        }
    }

    // Deduplicate
    mutations.sort();
    mutations.dedup();
    mutations.truncate(max_count as usize);

    mutations
}
