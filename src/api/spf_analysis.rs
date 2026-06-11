//! SPF recursive deep analysis — count total DNS lookups across include chains per RFC 7208.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use std::collections::HashSet;

/// Request for SPF deep analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfAnalysisRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// SPF include node in the resolution tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfIncludeNode {
    pub domain: String,
    pub raw: Option<String>,
    pub depth: u32,
    pub ip4_cidrs: Vec<String>,
    pub ip6_cidrs: Vec<String>,
    pub includes: Vec<String>,  // domains included by this node
    pub lookup_count: u32,      // DNS lookups this node adds
}

/// SPF recursive analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfAnalysisResult {
    pub domain: String,
    pub total_lookup_count: u32,
    pub exceeds_rfc_limit: bool,  // > 10
    pub authorized_ip4: Vec<String>,
    pub authorized_ip6: Vec<String>,
    pub include_tree: Vec<SpfIncludeNode>,
    pub all_qualifier: Option<String>,  // "+all" | "-all" | "~all" | "?all"
    pub error: Option<String>,
}

/// Perform SPF recursive deep analysis.
pub async fn check_spf_deep(req: &SpfAnalysisRequest) -> Result<SpfAnalysisResult> {
    const MAX_SPF_DEPTH: u32 = 10;  // RFC 7208 §4.6.4 limit
    const MAX_QUEUE_SIZE: usize = 1000;  // Prevent queue explosion

    let mut visited = HashSet::new();
    let mut work_queue = vec![(req.domain.clone(), 0u32)];
    let mut nodes = Vec::new();
    let mut total_lookups = 0u32;

    while let Some((domain, depth)) = work_queue.pop() {
        if depth >= MAX_SPF_DEPTH || visited.contains(&domain) || work_queue.len() >= MAX_QUEUE_SIZE {
            continue;
        }
        visited.insert(domain.clone());

        if let Some(node) = resolve_spf_domain(&domain, depth, req.timeout_secs).await {
            total_lookups = total_lookups.saturating_add(node.lookup_count);
            for include_domain in &node.includes {
                if !visited.contains(include_domain) {
                    work_queue.push((include_domain.clone(), depth + 1));
                }
            }
            nodes.push(node);
        }
    }

    let mut all_ip4 = Vec::new();
    let mut all_ip6 = Vec::new();

    for node in &nodes {
        all_ip4.extend(node.ip4_cidrs.clone());
        all_ip6.extend(node.ip6_cidrs.clone());
    }

    all_ip4.sort();
    all_ip4.dedup();
    all_ip6.sort();
    all_ip6.dedup();

    Ok(SpfAnalysisResult {
        domain: req.domain.clone(),
        total_lookup_count: total_lookups,
        exceeds_rfc_limit: total_lookups > 10,
        authorized_ip4: all_ip4,
        authorized_ip6: all_ip6,
        include_tree: nodes,
        all_qualifier: None,
        error: None,
    })
}

async fn resolve_spf_domain(domain: &str, depth: u32, timeout_secs: u64) -> Option<SpfIncludeNode> {
    // Fetch TXT records
    let dns_req = crate::api::DnsCheckRequest {
        domain: domain.to_string(),
        record_types: vec!["TXT".to_string()],
        timeout_secs,
        ..Default::default()
    };

    let txt_records = match crate::api::check_dns(&dns_req).await {
        Ok(results) => results,
        Err(_) => {
            return Some(SpfIncludeNode {
                domain: domain.to_string(),
                raw: None,
                depth,
                ip4_cidrs: vec![],
                ip6_cidrs: vec![],
                includes: vec![],
                lookup_count: 1,
            });
        }
    };

    // Find SPF record
    let mut spf_raw = None;
    for result in &txt_records {
        for answer in &result.answers {
            if let crate::resolver::RecordData::Txt(txt_parts) = &answer.data {
                let txt = txt_parts.join("");
                if txt.starts_with("v=spf1") {
                    spf_raw = Some(txt);
                    break;
                }
            }
        }
        if spf_raw.is_some() {
            break;
        }
    }

    let mut ip4_cidrs = Vec::new();
    let mut ip6_cidrs = Vec::new();
    let mut includes = Vec::new();
    let lookup_count = 1u32;

    if let Some(spf) = spf_raw.as_ref() {
        // Parse SPF record
        let parts: Vec<&str> = spf.split_whitespace().collect();
        for part in parts {
            if part.starts_with("ip4:") && part.len() > 4 {
                ip4_cidrs.push(part[4..].to_string());
            } else if part.starts_with("ip6:") && part.len() > 4 {
                ip6_cidrs.push(part[4..].to_string());
            } else if part.starts_with("include:") && part.len() > 8 {
                let include_domain = &part[8..];
                includes.push(include_domain.to_string());
            } else if part.starts_with("redirect=") && part.len() > 9 {
                let redirect_domain = &part[9..];
                includes.push(redirect_domain.to_string());
            }
        }
    }

    Some(SpfIncludeNode {
        domain: domain.to_string(),
        raw: spf_raw,
        depth,
        ip4_cidrs,
        ip6_cidrs,
        includes,
        lookup_count,
    })
}
