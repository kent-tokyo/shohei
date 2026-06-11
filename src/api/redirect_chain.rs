//! URL redirect chain tracing — follow and analyze HTTP redirects.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to trace redirect chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectChainRequest {
    pub url: String,
    #[serde(default = "default_max_hops")]
    pub max_hops: u32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_max_hops() -> u32 { 20 }
fn default_timeout() -> u64 { 10 }

/// A single redirect hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub url: String,
    pub status_code: u16,
    pub location: Option<String>,
    pub scheme_downgrade: bool,
}

/// Result of redirect chain tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectChainResult {
    pub original_url: String,
    pub final_url: String,
    pub hop_count: u32,
    pub hops: Vec<RedirectHop>,
    pub has_loop: bool,
    pub has_scheme_downgrade: bool,
    pub error: Option<String>,
}

/// Trace HTTP redirect chain for a URL.
pub async fn check_redirect_chain(req: &RedirectChainRequest) -> Result<RedirectChainResult> {
    let original_url = req.url.clone();
    let max_hops = req.max_hops as usize;

    // Build client with no automatic redirects
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(format!("Client build failed: {}", e)))?;

    let mut hops = Vec::new();
    let mut current_url = original_url.clone();
    let mut seen_urls = std::collections::HashSet::new();
    let mut has_loop = false;
    let mut has_scheme_downgrade = false;

    while hops.len() < max_hops {
        seen_urls.insert(current_url.clone());

        let response = match client
            .get(&current_url)
            .timeout(std::time::Duration::from_secs(req.timeout_secs))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(RedirectChainResult {
                    original_url,
                    final_url: current_url,
                    hop_count: hops.len() as u32,
                    hops,
                    has_loop,
                    has_scheme_downgrade,
                    error: Some(format!("HTTP request failed: {}", e)),
                });
            }
        };

        let status_code = response.status().as_u16();
        let is_redirect = (300..400).contains(&status_code);

        let location = if is_redirect {
            response
                .headers()
                .get("location")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        } else {
            None
        };

        // Check for scheme downgrade (HTTPS -> HTTP)
        let next_url = location.clone().unwrap_or_default();
        let current_scheme = current_url.split("://").next().unwrap_or("http");
        let next_scheme = next_url.split("://").next().unwrap_or("http");
        let scheme_downgrade = current_scheme == "https" && next_scheme == "http";
        if scheme_downgrade {
            has_scheme_downgrade = true;
        }

        hops.push(RedirectHop {
            url: current_url.clone(),
            status_code,
            location: location.clone(),
            scheme_downgrade,
        });

        // Stop if not a redirect
        if !is_redirect {
            break;
        }

        // Check for redirect loops
        if let Some(ref next) = location {
            if seen_urls.contains(next) {
                has_loop = true;
                hops.push(RedirectHop {
                    url: next.clone(),
                    status_code: 0,
                    location: None,
                    scheme_downgrade: false,
                });
                break;
            }
            current_url = next.clone();
        } else {
            break;
        }
    }

    let final_url = hops.last().map(|h| h.url.clone()).unwrap_or(original_url.clone());

    Ok(RedirectChainResult {
        original_url,
        final_url,
        hop_count: hops.len() as u32,
        hops,
        has_loop,
        has_scheme_downgrade,
        error: None,
    })
}
