//! CDN / WAF detector — identify CDN and WAF providers via HTTP headers.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use tokio::time::{timeout, Duration};

/// Detect CDN and WAF providers based on HTTP response headers.
pub async fn detect_cdn(req: &CdnDetectRequest) -> Result<CdnDetectResult> {
    // Ensure URL has scheme
    let url = if req.url.starts_with("http://") || req.url.starts_with("https://") {
        req.url.clone()
    } else {
        format!("https://{}", req.url)
    };

    // Fetch the page
    let client = reqwest::Client::new();
    let response = match timeout(
        Duration::from_secs(req.timeout_secs),
        client.get(&url).send()
    ).await {
        Ok(Ok(resp)) => resp,
        _ => {
            return Ok(CdnDetectResult {
                url: req.url.clone(),
                cdn_name: None,
                confidence: "error".to_string(),
                detected_headers: vec![],
                error: Some("Failed to fetch URL".to_string()),
            });
        }
    };

    let mut detected_headers = Vec::new();
    let mut cdn_name = None;
    let mut confidence = "low".to_string();

    // Check headers in priority order
    let headers = response.headers();

    // Cloudflare
    if let Some(cf_ray) = headers.get("cf-ray") {
        if let Ok(cf_val) = cf_ray.to_str() {
            detected_headers.push(format!("CF-Ray: {}", cf_val));
            cdn_name = Some("Cloudflare".to_string());
            confidence = "high".to_string();
        }
    } else if let Some(server) = headers.get("server") {
        if let Ok(server_val) = server.to_str() {
            if server_val.contains("cloudflare") {
                detected_headers.push("Server: cloudflare".to_string());
                cdn_name = Some("Cloudflare".to_string());
                confidence = "high".to_string();
            }
        }
    }

    // AWS CloudFront
    if cdn_name.is_none() {
        if let Some(amz_cf_id) = headers.get("x-amz-cf-id") {
            if let Ok(amz_val) = amz_cf_id.to_str() {
                detected_headers.push(format!("X-Amz-Cf-Id: {}", amz_val));
                cdn_name = Some("AWS CloudFront".to_string());
                confidence = "high".to_string();
            }
        }
    }

    // Fastly
    if cdn_name.is_none() {
        if let Some(served_by) = headers.get("x-served-by") {
            if let Ok(served_val) = served_by.to_str() {
                detected_headers.push(format!("X-Served-By: {}", served_val));
                cdn_name = Some("Fastly".to_string());
                confidence = "high".to_string();
            }
        }
    }

    // Akamai
    if cdn_name.is_none() {
        if headers.get("x-akamai-transformed").is_some() {
            detected_headers.push("X-Akamai-Transformed: present".to_string());
            cdn_name = Some("Akamai".to_string());
            confidence = "high".to_string();
        }
    }

    // Vercel
    if cdn_name.is_none() {
        if let Some(vercel_id) = headers.get("x-vercel-id") {
            if let Ok(vercel_val) = vercel_id.to_str() {
                detected_headers.push(format!("X-Vercel-Id: {}", vercel_val));
                cdn_name = Some("Vercel".to_string());
                confidence = "high".to_string();
            }
        }
    }

    // Netlify
    if cdn_name.is_none() {
        if let Some(nf_id) = headers.get("x-nf-request-id") {
            if let Ok(nf_val) = nf_id.to_str() {
                detected_headers.push(format!("X-Nf-Request-Id: {}", nf_val));
                cdn_name = Some("Netlify".to_string());
                confidence = "high".to_string();
            }
        }
    }

    // Imperva / Incapsula
    if cdn_name.is_none() {
        if let Some(cdn_header) = headers.get("x-cdn") {
            if let Ok(cdn_val) = cdn_header.to_str() {
                if cdn_val.contains("Incapsula") {
                    detected_headers.push("X-CDN: Incapsula".to_string());
                    cdn_name = Some("Imperva / Incapsula".to_string());
                    confidence = "high".to_string();
                }
            }
        }
    }

    Ok(CdnDetectResult {
        url: req.url.clone(),
        cdn_name,
        confidence,
        detected_headers,
        error: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnDetectRequest {
    /// URL to check
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnDetectResult {
    pub url: String,
    /// Detected CDN/WAF name (e.g., "Cloudflare", "AWS CloudFront")
    pub cdn_name: Option<String>,
    /// Confidence level: high, medium, low, error
    pub confidence: String,
    /// Headers that triggered detection
    pub detected_headers: Vec<String>,
    pub error: Option<String>,
}
