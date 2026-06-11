//! URL structure analysis — detect phishing and brand impersonation signals in URL structure.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use url::Url;

/// Request to analyze URL structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAnalysisRequest {
    pub url: String,
}

/// Result of URL structure analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAnalysisResult {
    pub url: String,
    pub scheme: String,
    pub hostname: String,
    pub tld: Option<String>,
    pub subdomain_depth: u32,
    pub path_length: usize,
    pub query_param_count: u32,
    pub is_ip_address: bool,
    pub has_non_ascii: bool,
    pub risk_signals: Vec<String>,
    pub risk_score: u32,
    pub error: Option<String>,
}

const SUSPICIOUS_TLDS: &[&str] = &[".xyz", ".tk", ".ml", ".ga", ".cf", ".pw", ".top", ".click"];

/// Analyze URL structure for phishing signals.
pub async fn check_url_analysis(req: &UrlAnalysisRequest) -> Result<UrlAnalysisResult> {
    let parsed = match Url::parse(&req.url) {
        Ok(u) => u,
        Err(e) => {
            return Ok(UrlAnalysisResult {
                url: req.url.clone(),
                scheme: String::new(),
                hostname: String::new(),
                tld: None,
                subdomain_depth: 0,
                path_length: 0,
                query_param_count: 0,
                is_ip_address: false,
                has_non_ascii: false,
                risk_signals: vec!["invalid_url".to_string()],
                risk_score: 0,
                error: Some(e.to_string()),
            });
        }
    };

    let scheme = parsed.scheme().to_string();
    let hostname = parsed.host_str().unwrap_or("").to_string();
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let mut risk_signals = Vec::new();
    let mut risk_score: u32 = 0;

    // Check 1: IP address as hostname
    let is_ip = hostname.parse::<std::net::IpAddr>().is_ok();
    if is_ip {
        risk_signals.push("ip_hostname".to_string());
        risk_score += 30;
    }

    // Check 2: Non-ASCII characters (homoglyph attack)
    let has_non_ascii = !hostname.is_ascii();
    if has_non_ascii {
        risk_signals.push("non_ascii_hostname".to_string());
        risk_score += 25;
    }

    // Check 3: Subdomain depth
    let subdomain_depth = hostname.matches('.').count() as u32;
    if subdomain_depth >= 4 {
        risk_signals.push("deep_subdomain".to_string());
        risk_score += 20;
    }

    // Check 4: Suspicious TLD
    for tld_str in SUSPICIOUS_TLDS {
        if hostname.ends_with(tld_str) {
            risk_signals.push("suspicious_tld".to_string());
            risk_score += 15;
            break;
        }
    }

    // Check 5: Long path
    if path.len() > 100 {
        risk_signals.push("long_path".to_string());
        risk_score += 10;
    }

    // Check 6: Many query parameters
    let query_param_count = query.split('&').filter(|s| !s.is_empty()).count() as u32;
    if query_param_count > 5 {
        risk_signals.push("many_params".to_string());
        risk_score += 10;
    }

    // Check 7: Excessive hyphens
    let hyphen_count = hostname.matches('-').count();
    if hyphen_count >= 4 {
        risk_signals.push("excessive_hyphens".to_string());
        risk_score += 10;
    }

    // Check 8: Brand names in subdomain (simplified check for common brands)
    let brand_keywords = ["google", "paypal", "amazon", "apple", "microsoft", "bank", "secure"];
    for brand in &brand_keywords {
        if hostname.contains(brand) && !is_ip {
            risk_signals.push("brand_in_subdomain".to_string());
            risk_score += 15;
            break;
        }
    }

    // Extract TLD
    let parts: Vec<&str> = hostname.split('.').collect();
    let tld = if parts.len() >= 2 {
        Some(format!(".{}", parts[parts.len() - 1]))
    } else {
        None
    };

    // Cap score at 100
    let risk_score = std::cmp::min(risk_score, 100);

    Ok(UrlAnalysisResult {
        url: req.url.clone(),
        scheme,
        hostname,
        tld,
        subdomain_depth,
        path_length: path.len(),
        query_param_count,
        is_ip_address: is_ip,
        has_non_ascii,
        risk_signals,
        risk_score,
        error: None,
    })
}
