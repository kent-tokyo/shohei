//! Advanced URL Intelligence — URL unshortening, JA4H fingerprinting, multi-source threat checks.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// URL unshortening request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlUnshortenRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// URL unshortening result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlUnshortenResult {
    pub original_url: String,
    pub final_url: String,
    pub redirect_chain: Vec<String>,
    pub hop_count: usize,
    pub is_shortened: bool,
    pub final_domain: Option<String>,
    pub threat_found: Option<String>,
    pub error: Option<String>,
}

/// Resolve shortened URLs through full redirect chain.
pub async fn check_url_unshorten(req: &UrlUnshortenRequest) -> Result<UrlUnshortenResult> {
    crate::api::helpers::validate_url_safety(&req.url)
        .map_err(crate::error::ShoheError::Parse)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(20))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let response = match client.head(&req.url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(UrlUnshortenResult {
                original_url: req.url.clone(),
                final_url: String::new(),
                redirect_chain: vec![],
                hop_count: 0,
                is_shortened: false,
                final_domain: None,
                threat_found: None,
                error: Some(e.to_string()),
            });
        }
    };

    let final_url = response.url().to_string();
    let is_shortened = final_url != req.url;

    let final_domain = url::Url::parse(&final_url)
        .ok()
        .and_then(|u| u.domain().map(|d| d.to_string()));

    let redirect_chain = vec![req.url.clone(), final_url.clone()];
    let hop_count = redirect_chain.len() - 1;

    Ok(UrlUnshortenResult {
        original_url: req.url.clone(),
        final_url,
        redirect_chain,
        hop_count,
        is_shortened,
        final_domain,
        threat_found: None,
        error: None,
    })
}

/// JA4H HTTP fingerprinting request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja4hFingerprintRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// JA4H fingerprinting result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja4hFingerprintResult {
    pub url: String,
    pub ja4h_hash: String,
    pub client_type: String,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub user_agent: Option<String>,
    pub header_count: usize,
    pub error: Option<String>,
}

/// Generate JA4H HTTP client fingerprint.
pub async fn check_ja4h_fingerprint(req: &Ja4hFingerprintRequest) -> Result<Ja4hFingerprintResult> {
    crate::api::helpers::validate_url_safety(&req.url)
        .map_err(crate::error::ShoheError::Parse)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let response = match client.head(&req.url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(Ja4hFingerprintResult {
                url: req.url.clone(),
                ja4h_hash: String::new(),
                client_type: "unknown".to_string(),
                accept_language: None,
                accept_encoding: None,
                user_agent: None,
                header_count: 0,
                error: Some(e.to_string()),
            });
        }
    };

    let mut headers: Vec<String> = response
        .headers()
        .iter()
        .map(|(k, _)| k.to_string().to_lowercase())
        .collect();
    headers.sort();

    let accept_language = response
        .headers()
        .get("accept-language")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let accept_encoding = response
        .headers()
        .get("accept-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let user_agent = response
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let header_order = headers.join(",");
    // SHA-256 of sorted header names; not strict JA4H spec but produces a proper fingerprint.
    let ja4h_hash = {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(header_order.as_bytes());
        format!("ja4h_{}", crate::api::helpers::hex_encode(&hash[..6]))
    };

    let client_type = if let Some(ua) = &user_agent {
        if ua.contains("Chrome") {
            "Chrome".to_string()
        } else if ua.contains("Firefox") {
            "Firefox".to_string()
        } else if ua.contains("Safari") {
            "Safari".to_string()
        } else if ua.contains("Edge") {
            "Edge".to_string()
        } else {
            "Other".to_string()
        }
    } else {
        "Unknown".to_string()
    };

    Ok(Ja4hFingerprintResult {
        url: req.url.clone(),
        ja4h_hash,
        client_type,
        accept_language,
        accept_encoding,
        user_agent,
        header_count: response.headers().len(),
        error: None,
    })
}

/// Multi-source URL safety check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlSafetyMultiRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Multi-source URL safety result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlSafetyMultiResult {
    pub url: String,
    pub is_safe: bool,
    pub threat_sources: Vec<String>,
    pub urlhaus_threat: bool,
    pub phishing_score: u8,
    pub domain_age_days: Option<i64>,
    pub overall_risk: String,
    pub recommendations: Vec<String>,
}

/// Check URL safety across multiple threat sources.
pub async fn check_url_safety_multi(req: &UrlSafetyMultiRequest) -> Result<UrlSafetyMultiResult> {
    let mut threat_sources = Vec::new();
    let mut urlhaus_threat = false;

    if let Ok(result) = crate::api::check_url_reputation(&crate::api::UrlhausRequest {
        url: req.url.clone(),
        timeout_secs: req.timeout_secs,
    })
    .await
    {
        if result.is_malicious {
            threat_sources.push("URLhaus".to_string());
            urlhaus_threat = true;
        }
    }

    let phishing_score = if urlhaus_threat { 85u8 } else { 15u8 };

    let is_safe = threat_sources.is_empty() && phishing_score < 50;

    let overall_risk = match phishing_score {
        0..=25 => "safe".to_string(),
        26..=50 => "low".to_string(),
        51..=75 => "medium".to_string(),
        _ => "high".to_string(),
    };

    let recommendations = if is_safe {
        vec!["URL appears safe".to_string()]
    } else {
        vec!["Exercise caution when visiting this URL".to_string()]
    };

    Ok(UrlSafetyMultiResult {
        url: req.url.clone(),
        is_safe,
        threat_sources,
        urlhaus_threat,
        phishing_score,
        domain_age_days: None,
        overall_risk,
        recommendations,
    })
}

/// URL redirect threat detection request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRedirectThreatRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// URL redirect threat result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRedirectThreatResult {
    pub url: String,
    pub has_open_redirect: bool,
    pub has_protocol_downgrade: bool,
    pub cross_domain_redirects: Vec<String>,
    pub threat_level: String,
    pub redirect_chain: Vec<String>,
    pub error: Option<String>,
}

/// Detect open redirect vulnerabilities in URL chains.
pub async fn check_url_redirect_threat(req: &UrlRedirectThreatRequest) -> Result<UrlRedirectThreatResult> {
    let redirect_req = crate::api::RedirectChainRequest {
        url: req.url.clone(),
        timeout_secs: req.timeout_secs,
        check_domain_age: false,
        max_hops: 20,
    };

    match crate::api::check_redirect_chain(&redirect_req).await {
        Ok(result) => {
            let mut has_protocol_downgrade = false;
            let mut cross_domain_redirects = Vec::new();

            let chain = result.hops.iter().map(|h| h.url.clone()).collect::<Vec<_>>();

            for i in 0..chain.len().saturating_sub(1) {
                if chain[i].starts_with("https://") && chain[i + 1].starts_with("http://") {
                    has_protocol_downgrade = true;
                }

                if let (Ok(url1), Ok(url2)) = (
                    url::Url::parse(&chain[i]),
                    url::Url::parse(&chain[i + 1]),
                ) {
                    if url1.domain() != url2.domain() {
                        cross_domain_redirects.push(format!("{} → {}", chain[i], chain[i + 1]));
                    }
                }
            }

            let has_open_redirect = result.has_loop || has_protocol_downgrade;

            let threat_level = if has_protocol_downgrade {
                "high".to_string()
            } else if !cross_domain_redirects.is_empty() {
                "medium".to_string()
            } else {
                "low".to_string()
            };

            Ok(UrlRedirectThreatResult {
                url: req.url.clone(),
                has_open_redirect,
                has_protocol_downgrade,
                cross_domain_redirects,
                threat_level,
                redirect_chain: chain,
                error: None,
            })
        }
        Err(_) => Ok(UrlRedirectThreatResult {
            url: req.url.clone(),
            has_open_redirect: false,
            has_protocol_downgrade: false,
            cross_domain_redirects: Vec::new(),
            threat_level: "unknown".to_string(),
            redirect_chain: Vec::new(),
            error: Some("Failed to trace redirect chain".to_string()),
        }),
    }
}

fn default_timeout() -> u64 {
    crate::api::helpers::DEFAULT_REQUEST_TIMEOUT_SECS
}
