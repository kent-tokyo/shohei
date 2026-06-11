//! Identity & Credential Security — JWT analysis, OAuth config, cookie security, CSP inspection.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use std::collections::HashMap;

/// JWT security check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSecurityRequest {
    pub token: String,
}

/// JWT security result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSecurityResult {
    pub token_valid: bool,
    pub alg: Option<String>,
    pub alg_secure: bool,
    pub has_expiry: bool,
    pub expires_in_days: Option<i64>,
    pub critical_issues: Vec<String>,
    pub risk_level: String,
}

/// Parse and analyze JWT token security.
pub async fn check_jwt_security(req: &JwtSecurityRequest) -> Result<JwtSecurityResult> {
    let parts: Vec<&str> = req.token.split('.').collect();
    if parts.len() != 3 {
        return Ok(JwtSecurityResult {
            token_valid: false,
            alg: None,
            alg_secure: false,
            has_expiry: false,
            expires_in_days: None,
            critical_issues: vec!["Invalid JWT format (expected 3 parts)".to_string()],
            risk_level: "critical".to_string(),
        });
    }

    let mut alg = None;
    let mut alg_secure = true;
    let mut critical_issues = Vec::new();

    if let Ok(header_bytes) = base64_url_decode(parts[0]) {
        if let Ok(header_str) = String::from_utf8(header_bytes) {
            if let Ok(header) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&header_str) {
                if let Some(alg_val) = header.get("alg").and_then(|v| v.as_str()) {
                    alg = Some(alg_val.to_string());
                    if alg_val == "none" {
                        alg_secure = false;
                        critical_issues.push("Algorithm is 'none' — token signature not validated".to_string());
                    }
                }
            }
        }
    }

    let mut has_expiry = false;
    let mut expires_in_days = None;

    if let Ok(payload_bytes) = base64_url_decode(parts[1]) {
        if let Ok(payload_str) = String::from_utf8(payload_bytes) {
            if let Ok(payload) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&payload_str) {
                if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
                    has_expiry = true;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    expires_in_days = Some((exp - now) / 86400);

                    if (exp - now) < 0 {
                        critical_issues.push("Token has already expired".to_string());
                    }
                }
            }
        }
    }

    let risk_level = if critical_issues.is_empty() && alg_secure && has_expiry {
        "low".to_string()
    } else if critical_issues.is_empty() {
        "medium".to_string()
    } else {
        "critical".to_string()
    };

    Ok(JwtSecurityResult {
        token_valid: !critical_issues.is_empty() || alg_secure,
        alg,
        alg_secure,
        has_expiry,
        expires_in_days,
        critical_issues,
        risk_level,
    })
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>> {
    let mut padded = s.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    let padded = padded.replace('-', "+").replace('_', "/");
    base64_decode(&padded)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use std::str::FromStr;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0usize;

    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        if let Some(idx) = CHARSET.iter().position(|&b| b == c) {
            buf = (buf << 6) | (idx as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                result.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
    }
    Ok(result)
}

/// Cookie security check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieSecurityRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Cookie security result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieSecurityResult {
    pub url: String,
    pub cookie_count: usize,
    pub secure_count: usize,
    pub httponly_count: usize,
    pub samesite_count: usize,
    pub insecure_cookies: Vec<String>,
    pub security_score: u8,
}

/// Inspect HTTP Set-Cookie headers for security flags.
pub async fn check_cookie_security(req: &CookieSecurityRequest) -> Result<CookieSecurityResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    match client.get(&req.url).send().await {
        Ok(response) => {
            let mut cookie_count = 0;
            let mut secure_count = 0;
            let mut httponly_count = 0;
            let mut samesite_count = 0;
            let mut insecure_cookies = Vec::new();

            for (key, val) in response.headers().iter() {
                if key.as_str().to_lowercase() == "set-cookie" {
                    if let Ok(cookie_str) = val.to_str() {
                        cookie_count += 1;
                        let cookie_lower = cookie_str.to_lowercase();

                        let has_secure = cookie_lower.contains("secure");
                        let has_httponly = cookie_lower.contains("httponly");
                        let has_samesite = cookie_lower.contains("samesite");

                        if has_secure {
                            secure_count += 1;
                        }
                        if has_httponly {
                            httponly_count += 1;
                        }
                        if has_samesite {
                            samesite_count += 1;
                        }

                        if !has_secure || !has_httponly {
                            insecure_cookies.push(cookie_str.split('=').next().unwrap_or("unknown").to_string());
                        }
                    }
                }
            }

            let security_score = if cookie_count == 0 {
                100u8
            } else {
                let score = ((secure_count + httponly_count + samesite_count) as u8 * 100) / (cookie_count as u8 * 3);
                score
            };

            Ok(CookieSecurityResult {
                url: req.url.clone(),
                cookie_count,
                secure_count,
                httponly_count,
                samesite_count,
                insecure_cookies,
                security_score,
            })
        }
        Err(_) => Ok(CookieSecurityResult {
            url: req.url.clone(),
            cookie_count: 0,
            secure_count: 0,
            httponly_count: 0,
            samesite_count: 0,
            insecure_cookies: Vec::new(),
            security_score: 0,
        }),
    }
}

/// CSP advanced analysis request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspAdvancedRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// CSP advanced result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspAdvancedResult {
    pub url: String,
    pub csp_present: bool,
    pub policy: Option<String>,
    pub unsafe_inline: bool,
    pub unsafe_eval: bool,
    pub wildcard_sources: bool,
    pub missing_directives: Vec<String>,
    pub security_score: u8,
    pub issues: Vec<String>,
}

/// Deep CSP policy analysis.
pub async fn check_csp_advanced(req: &CspAdvancedRequest) -> Result<CspAdvancedResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    match client.get(&req.url).send().await {
        Ok(response) => {
            let csp = response
                .headers()
                .get("content-security-policy")
                .or_else(|| response.headers().get("content-security-policy-report-only"))
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let mut score = 100u8;
            let mut issues = Vec::new();
            let mut unsafe_inline = false;
            let mut unsafe_eval = false;
            let mut wildcard_sources = false;
            let mut missing_directives = Vec::new();

            if let Some(ref policy) = csp {
                if policy.contains("'unsafe-inline'") {
                    unsafe_inline = true;
                    score = score.saturating_sub(30);
                    issues.push("'unsafe-inline' allows inline scripts — major XSS risk".to_string());
                }
                if policy.contains("'unsafe-eval'") {
                    unsafe_eval = true;
                    score = score.saturating_sub(20);
                    issues.push("'unsafe-eval' allows dynamic code execution".to_string());
                }
                if policy.contains("*") {
                    wildcard_sources = true;
                    score = score.saturating_sub(25);
                    issues.push("Wildcard sources allow any domain".to_string());
                }
                if !policy.contains("default-src") && !policy.contains("script-src") {
                    missing_directives.push("script-src".to_string());
                    score = score.saturating_sub(15);
                }
                if !policy.contains("upgrade-insecure-requests") {
                    missing_directives.push("upgrade-insecure-requests".to_string());
                }
            } else {
                score = 0;
                issues.push("No CSP header detected".to_string());
            }

            Ok(CspAdvancedResult {
                url: req.url.clone(),
                csp_present: csp.is_some(),
                policy: csp,
                unsafe_inline,
                unsafe_eval,
                wildcard_sources,
                missing_directives,
                security_score: score,
                issues,
            })
        }
        Err(_) => Ok(CspAdvancedResult {
            url: req.url.clone(),
            csp_present: false,
            policy: None,
            unsafe_inline: false,
            unsafe_eval: false,
            wildcard_sources: false,
            missing_directives: vec!["Unable to fetch URL".to_string()],
            security_score: 0,
            issues: vec!["Unable to fetch URL".to_string()],
        }),
    }
}

fn default_timeout() -> u64 {
    crate::api::helpers::DEFAULT_REQUEST_TIMEOUT_SECS
}
