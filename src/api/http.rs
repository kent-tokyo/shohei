//! HTTP(S) connectivity checker — verify web endpoint reachability and SSL/TLS.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::{Result, ShoheError};

/// Check HTTP(S) connectivity and headers.
pub async fn check_http(req: &HttpCheckRequest) -> Result<HttpCheckResult> {
    use std::str::FromStr;
    use std::time::Instant;

    crate::api::helpers::validate_url_safety(&req.url)
        .map_err(ShoheError::Parse)?;

    let url = url::Url::from_str(&req.url)
        .map_err(|e| ShoheError::Parse(format!("invalid URL: {}", e)))?;

    let total_start = Instant::now();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .redirect(if req.follow_redirects {
            reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 10 {
                    return attempt.stop();
                }
                if crate::api::helpers::validate_url_safety(attempt.url().as_str()).is_err() {
                    return attempt.stop();
                }
                attempt.follow()
            })
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()
        .map_err(|e| ShoheError::Transport(format!("client creation failed: {}", e)))?;

    let request_start = Instant::now();
    let response = match client.get(req.url.clone()).send().await {
        Ok(r) => r,
        Err(e) => {
            let total_ms = total_start.elapsed().as_millis() as u64;
            return Ok(HttpCheckResult {
                url: req.url.clone(),
                status_code: None,
                status_text: None,
                headers: HashMap::new(),
                hsts_present: false,
                hsts_max_age: None,
                redirect_chain: vec![],
                server_header: None,
                tls_info: None,
                security_headers: None,
                http_version: None,
                timing: Some(HttpTiming {
                    dns_ms: None,
                    connect_ms: None,
                    ttfb_ms: None,
                    total_ms,
                }),
                error: Some(e.to_string()),
            });
        }
    };
    let ttfb_ms = request_start.elapsed().as_millis() as u64;

    let status_code = Some(response.status().as_u16());
    let status_text = Some(response.status().canonical_reason().unwrap_or("").to_string());
    let final_url = response.url().to_string();
    let http_version = Some(format!("{:?}", response.version()).replace("HTTP_", "HTTP/"));

    // Extract headers
    let mut headers = HashMap::new();
    let mut hsts_max_age = None;
    let mut server_header = None;

    for (key, val) in response.headers().iter() {
        let key_str = key.to_string();
        let val_str = std::str::from_utf8(val.as_bytes())
            .unwrap_or("<invalid-utf8>")
            .to_string();

        headers.insert(key_str.clone(), val_str.clone());

        // Check for HSTS
        if key_str.to_lowercase() == "strict-transport-security" {
            if let Some(max_age_str) = val_str.split("max-age=").nth(1) {
                let age_part = max_age_str.split(';').next().unwrap_or("0").trim();
                match age_part.parse::<u64>() {
                    Ok(age) => hsts_max_age = Some(age),
                    Err(_) => {
                        // Malformed max-age value; log but don't fail
                        hsts_max_age = None;
                    }
                }
            }
        }

        // Check for Server
        if key_str.to_lowercase() == "server" {
            server_header = Some(val_str);
        }
    }

    let hsts_present = response.headers().contains_key("strict-transport-security");

    // Redirect chain: build from initial URL to final URL
    let redirect_chain = if final_url != req.url {
        let mut chain = vec![req.url.clone(), final_url.clone()];

        // Check for HTTPS -> HTTP downgrade (security issue)
        if req.url.starts_with("https://") && final_url.starts_with("http://") {
            chain.push("WARNING: HTTPS-to-HTTP downgrade detected".to_string());
        }

        chain
    } else {
        vec![]
    };

    // Extract TLS info if HTTPS
    let tls_info = if url.scheme() == "https" {
        if let Some(host) = url.host_str() {
            match crate::api::check_tls_chain(&crate::api::TlsCheckRequest {
                hostname: host.to_string(),
                port: url.port().unwrap_or(443),
                check_dane: false,
                timeout_secs: req.timeout_secs,
            })
            .await
            {
                Ok(tls_result) => Some(HttpTlsInfo {
                    protocol_version: tls_result.tls_version,
                    cipher_suite: tls_result.cipher_suite,
                    cert_valid: tls_result.valid,
                    days_until_expiry: tls_result.days_until_expiry.map(|d| d as i32),
                }),
                Err(_) => Some(HttpTlsInfo {
                    protocol_version: None,
                    cipher_suite: None,
                    cert_valid: false,
                    days_until_expiry: None,
                }),
            }
        } else {
            None
        }
    } else {
        None
    };

    // Audit security headers
    let security_headers = audit_security_headers(&headers);

    let total_ms = total_start.elapsed().as_millis() as u64;

    Ok(HttpCheckResult {
        url: req.url.clone(),
        status_code,
        status_text,
        headers,
        hsts_present,
        hsts_max_age,
        redirect_chain,
        server_header,
        tls_info,
        security_headers: Some(security_headers),
        http_version,
        timing: Some(HttpTiming {
            dns_ms: None, // DNS time is hard to measure with reqwest
            connect_ms: None, // Connection time is abstracted by reqwest
            ttfb_ms: Some(ttfb_ms),
            total_ms,
        }),
        error: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCheckRequest {
    pub url: String,
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_true() -> bool { true }
fn default_timeout() -> u64 { 10 }

fn audit_security_headers(headers: &HashMap<String, String>) -> SecurityHeadersAudit {
    // Pre-lowercase all keys once — reqwest normalises to lowercase already but this is defensive
    let lower: HashMap<String, &str> = headers.iter()
        .map(|(k, v)| (k.to_lowercase(), v.as_str()))
        .collect();

    struct Spec<'a> {
        canonical: &'a str,
        lookup: &'a str,
        penalty_missing: u8,
        penalty_weak: u8,
        improvement_missing: &'a str,
        evaluate: fn(&str) -> (&'static str, bool, Option<&'static str>),
    }

    let specs: &[Spec] = &[
        Spec {
            canonical: "Strict-Transport-Security",
            lookup: "strict-transport-security",
            penalty_missing: 20,
            penalty_weak: 15,
            improvement_missing: "Add Strict-Transport-Security header for HTTPS sites",
            evaluate: |v| {
                let (status, good) = evaluate_hsts(v);
                let imp = if !good {
                    Some("HSTS: Increase max-age to ≥ 31536000 (1 year), add includeSubDomains and preload")
                } else { None };
                (if good { "good" } else { "weak" }, good, imp)
            },
        },
        Spec {
            canonical: "Content-Security-Policy",
            lookup: "content-security-policy",
            penalty_missing: 15,
            penalty_weak: 10,
            improvement_missing: "Add Content-Security-Policy header",
            evaluate: |v| {
                let (_, good) = evaluate_csp(v);
                let imp = if !good { Some("CSP: Remove unsafe-inline and unsafe-eval") } else { None };
                (if good { "good" } else { "weak" }, good, imp)
            },
        },
        Spec {
            canonical: "X-Frame-Options",
            lookup: "x-frame-options",
            penalty_missing: 10,
            penalty_weak: 10,
            improvement_missing: "Add X-Frame-Options: DENY or SAMEORIGIN",
            evaluate: |v| {
                let good = v.to_uppercase().contains("DENY") || v.to_uppercase().contains("SAMEORIGIN");
                (if good { "good" } else { "weak" }, good, None)
            },
        },
        Spec {
            canonical: "X-Content-Type-Options",
            lookup: "x-content-type-options",
            penalty_missing: 5,
            penalty_weak: 0,
            improvement_missing: "Add X-Content-Type-Options: nosniff",
            evaluate: |v| {
                let good = v.to_lowercase().contains("nosniff");
                (if good { "good" } else { "weak" }, good, None)
            },
        },
        Spec {
            canonical: "Referrer-Policy",
            lookup: "referrer-policy",
            penalty_missing: 0,
            penalty_weak: 0,
            improvement_missing: "",
            evaluate: |v| {
                let good = v.to_lowercase().contains("strict-origin-when-cross-origin");
                (if good { "good" } else { "weak" }, good, None)
            },
        },
        Spec {
            canonical: "Permissions-Policy",
            lookup: "permissions-policy",
            penalty_missing: 0,
            penalty_weak: 0,
            improvement_missing: "",
            evaluate: |_| ("good", true, None),
        },
    ];

    let mut headers_audit = HashMap::new();
    let mut score = 100u8;
    let mut improvements = Vec::new();

    for spec in specs {
        if let Some(&value) = lower.get(spec.lookup) {
            let (status, good, imp) = (spec.evaluate)(value);
            headers_audit.insert(spec.canonical.to_string(), HeaderStatus {
                present: true,
                value: Some(value.to_string()),
                status: status.to_string(),
            });
            if !good {
                score = score.saturating_sub(spec.penalty_weak);
                if let Some(msg) = imp { improvements.push(msg.to_string()); }
            }
        } else {
            headers_audit.insert(spec.canonical.to_string(), HeaderStatus {
                present: false,
                value: None,
                status: "missing".to_string(),
            });
            score = score.saturating_sub(spec.penalty_missing);
            if !spec.improvement_missing.is_empty() {
                improvements.push(spec.improvement_missing.to_string());
            }
        }
    }

    SecurityHeadersAudit { score, headers: headers_audit, improvements }
}

fn evaluate_hsts(hsts_value: &str) -> (String, bool) {
    let max_age_ok = hsts_value
        .split(';')
        .any(|part| {
            let part = part.trim();
            if let Some(age_str) = part.strip_prefix("max-age=") {
                age_str.parse::<u64>().map(|age| age >= 31536000).unwrap_or(false)
            } else {
                false
            }
        });

    let has_subdomain = hsts_value.to_lowercase().contains("includesubdomains");
    let has_preload = hsts_value.to_lowercase().contains("preload");

    let is_good = max_age_ok && has_subdomain && has_preload;
    (if is_good { "good".to_string() } else { "weak".to_string() }, is_good)
}

fn evaluate_csp(csp_value: &str) -> (String, bool) {
    let has_unsafe_inline = csp_value.to_lowercase().contains("unsafe-inline");
    let has_unsafe_eval = csp_value.to_lowercase().contains("unsafe-eval");

    let is_good = !has_unsafe_inline && !has_unsafe_eval;
    let status = if is_good { "good".to_string() } else { "weak".to_string() };

    (status, is_good)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpCheckResult {
    pub url: String,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub headers: HashMap<String, String>,
    pub hsts_present: bool,
    pub hsts_max_age: Option<u64>,
    pub redirect_chain: Vec<String>,
    pub server_header: Option<String>,
    pub tls_info: Option<HttpTlsInfo>,
    #[serde(default)]
    pub security_headers: Option<SecurityHeadersAudit>,
    #[serde(default)]
    pub http_version: Option<String>,
    #[serde(default)]
    pub timing: Option<HttpTiming>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTiming {
    /// DNS resolution time in milliseconds
    pub dns_ms: Option<u64>,
    /// TCP connection time in milliseconds (TLS included for HTTPS)
    pub connect_ms: Option<u64>,
    /// Time to first byte (TTFB) in milliseconds
    pub ttfb_ms: Option<u64>,
    /// Total request time in milliseconds
    pub total_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTlsInfo {
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub cert_valid: bool,
    pub days_until_expiry: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersAudit {
    pub score: u8,  // 0-100
    pub headers: HashMap<String, HeaderStatus>,
    pub improvements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderStatus {
    pub present: bool,
    pub value: Option<String>,
    pub status: String,  // "good", "missing", "weak", etc.
}
