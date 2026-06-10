//! HTTP(S) connectivity checker — verify web endpoint reachability and SSL/TLS.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::{Result, ShoheError};

/// Check HTTP(S) connectivity and headers.
pub async fn check_http(req: &HttpCheckRequest) -> Result<HttpCheckResult> {
    use std::str::FromStr;

    let url = url::Url::from_str(&req.url)
        .map_err(|e| ShoheError::Parse(format!("invalid URL: {}", e)))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .redirect(if req.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()
        .map_err(|e| ShoheError::Transport(format!("client creation failed: {}", e)))?;

    let response = match client.get(req.url.clone()).send().await {
        Ok(r) => r,
        Err(e) => {
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
                error: Some(e.to_string()),
            });
        }
    };

    let status_code = Some(response.status().as_u16());
    let status_text = Some(response.status().canonical_reason().unwrap_or("").to_string());
    let final_url = response.url().to_string();

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
                if let Ok(age) = max_age_str.split(';').next().unwrap_or("0").parse::<u64>() {
                    hsts_max_age = Some(age);
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
    let mut headers_audit = HashMap::new();
    let mut score = 100u8;
    let mut improvements = Vec::new();

    // Check HSTS
    let hsts_key = headers
        .keys()
        .find(|k| k.to_lowercase() == "strict-transport-security")
        .cloned();

    if let Some(key) = hsts_key {
        let hsts_value = &headers[&key];
        let (hsts_status, hsts_good) = evaluate_hsts(hsts_value);
        headers_audit.insert(
            "Strict-Transport-Security".to_string(),
            HeaderStatus {
                present: true,
                value: Some(hsts_value.clone()),
                status: hsts_status,
            },
        );
        if !hsts_good {
            score = score.saturating_sub(15);
            improvements.push("HSTS: Increase max-age to ≥ 31536000 (1 year), add includeSubDomains and preload".to_string());
        }
    } else {
        headers_audit.insert(
            "Strict-Transport-Security".to_string(),
            HeaderStatus {
                present: false,
                value: None,
                status: "missing".to_string(),
            },
        );
        score = score.saturating_sub(20);
        improvements.push("Add Strict-Transport-Security header for HTTPS sites".to_string());
    }

    // Check CSP
    let csp_key = headers
        .keys()
        .find(|k| k.to_lowercase() == "content-security-policy")
        .cloned();

    if let Some(key) = csp_key {
        let csp_value = &headers[&key];
        let (csp_status, csp_good) = evaluate_csp(csp_value);
        headers_audit.insert(
            "Content-Security-Policy".to_string(),
            HeaderStatus {
                present: true,
                value: Some(csp_value.clone()),
                status: csp_status,
            },
        );
        if !csp_good {
            score = score.saturating_sub(10);
            improvements.push("CSP: Remove unsafe-inline and unsafe-eval".to_string());
        }
    } else {
        headers_audit.insert(
            "Content-Security-Policy".to_string(),
            HeaderStatus {
                present: false,
                value: None,
                status: "missing".to_string(),
            },
        );
        score = score.saturating_sub(15);
        improvements.push("Add Content-Security-Policy header".to_string());
    }

    // Check X-Frame-Options
    let xfo_key = headers
        .keys()
        .find(|k| k.to_lowercase() == "x-frame-options")
        .cloned();

    if let Some(key) = xfo_key {
        let xfo_value = &headers[&key];
        let xfo_good = xfo_value.to_uppercase().contains("DENY") || xfo_value.to_uppercase().contains("SAMEORIGIN");
        headers_audit.insert(
            "X-Frame-Options".to_string(),
            HeaderStatus {
                present: true,
                value: Some(xfo_value.clone()),
                status: if xfo_good { "good".to_string() } else { "weak".to_string() },
            },
        );
        if !xfo_good {
            score = score.saturating_sub(10);
        }
    } else {
        headers_audit.insert(
            "X-Frame-Options".to_string(),
            HeaderStatus {
                present: false,
                value: None,
                status: "missing".to_string(),
            },
        );
        score = score.saturating_sub(10);
        improvements.push("Add X-Frame-Options: DENY or SAMEORIGIN".to_string());
    }

    // Check X-Content-Type-Options
    let xcto_key = headers
        .keys()
        .find(|k| k.to_lowercase() == "x-content-type-options")
        .cloned();

    if let Some(key) = xcto_key {
        let xcto_value = &headers[&key];
        let xcto_good = xcto_value.to_lowercase().contains("nosniff");
        headers_audit.insert(
            "X-Content-Type-Options".to_string(),
            HeaderStatus {
                present: true,
                value: Some(xcto_value.clone()),
                status: if xcto_good { "good".to_string() } else { "weak".to_string() },
            },
        );
    } else {
        headers_audit.insert(
            "X-Content-Type-Options".to_string(),
            HeaderStatus {
                present: false,
                value: None,
                status: "missing".to_string(),
            },
        );
        score = score.saturating_sub(5);
        improvements.push("Add X-Content-Type-Options: nosniff".to_string());
    }

    // Check Referrer-Policy
    let rp_key = headers
        .keys()
        .find(|k| k.to_lowercase() == "referrer-policy")
        .cloned();

    if let Some(key) = rp_key {
        let rp_value = &headers[&key];
        let rp_good = rp_value.to_lowercase().contains("strict-origin-when-cross-origin");
        headers_audit.insert(
            "Referrer-Policy".to_string(),
            HeaderStatus {
                present: true,
                value: Some(rp_value.clone()),
                status: if rp_good { "good".to_string() } else { "weak".to_string() },
            },
        );
    } else {
        headers_audit.insert(
            "Referrer-Policy".to_string(),
            HeaderStatus {
                present: false,
                value: None,
                status: "missing".to_string(),
            },
        );
    }

    // Check Permissions-Policy
    let pp_key = headers
        .keys()
        .find(|k| k.to_lowercase() == "permissions-policy")
        .cloned();

    if pp_key.is_some() {
        headers_audit.insert(
            "Permissions-Policy".to_string(),
            HeaderStatus {
                present: true,
                value: pp_key.and_then(|k| headers.get(&k).cloned()),
                status: "good".to_string(),
            },
        );
    } else {
        headers_audit.insert(
            "Permissions-Policy".to_string(),
            HeaderStatus {
                present: false,
                value: None,
                status: "missing".to_string(),
            },
        );
    }

    SecurityHeadersAudit {
        score,
        headers: headers_audit,
        improvements,
    }
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
    let status = if is_good {
        "good".to_string()
    } else if max_age_ok {
        "weak".to_string()
    } else {
        "weak".to_string()
    };

    (status, is_good)
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
    pub error: Option<String>,
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
