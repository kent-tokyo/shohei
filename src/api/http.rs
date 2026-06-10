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

    // Redirect chain: track if URL changed
    let redirect_chain = if final_url != req.url {
        vec![req.url.clone(), final_url.clone()]
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
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTlsInfo {
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub cert_valid: bool,
    pub days_until_expiry: Option<i32>,
}
