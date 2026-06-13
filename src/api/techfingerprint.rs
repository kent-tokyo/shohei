//! Technology stack fingerprinting — identify web server, framework, CMS software.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to fingerprint technologies used by a web server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechFingerprintRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

/// A detected technology with version and source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechHit {
    pub technology: String,
    pub version: Option<String>,
    pub category: String,
    pub source: String,
}

/// Result of technology fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechFingerprintResult {
    pub url: String,
    pub technologies: Vec<TechHit>,
    pub error: Option<String>,
}

/// Fingerprint web technologies from HTTP response headers.
pub async fn check_tech_stack(req: &TechFingerprintRequest) -> Result<TechFingerprintResult> {
    let url = req.url.clone();

    // Fetch HTTP response to get headers
    let http_req = crate::api::HttpCheckRequest {
        url: url.clone(),
        follow_redirects: true,
        timeout_secs: req.timeout_secs,
    };

    let http_result = match crate::api::check_http(&http_req).await {
        Ok(result) => result,
        Err(e) => {
            return Ok(TechFingerprintResult {
                url,
                technologies: vec![],
                error: Some(format!("HTTP check failed: {}", e)),
            });
        }
    };

    let mut technologies = Vec::new();

    // Parse Server header
    if let Some(server_val) = http_result.headers.get("server") {
        let server_lower = server_val.to_lowercase();

        // Detect web servers
        if server_lower.contains("nginx") {
            if let Some(version) = extract_version(&server_val, "nginx") {
                technologies.push(TechHit {
                    technology: "nginx".to_string(),
                    version: Some(version),
                    category: "web_server".to_string(),
                    source: "Server".to_string(),
                });
            } else {
                technologies.push(TechHit {
                    technology: "nginx".to_string(),
                    version: None,
                    category: "web_server".to_string(),
                    source: "Server".to_string(),
                });
            }
        } else if server_lower.contains("apache") {
            if let Some(version) = extract_version(&server_val, "Apache") {
                technologies.push(TechHit {
                    technology: "Apache".to_string(),
                    version: Some(version),
                    category: "web_server".to_string(),
                    source: "Server".to_string(),
                });
            }
        } else if server_lower.contains("microsoft-iis") {
            if let Some(version) = extract_version(&server_val, "IIS") {
                technologies.push(TechHit {
                    technology: "IIS".to_string(),
                    version: Some(version),
                    category: "web_server".to_string(),
                    source: "Server".to_string(),
                });
            }
        } else if server_lower.contains("caddy") {
            technologies.push(TechHit {
                technology: "Caddy".to_string(),
                version: extract_version(&server_val, "Caddy"),
                category: "web_server".to_string(),
                source: "Server".to_string(),
            });
        }
    }

    // Parse X-Powered-By header
    if let Some(powered_by) = http_result.headers.get("x-powered-by") {
        let pb_lower = powered_by.to_lowercase();
        if pb_lower.contains("php") {
            technologies.push(TechHit {
                technology: "PHP".to_string(),
                version: extract_version(powered_by, "PHP"),
                category: "language".to_string(),
                source: "X-Powered-By".to_string(),
            });
        } else if pb_lower.contains("asp.net") {
            technologies.push(TechHit {
                technology: "ASP.NET".to_string(),
                version: extract_version(powered_by, "ASP.NET"),
                category: "framework".to_string(),
                source: "X-Powered-By".to_string(),
            });
        } else if pb_lower.contains("express") {
            technologies.push(TechHit {
                technology: "Express".to_string(),
                version: extract_version(powered_by, "Express"),
                category: "framework".to_string(),
                source: "X-Powered-By".to_string(),
            });
        }
    }

    // Parse X-Generator header
    if let Some(generator) = http_result.headers.get("x-generator") {
        let gen_lower = generator.to_lowercase();
        if gen_lower.contains("wordpress") {
            technologies.push(TechHit {
                technology: "WordPress".to_string(),
                version: extract_version(generator, "WordPress"),
                category: "cms".to_string(),
                source: "X-Generator".to_string(),
            });
        } else if gen_lower.contains("drupal") {
            technologies.push(TechHit {
                technology: "Drupal".to_string(),
                version: extract_version(generator, "Drupal"),
                category: "cms".to_string(),
                source: "X-Generator".to_string(),
            });
        }
    }

    // CMS signals
    if http_result.headers.contains_key("x-drupal-cache") {
        technologies.push(TechHit {
            technology: "Drupal".to_string(),
            version: None,
            category: "cms".to_string(),
            source: "X-Drupal-Cache".to_string(),
        });
    }

    if let Some(_shopify) = http_result.headers.iter().find(|(k, _)| k.to_lowercase().starts_with("x-shopify")) {
        technologies.push(TechHit {
            technology: "Shopify".to_string(),
            version: None,
            category: "cms".to_string(),
            source: "X-Shopify-*".to_string(),
        });
    }

    if http_result.headers.contains_key("x-wp-total-api-calls") {
        technologies.push(TechHit {
            technology: "WordPress".to_string(),
            version: None,
            category: "cms".to_string(),
            source: "X-WP-*".to_string(),
        });
    }

    // Cache headers
    if let Some(via) = http_result.headers.get("via") {
        let via_lower = via.to_lowercase();
        if via_lower.contains("varnish") {
            technologies.push(TechHit {
                technology: "Varnish".to_string(),
                version: extract_version(via, "Varnish"),
                category: "cache".to_string(),
                source: "Via".to_string(),
            });
        } else if via_lower.contains("squid") {
            technologies.push(TechHit {
                technology: "Squid".to_string(),
                version: extract_version(via, "Squid"),
                category: "cache".to_string(),
                source: "Via".to_string(),
            });
        }
    }

    Ok(TechFingerprintResult {
        url,
        technologies,
        error: None,
    })
}

/// Extract version from a string like "nginx/1.24.0" or "PHP/8.2.0"
fn extract_version(input: &str, prefix: &str) -> Option<String> {
    let lower_input = input.to_lowercase();
    let lower_prefix = prefix.to_lowercase();
    let pos = lower_input.find(&lower_prefix)?;
    // Use lower_input consistently to avoid cross-string byte-index mismatch
    // (to_lowercase() can change byte length, e.g. Turkish İ or German ß)
    let after_match = lower_input.get(pos + lower_prefix.len()..)?;
    // Look for version after "/" or " "
    if after_match.starts_with('/') || after_match.starts_with(' ') {
        let version = after_match[1..].split_whitespace().next().unwrap_or("");
        if !version.is_empty() {
            return Some(version.to_string());
        }
    }
    None
}
