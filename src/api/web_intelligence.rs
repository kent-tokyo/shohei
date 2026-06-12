//! Web Application Intelligence — robots.txt, .well-known discovery, OAuth/OIDC, cert pinning, API exposure.

use serde::{Deserialize, Serialize};
use crate::error::Result;

fn default_timeout() -> u64 { 10 }

// ── robots.txt ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotsTxtRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotsTxtResult {
    pub domain: String,
    pub found: bool,
    pub disallowed_paths: Vec<String>,
    pub sensitive_paths: Vec<String>,
    pub crawl_delay: Option<u32>,
    pub sitemap_urls: Vec<String>,
    pub risk_level: String,
    pub findings: Vec<String>,
}

pub async fn check_robots_txt(req: &RobotsTxtRequest) -> Result<RobotsTxtResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .user_agent("shohei-security-scanner/2.4")
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let url = format!("https://{}/robots.txt", req.domain);
    let body = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => {
            return Ok(RobotsTxtResult {
                domain: req.domain.clone(),
                found: false,
                disallowed_paths: vec![],
                sensitive_paths: vec![],
                crawl_delay: None,
                sitemap_urls: vec![],
                risk_level: "info".to_string(),
                findings: vec!["No robots.txt found".to_string()],
            });
        }
    };

    let sensitive_patterns = [
        "/admin", "/wp-admin", "/phpmyadmin", "/backup", "/config",
        "/.git", "/.env", "/api/", "/dashboard", "/internal", "/private",
        "/secret", "/credentials", "/passwd", "/shadow", "/db",
    ];

    let mut disallowed_paths = Vec::new();
    let mut sensitive_paths = Vec::new();
    let mut sitemap_urls = Vec::new();
    let mut crawl_delay: Option<u32> = None;
    let mut findings = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if let Some(path) = line.strip_prefix("Disallow:") {
            let path = path.trim().to_string();
            if !path.is_empty() {
                let path_lower = path.to_lowercase();
                disallowed_paths.push(path.clone());
                for pattern in &sensitive_patterns {
                    if path_lower.contains(pattern) {
                        sensitive_paths.push(path.clone());
                        findings.push(format!("Sensitive path disclosed in robots.txt: {}", path));
                        break;
                    }
                }
            }
        } else if let Some(url) = line.strip_prefix("Sitemap:") {
            sitemap_urls.push(url.trim().to_string());
        } else if let Some(delay) = line.strip_prefix("Crawl-delay:") {
            crawl_delay = delay.trim().parse().ok();
        }
    }

    let risk_level = if !sensitive_paths.is_empty() { "medium" } else { "low" }.to_string();

    Ok(RobotsTxtResult {
        domain: req.domain.clone(),
        found: true,
        disallowed_paths,
        sensitive_paths,
        crawl_delay,
        sitemap_urls,
        risk_level,
        findings,
    })
}

// ── .well-known discovery ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WellKnownRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WellKnownEndpoint {
    pub path: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WellKnownResult {
    pub domain: String,
    pub endpoints: Vec<WellKnownEndpoint>,
    pub found_count: usize,
}

pub async fn check_well_known(req: &WellKnownRequest) -> Result<WellKnownResult> {
    let client = std::sync::Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?,
    );

    let candidates: &[(&str, &str)] = &[
        ("/.well-known/openid-configuration", "OAuth 2.0 / OIDC discovery"),
        ("/.well-known/security.txt", "Security contact (RFC 9116)"),
        ("/.well-known/change-password", "Password change URL"),
        ("/.well-known/dnt-policy.txt", "Do Not Track policy"),
        ("/.well-known/assetlinks.json", "Android App Links"),
        ("/.well-known/apple-app-site-association", "iOS Universal Links"),
        ("/.well-known/webfinger", "WebFinger identity discovery"),
        ("/.well-known/mta-sts.txt", "MTA-STS policy"),
        ("/.well-known/sbom", "Software Bill of Materials"),
        ("/.well-known/ai-plugin.json", "OpenAI plugin manifest"),
        ("/.well-known/jwks.json", "JSON Web Key Set"),
        ("/.well-known/oauth-authorization-server", "OAuth Authorization Server metadata"),
        ("/.well-known/nodeinfo", "Fediverse node info"),
        ("/.well-known/matrix/server", "Matrix server discovery"),
    ];

    let domain = req.domain.clone();
    let mut handles = Vec::new();
    for &(path, desc) in candidates {
        let url = format!("https://{}{}", domain, path);
        let client = client.clone();
        let path = path.to_string();
        let desc = desc.to_string();
        handles.push(tokio::spawn(async move {
            if let Ok(r) = client.get(&url).send().await {
                let status = r.status().as_u16();
                if status < 400 {
                    let content_type = r.headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());
                    return Some(WellKnownEndpoint { path, status, content_type, description: desc });
                }
            }
            None
        }));
    }

    let mut endpoints = Vec::new();
    for h in handles {
        if let Ok(Some(ep)) = h.await {
            endpoints.push(ep);
        }
    }
    let found_count = endpoints.len();
    Ok(WellKnownResult { domain: req.domain.clone(), endpoints, found_count })
}

// ── OAuth/OIDC security audit ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthOidcRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthOidcResult {
    pub domain: String,
    pub oidc_found: bool,
    pub issuer: Option<String>,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub pkce_supported: bool,
    pub implicit_flow_enabled: bool,
    pub device_flow_enabled: bool,
    pub security_issues: Vec<String>,
    pub risk_level: String,
}

pub async fn check_oauth_oidc(req: &OauthOidcRequest) -> Result<OauthOidcResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let url = format!("https://{}/.well-known/openid-configuration", req.domain);

    let response = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => {
            return Ok(OauthOidcResult {
                domain: req.domain.clone(),
                oidc_found: false,
                issuer: None,
                grant_types_supported: vec![],
                response_types_supported: vec![],
                pkce_supported: false,
                implicit_flow_enabled: false,
                device_flow_enabled: false,
                security_issues: vec![],
                risk_level: "info".to_string(),
            });
        }
    };

    let json: serde_json::Value = match response.json().await {
        Ok(j) => j,
        Err(_) => {
            return Ok(OauthOidcResult {
                domain: req.domain.clone(),
                oidc_found: true,
                issuer: None,
                grant_types_supported: vec![],
                response_types_supported: vec![],
                pkce_supported: false,
                implicit_flow_enabled: false,
                device_flow_enabled: false,
                security_issues: vec!["OIDC endpoint returned invalid JSON".to_string()],
                risk_level: "medium".to_string(),
            });
        }
    };

    let issuer = json.get("issuer").and_then(|v| v.as_str()).map(|s| s.to_string());

    let grant_types: Vec<String> = json.get("grant_types_supported")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let response_types: Vec<String> = json.get("response_types_supported")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let pkce_methods: Vec<String> = json.get("code_challenge_methods_supported")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let pkce_supported = !pkce_methods.is_empty();
    let implicit_flow_enabled = grant_types.iter().any(|g| g == "implicit")
        || response_types.iter().any(|r| r == "token" || r == "id_token token");
    let device_flow_enabled = grant_types.iter().any(|g| g.contains("device"));

    let mut security_issues = Vec::new();

    if implicit_flow_enabled {
        security_issues.push("Implicit flow enabled (deprecated — tokens exposed in URL fragment)".to_string());
    }
    if !pkce_supported && !grant_types.is_empty() {
        security_issues.push("PKCE not advertised — authorization code interception may be possible".to_string());
    }
    if let Some(auth_methods) = json.get("token_endpoint_auth_methods_supported").and_then(|v| v.as_array()) {
        if auth_methods.iter().any(|m| m.as_str() == Some("none")) {
            security_issues.push("Token endpoint supports 'none' auth — ensure PKCE is enforced".to_string());
        }
    }

    let risk_level = if security_issues.is_empty() { "low" }
        else if security_issues.len() == 1 { "medium" }
        else { "high" }.to_string();

    Ok(OauthOidcResult {
        domain: req.domain.clone(),
        oidc_found: true,
        issuer,
        grant_types_supported: grant_types,
        response_types_supported: response_types,
        pkce_supported,
        implicit_flow_enabled,
        device_flow_enabled,
        security_issues,
        risk_level,
    })
}

// ── Certificate Pinning audit ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertPinningRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertPinningResult {
    pub domain: String,
    pub expect_ct_present: bool,
    pub expect_ct_enforce: bool,
    pub expect_ct_max_age: Option<u64>,
    pub hpkp_present: bool,
    pub caa_has_iodef: bool,
    pub findings: Vec<String>,
    pub risk_level: String,
}

pub async fn check_cert_pinning(req: &CertPinningRequest) -> Result<CertPinningResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let url = format!("https://{}", req.domain);
    let mut expect_ct_present = false;
    let mut expect_ct_enforce = false;
    let mut expect_ct_max_age: Option<u64> = None;
    let mut hpkp_present = false;
    let mut findings = Vec::new();

    if let Ok(r) = client.head(&url).send().await {
        let headers = r.headers();
        if let Some(ect) = headers.get("expect-ct") {
            expect_ct_present = true;
            let ect_str = ect.to_str().unwrap_or("");
            if ect_str.contains("enforce") {
                expect_ct_enforce = true;
                findings.push(format!("Expect-CT enforce mode active: {}", ect_str));
            } else {
                findings.push("Expect-CT present but not enforced (report-only mode)".to_string());
            }
            if let Some(age_part) = ect_str.split(',').find(|p| p.trim().starts_with("max-age=")) {
                expect_ct_max_age = age_part.trim().trim_start_matches("max-age=").parse().ok();
            }
        }
        if headers.get("public-key-pins").is_some() || headers.get("public-key-pins-report-only").is_some() {
            hpkp_present = true;
            findings.push("HPKP (Public-Key-Pins) header found — deprecated since 2018, risk of lock-out".to_string());
        }
    }

    if !expect_ct_present {
        findings.push("Expect-CT header absent — Certificate Transparency enforcement not configured".to_string());
    }

    // Check CAA iodef tag via DNS
    let dns_req = crate::api::DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["CAA".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };
    let mut caa_has_iodef = false;
    if let Ok(results) = crate::api::check_dns(&dns_req).await {
        for result in results {
            for record in &result.answers {
                if let crate::api::RecordData::Caa { tag, .. } = &record.data {
                    if tag == "iodef" {
                        caa_has_iodef = true;
                    }
                }
            }
        }
    }

    let risk_level = if hpkp_present { "medium" }
        else if !expect_ct_present { "low" }
        else { "info" }.to_string();

    Ok(CertPinningResult {
        domain: req.domain.clone(),
        expect_ct_present,
        expect_ct_enforce,
        expect_ct_max_age,
        hpkp_present,
        caa_has_iodef,
        findings,
        risk_level,
    })
}

// ── API Exposure ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiExposureRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedEndpoint {
    pub path: String,
    pub status: u16,
    pub risk: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiExposureResult {
    pub domain: String,
    pub exposed_endpoints: Vec<ExposedEndpoint>,
    pub version_headers: Vec<String>,
    pub debug_headers: Vec<String>,
    pub rate_limit_present: bool,
    pub risk_level: String,
    pub findings: Vec<String>,
}

pub async fn check_api_exposure(req: &ApiExposureRequest) -> Result<ApiExposureResult> {
    let client = std::sync::Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?,
    );

    let debug_paths: &[(&str, &str)] = &[
        ("/actuator", "Spring Boot Actuator — env/health/beans exposure"),
        ("/actuator/env", "Spring Boot environment variables"),
        ("/actuator/beans", "Spring Boot bean definitions"),
        ("/_ah/admin", "Google App Engine admin console"),
        ("/debug", "Generic debug endpoint"),
        ("/metrics", "Prometheus/Micrometer metrics"),
        ("/swagger-ui.html", "Swagger UI — API schema"),
        ("/swagger-ui/", "Swagger UI — API schema"),
        ("/api-docs", "OpenAPI documentation"),
        ("/v1/api-docs", "OpenAPI v1 documentation"),
        ("/graphql", "GraphQL endpoint"),
        ("/console", "Admin console"),
        ("/phpinfo.php", "PHP configuration disclosure"),
        ("/server-status", "Apache server status"),
        ("/server-info", "Apache server info"),
        ("/.well-known/jwks.json", "JSON Web Key Set (public, informational)"),
    ];

    let domain = req.domain.clone();
    let mut handles = Vec::new();
    for &(path, desc) in debug_paths {
        let url = format!("https://{}{}", domain, path);
        let client = client.clone();
        let path = path.to_string();
        let desc = desc.to_string();
        handles.push(tokio::spawn(async move {
            if let Ok(r) = client.get(&url).send().await {
                let status = r.status().as_u16();
                if status < 404 {
                    let risk = if status == 200 { "high" } else { "medium" }.to_string();
                    return Some(ExposedEndpoint { path, status, risk, description: desc });
                }
            }
            None
        }));
    }

    let mut exposed_endpoints = Vec::new();
    for h in handles {
        if let Ok(Some(ep)) = h.await {
            exposed_endpoints.push(ep);
        }
    }

    let mut version_headers = Vec::new();
    let mut debug_headers = Vec::new();
    let mut rate_limit_present = false;
    let mut findings = Vec::new();

    if let Ok(r) = client.head(&format!("https://{}", req.domain)).send().await {
        for (name, value) in r.headers().iter() {
            let n = name.as_str().to_lowercase();
            let v = value.to_str().unwrap_or("").to_string();
            if matches!(n.as_str(), "x-powered-by" | "x-aspnet-version" | "x-generator" | "server") {
                version_headers.push(format!("{}: {}", n, v));
            }
            if n.contains("debug") || n.contains("x-request-id") || n.contains("x-trace") {
                debug_headers.push(format!("{}: {}", n, v));
            }
            if n.starts_with("x-ratelimit") || n == "retry-after" {
                rate_limit_present = true;
            }
        }
    }

    for h in &version_headers {
        findings.push(format!("Version/technology disclosure header: {}", h));
    }
    for ep in &exposed_endpoints {
        if ep.status == 200 {
            findings.push(format!("Exposed endpoint (HTTP {}): {} — {}", ep.status, ep.path, ep.description));
        }
    }
    if !rate_limit_present {
        findings.push("No rate limiting headers detected".to_string());
    }

    let risk_level = if exposed_endpoints.iter().any(|e| e.status == 200) { "high" }
        else if !version_headers.is_empty() || !exposed_endpoints.is_empty() { "medium" }
        else { "low" }.to_string();

    Ok(ApiExposureResult {
        domain: req.domain.clone(),
        exposed_endpoints,
        version_headers,
        debug_headers,
        rate_limit_present,
        risk_level,
        findings,
    })
}
