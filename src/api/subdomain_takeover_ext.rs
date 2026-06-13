//! Subdomain Takeover Detection, RIPE Stat Passive DNS, Azure AD Exposure.

use serde::{Deserialize, Serialize};
use crate::error::Result;

fn default_timeout() -> u64 { 10 }

// ── Subdomain Takeover ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainTakeoverRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverFinding {
    pub subdomain: String,
    pub cname: String,
    pub service: String,
    pub confidence: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainTakeoverResult {
    pub domain: String,
    pub vulnerable: Vec<TakeoverFinding>,
    pub potential: Vec<TakeoverFinding>,
    pub checked_subdomains: usize,
    pub risk_level: String,
}

struct Sig {
    service: &'static str,
    /// CNAME patterns — if CNAME contains any of these the service matches
    patterns: &'static [&'static str],
    /// HTTP body fingerprint indicating unclaimed service
    fingerprint: &'static str,
}

const SIGS: &[Sig] = &[
    Sig { service: "GitHub Pages",    patterns: &["github.io", "github.com"],                    fingerprint: "There isn't a GitHub Pages site here" },
    Sig { service: "Heroku",          patterns: &["herokuapp.com", "herokussl.com"],              fingerprint: "No such app" },
    Sig { service: "Fastly",          patterns: &["fastly.net"],                                  fingerprint: "Fastly error: unknown domain" },
    Sig { service: "Shopify",         patterns: &["myshopify.com"],                               fingerprint: "Sorry, this shop is currently unavailable" },
    Sig { service: "Tumblr",          patterns: &["tumblr.com"],                                  fingerprint: "Whatever you were looking for doesn't currently exist" },
    Sig { service: "SendGrid",        patterns: &["sendgrid.net"],                                fingerprint: "The provided CNAME does not match" },
    Sig { service: "Mailgun",         patterns: &["mailgun.org", "email.mailgun.org"],            fingerprint: "mailgun" },
    Sig { service: "AWS EB",          patterns: &["elasticbeanstalk.com"],                        fingerprint: "NXDOMAIN" },
    Sig { service: "Azure Web Apps",  patterns: &["azurewebsites.net", "trafficmanager.net"],     fingerprint: "404 Web Site not found" },
    Sig { service: "Azure Blob",      patterns: &["blob.core.windows.net"],                       fingerprint: "The specified container does not exist" },
    Sig { service: "Azure CDN",       patterns: &["azureedge.net"],                               fingerprint: "CDN endpoint not found" },
    Sig { service: "Netlify",         patterns: &["netlify.app", "netlify.com"],                  fingerprint: "Not Found" },
    Sig { service: "Vercel",          patterns: &["vercel.app", "now.sh"],                        fingerprint: "The deployment could not be found" },
    Sig { service: "LaunchDarkly",    patterns: &["launchdarkly.com"],                            fingerprint: "ld-404" },
    Sig { service: "HubSpot",         patterns: &["hubspot.net", "hs-sites.com"],                 fingerprint: "Domain not found" },
    Sig { service: "Zendesk",         patterns: &["zendesk.com"],                                 fingerprint: "Help Center Closed" },
    Sig { service: "Surge.sh",        patterns: &["surge.sh"],                                    fingerprint: "project not found" },
    Sig { service: "Ghost",           patterns: &["ghost.io"],                                    fingerprint: "The thing you were looking for is no longer here" },
    Sig { service: "Pantheon",        patterns: &["pantheonsite.io"],                             fingerprint: "The gods are wise" },
    Sig { service: "Wix",             patterns: &["wix.com", "wixsite.com"],                      fingerprint: "Error ConnectYourDomain" },
    Sig { service: "WordPress.com",   patterns: &["wordpress.com"],                               fingerprint: "Do you want to register" },
    Sig { service: "Squarespace",     patterns: &["squarespace.com"],                             fingerprint: "No Such Account" },
    Sig { service: "Webflow",         patterns: &["webflow.io"],                                  fingerprint: "page doesn't exist" },
    Sig { service: "Cargo Collective",patterns: &["cargocollective.com"],                         fingerprint: "If you're moving your domain away" },
    Sig { service: "UserVoice",       patterns: &["uservoice.com"],                               fingerprint: "This UserVoice subdomain is currently available" },
    Sig { service: "Readme.io",       patterns: &["readme.io"],                                   fingerprint: "Project doesnt exist" },
    Sig { service: "Pingdom",         patterns: &["pingdom.net"],                                  fingerprint: "This public status page does not exist" },
    Sig { service: "AWS S3",          patterns: &[".s3.amazonaws.com", ".s3-website"],            fingerprint: "NoSuchBucket" },
    Sig { service: "AWS CloudFront",  patterns: &["cloudfront.net"],                              fingerprint: "ERROR: The request could not be satisfied" },
    Sig { service: "GCS",             patterns: &["storage.googleapis.com"],                      fingerprint: "NoSuchBucket" },
];

pub async fn check_subdomain_takeover(req: &SubdomainTakeoverRequest) -> Result<SubdomainTakeoverResult> {
    let client = std::sync::Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?,
    );

    let prefixes = [
        "www", "mail", "email", "blog", "shop", "store", "app", "api",
        "dev", "staging", "beta", "old", "legacy", "cdn", "static",
        "assets", "media", "help", "support", "docs", "status", "admin",
    ];

    let mut handles = Vec::new();
    for &prefix in &prefixes {
        let subdomain = format!("{}.{}", prefix, req.domain);
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            // DNS CNAME lookup
            let dns_req = crate::api::DnsCheckRequest {
                domain: subdomain.clone(),
                record_types: vec!["CNAME".to_string()],
                timeout_secs: 5,
                ..Default::default()
            };

            let cname = match crate::api::check_dns(&dns_req).await {
                Ok(results) => results.into_iter().flat_map(|r| r.answers).find_map(|rec| {
                    if let crate::api::RecordData::Cname(c) = rec.data { Some(c) } else { None }
                }),
                Err(_) => None,
            };

            let Some(cname_target) = cname else { return None; };
            let cname_lower = cname_target.to_lowercase();

            for sig in SIGS {
                if sig.patterns.iter().any(|p| cname_lower.contains(p)) {
                    // Fetch body and check for the service-specific fingerprint string
                    let url = format!("http://{}", subdomain);
                    if crate::api::helpers::validate_url_safety(&url).is_err() {
                        return None;
                    }
                    let fingerprint_found = async {
                        let resp = client.get(&url).send().await.ok()?;
                        let status = resp.status().as_u16();
                        if status < 400 { return None; }
                        let body = resp.text().await.ok()?;
                        if body.contains(sig.fingerprint) { Some(()) } else { None }
                    }.await;

                    let confidence = if fingerprint_found.is_some() { "high" } else { "medium" }.to_string();
                    return Some((subdomain, cname_target, sig.service.to_string(), sig.fingerprint.to_string(), confidence));
                }
            }
            None
        }));
    }

    let mut vulnerable = Vec::new();
    let mut potential = Vec::new();
    let checked = prefixes.len();

    for h in handles {
        if let Ok(Some((sub, cname, service, fingerprint, confidence))) = h.await {
            let finding = TakeoverFinding { subdomain: sub, cname, service, confidence: confidence.clone(), fingerprint };
            if confidence == "high" { vulnerable.push(finding); } else { potential.push(finding); }
        }
    }

    let risk_level = if !vulnerable.is_empty() { "critical" }
        else if !potential.is_empty() { "high" }
        else { "low" }.to_string();

    Ok(SubdomainTakeoverResult {
        domain: req.domain.clone(),
        vulnerable,
        potential,
        checked_subdomains: checked,
        risk_level,
    })
}

// ── Passive DNS via RIPE Stat ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveDnsRequest {
    pub query: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveDnsRecord {
    pub rtype: String,
    pub rrname: String,
    pub rdata: Vec<String>,
    pub time_first: Option<String>,
    pub time_last: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveDnsResult {
    pub query: String,
    pub records: Vec<PassiveDnsRecord>,
    pub record_count: usize,
    pub source: String,
}

pub async fn check_passive_dns(req: &PassiveDnsRequest) -> Result<PassiveDnsResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .user_agent("shohei-security-scanner/2.4")
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    // RIPE Stat DNS History API (free, no API key)
    let url = format!(
        "https://stat.ripe.net/data/dns-history/data.json?resource={}&sourceapp=shohei-mcp",
        crate::api::helpers::percent_encode(&req.query)
    );

    let response = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => {
            return Ok(PassiveDnsResult {
                query: req.query.clone(),
                records: vec![],
                record_count: 0,
                source: "RIPE Stat PDNS (unavailable)".to_string(),
            });
        }
    };

    let json: serde_json::Value = response.json().await.unwrap_or_default();

    let records: Vec<PassiveDnsRecord> = json
        .get("data")
        .and_then(|d| d.get("entries"))
        .and_then(|e| e.as_array())
        .map(|entries| {
            entries.iter().filter_map(|entry| {
                let rtype = entry.get("type").or_else(|| entry.get("rtype"))
                    .and_then(|v| v.as_str())?.to_string();
                let rrname = entry.get("domain").or_else(|| entry.get("rrname"))
                    .and_then(|v| v.as_str())?.to_string();
                let rdata = entry.get("response").or_else(|| entry.get("rdata"))
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                    .unwrap_or_default();
                let time_first = entry.get("first_seen").and_then(|v| v.as_str()).map(|s| s.to_string());
                let time_last = entry.get("last_seen").and_then(|v| v.as_str()).map(|s| s.to_string());
                Some(PassiveDnsRecord { rtype, rrname, rdata, time_first, time_last })
            }).collect()
        })
        .unwrap_or_default();

    let record_count = records.len();
    Ok(PassiveDnsResult {
        query: req.query.clone(),
        records,
        record_count,
        source: "RIPE Stat PDNS".to_string(),
    })
}

// ── Azure AD Exposure ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureAdExposureRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureAdExposureResult {
    pub domain: String,
    pub tenant_found: bool,
    pub tenant_id: Option<String>,
    pub issuer: Option<String>,
    pub federation_type: Option<String>,
    pub oidc_metadata_accessible: bool,
    pub risk_level: String,
    pub findings: Vec<String>,
}

pub async fn check_azure_ad_exposure(req: &AzureAdExposureRequest) -> Result<AzureAdExposureResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let mut findings = Vec::new();
    let mut tenant_id: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut oidc_metadata_accessible = false;

    // Azure AD OIDC discovery for a specific domain (tenant)
    let openid_url = format!(
        "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
        crate::api::helpers::percent_encode(&req.domain)
    );

    let tenant_found = if let Ok(r) = client.get(&openid_url).send().await {
        if r.status().is_success() {
            oidc_metadata_accessible = true;
            if let Ok(json) = r.json::<serde_json::Value>().await {
                // Extract tenant ID from token_endpoint URL
                tenant_id = json.get("token_endpoint")
                    .and_then(|v| v.as_str())
                    .and_then(|ep| ep.split('/').nth(3))
                    .map(|s| s.to_string());
                issuer = json.get("issuer").and_then(|v| v.as_str()).map(|s| s.to_string());
                findings.push("Azure AD tenant OIDC metadata is publicly accessible".to_string());
            }
            true
        } else {
            false
        }
    } else {
        false
    };

    // Federation check via userealm API (public endpoint)
    let realm_url = format!(
        "https://login.microsoftonline.com/common/userrealm/?user=probe@{}&api-version=2.1&checkForMicrosoftAccount=false",
        crate::api::helpers::percent_encode(&req.domain)
    );
    let mut federation_type: Option<String> = None;
    if let Ok(r) = client.get(&realm_url).send().await {
        if r.status().is_success() {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                let ns = json.get("NameSpaceType").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if ns == "Federated" {
                    federation_type = Some("Federated (ADFS)".to_string());
                    findings.push("Azure AD federation (ADFS) configured for this domain".to_string());
                } else if ns == "Managed" {
                    federation_type = Some("Managed".to_string());
                    findings.push("Azure AD managed authentication (no ADFS) for this domain".to_string());
                }
            }
        }
    }

    let risk_level = if tenant_found { "info" } else { "none" }.to_string();

    Ok(AzureAdExposureResult {
        domain: req.domain.clone(),
        tenant_found,
        tenant_id,
        issuer,
        federation_type,
        oidc_metadata_accessible,
        risk_level,
        findings,
    })
}
