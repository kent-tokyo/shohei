//! Subdomain health checker — test common subdomains for DNS/HTTP/TLS.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest};
use futures_util::future::join_all;

/// Check common subdomains for DNS/HTTP/TLS validity.
pub async fn check_common_subdomains(req: &SubdomainCheckRequest) -> Result<SubdomainCheckResult> {
    const MAX_TOTAL_SUBDOMAINS: usize = 100;

    let mut subdomains = vec![
        "www", "mail", "ftp", "api", "cdn", "staging", "dev", "admin",
        "vpn", "test", "beta", "app", "mobile", "auth", "secure",
    ];

    // Merge extra subdomains if provided, enforcing limit to prevent resource exhaustion
    if let Some(extra) = &req.extra_subdomains {
        let remaining_capacity = MAX_TOTAL_SUBDOMAINS.saturating_sub(subdomains.len());
        let to_add = std::cmp::min(extra.len(), remaining_capacity);
        for extra_sub in extra.iter().take(to_add) {
            subdomains.push(extra_sub.as_str());
        }
    }

    // Parallel DNS resolution for all subdomains
    let tasks: Vec<_> = subdomains
        .iter()
        .map(|sub| {
            let domain = req.domain.clone();
            let timeout = req.timeout_secs;
            async move {
                let full_domain = format!("{}.{}", sub, domain);
                check_subdomain(&full_domain, timeout).await
            }
        })
        .collect();

    let results = join_all(tasks).await;

    Ok(SubdomainCheckResult {
        domain: req.domain.clone(),
        subdomains: results,
    })
}

async fn check_subdomain(subdomain: &str, timeout_secs: u64) -> SubdomainStatus {
    // Step 1: DNS resolution
    let dns_req = DnsCheckRequest {
        domain: subdomain.to_string(),
        record_types: vec!["A".to_string()],
        timeout_secs,
        ..Default::default()
    };

    let dns_resolves = match check_dns(&dns_req).await {
        Ok(results) => !results.is_empty() && !results[0].answers.is_empty(),
        Err(_) => false,
    };

    // Step 2: HTTP status check (if DNS resolves)
    let http_status = if dns_resolves {
        match check_http_status(subdomain, timeout_secs).await {
            Some(status) => Some(status),
            None => None,
        }
    } else {
        None
    };

    // Step 3: TLS validity (if DNS resolves)
    let tls_valid = if dns_resolves && http_status.is_some() {
        if let Some(status) = &http_status {
            if status >= &200 && status < &400 {
                match crate::api::check_tls_chain(&crate::api::TlsCheckRequest {
                    hostname: subdomain.to_string(),
                    port: 443,
                    check_dane: false,
                    timeout_secs,
                })
                .await
                {
                    Ok(result) => Some(result.valid),
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    SubdomainStatus {
        subdomain: subdomain.to_string(),
        dns_resolves,
        http_status,
        tls_valid,
    }
}

async fn check_http_status(hostname: &str, timeout_secs: u64) -> Option<u16> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    match client
        .get(format!("https://{}", hostname))
        .send()
        .await
    {
        Ok(response) => Some(response.status().as_u16()),
        Err(_) => {
            // Try HTTP as fallback
            match client
                .get(format!("http://{}", hostname))
                .send()
                .await
            {
                Ok(response) => Some(response.status().as_u16()),
                Err(_) => None,
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainCheckRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub extra_subdomains: Option<Vec<String>>,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainCheckResult {
    pub domain: String,
    pub subdomains: Vec<SubdomainStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainStatus {
    pub subdomain: String,
    pub dns_resolves: bool,
    #[serde(default)]
    pub http_status: Option<u16>,
    #[serde(default)]
    pub tls_valid: Option<bool>,
}
