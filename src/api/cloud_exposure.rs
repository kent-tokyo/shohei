//! Cloud & Infrastructure Exposure — S3 bucket detection, cloud provider identification, server hardening.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// S3 bucket exposure check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3BucketExposureRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// S3 bucket exposure result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3BucketExposureResult {
    pub domain: String,
    pub has_s3_cname: bool,
    pub bucket_name: Option<String>,
    pub publicly_accessible: bool,
    pub risk_level: String,
    pub error: Option<String>,
}

/// Check if domain maps to AWS S3 bucket.
pub async fn check_s3_bucket_exposure(req: &S3BucketExposureRequest) -> Result<S3BucketExposureResult> {
    let dns_req = crate::api::DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["CNAME".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    match crate::api::check_dns(&dns_req).await {
        Ok(results) => {
            for result in results {
                for record in &result.answers {
                    if let crate::api::RecordData::Cname(cname) = &record.data {
                        if cname.contains("s3") && cname.contains("amazonaws.com") {
                            return Ok(S3BucketExposureResult {
                                domain: req.domain.clone(),
                                has_s3_cname: true,
                                bucket_name: cname.split('.').next().map(|s| s.to_string()),
                                publicly_accessible: true,
                                risk_level: "high".to_string(),
                                error: None,
                            });
                        }
                    }
                }
            }
            Ok(S3BucketExposureResult {
                domain: req.domain.clone(),
                has_s3_cname: false,
                bucket_name: None,
                publicly_accessible: false,
                risk_level: "none".to_string(),
                error: None,
            })
        }
        Err(_) => Ok(S3BucketExposureResult {
            domain: req.domain.clone(),
            has_s3_cname: false,
            bucket_name: None,
            publicly_accessible: false,
            risk_level: "unknown".to_string(),
            error: Some("DNS lookup failed".to_string()),
        }),
    }
}

/// Cloud provider detection request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProviderRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Cloud provider result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProviderResult {
    pub domain: String,
    pub detected_provider: Option<String>,
    pub cname_pattern: Option<String>,
    pub confidence: u8,
    pub is_cdn: bool,
    pub provider_details: Vec<String>,
}

/// Detect cloud provider (AWS/GCP/Azure/Cloudflare).
pub async fn check_cloud_provider(req: &CloudProviderRequest) -> Result<CloudProviderResult> {
    let dns_req = crate::api::DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["CNAME".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    match crate::api::check_dns(&dns_req).await {
        Ok(results) => {
            for result in results {
                for record in &result.answers {
                    if let crate::api::RecordData::Cname(cname) = &record.data {
                        let (provider, confidence, is_cdn) = if cname.contains("amazonaws.com") {
                            ("AWS".to_string(), 95u8, true)
                        } else if cname.contains("azurewebsites.net") || cname.contains("azure.com") {
                            ("Azure".to_string(), 95u8, true)
                        } else if cname.contains("run.app") || cname.contains("appspot.com") {
                            ("Google Cloud".to_string(), 95u8, true)
                        } else if cname.contains("cloudflare.com") || cname.contains("cdn.cloudflare.net") {
                            ("Cloudflare".to_string(), 95u8, true)
                        } else if cname.contains("fastly.net") {
                            ("Fastly".to_string(), 90u8, true)
                        } else if cname.contains("akamai.net") {
                            ("Akamai".to_string(), 85u8, true)
                        } else {
                            ("Unknown".to_string(), 20u8, false)
                        };

                        return Ok(CloudProviderResult {
                            domain: req.domain.clone(),
                            detected_provider: Some(provider),
                            cname_pattern: Some(cname.clone()),
                            confidence,
                            is_cdn,
                            provider_details: vec![format!("CNAME: {}", cname)],
                        });
                    }
                }
            }

            Ok(CloudProviderResult {
                domain: req.domain.clone(),
                detected_provider: None,
                cname_pattern: None,
                confidence: 0,
                is_cdn: false,
                provider_details: vec!["No CDN/cloud provider detected".to_string()],
            })
        }
        Err(_) => Ok(CloudProviderResult {
            domain: req.domain.clone(),
            detected_provider: None,
            cname_pattern: None,
            confidence: 0,
            is_cdn: false,
            provider_details: vec!["DNS lookup failed".to_string()],
        }),
    }
}

/// Server hardening check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHardeningRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Server hardening result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHardeningResult {
    pub url: String,
    pub server_disclosed: bool,
    pub server_header: Option<String>,
    pub has_x_powered_by: bool,
    pub has_security_headers: bool,
    pub directory_listing_enabled: bool,
    pub hardening_score: u8,
    pub recommendations: Vec<String>,
}

/// Check server hardening (CIS-lite benchmark).
pub async fn check_server_hardening(req: &ServerHardeningRequest) -> Result<ServerHardeningResult> {
    crate::api::helpers::validate_url_safety(&req.url).map_err(crate::error::ShoheError::Parse)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    match client.get(&req.url).send().await {
        Ok(response) => {
            let server_header = response
                .headers()
                .get("server")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let server_disclosed = server_header.is_some();

            let has_x_powered_by = response.headers().contains_key("x-powered-by");

            let has_security_headers = response.headers().contains_key("strict-transport-security")
                || response.headers().contains_key("x-frame-options")
                || response.headers().contains_key("content-security-policy");

            let body_text = response.text().await.unwrap_or_default();
            let directory_listing_enabled = body_text.contains("Index of")
                || body_text.contains("directory listing");

            let mut score = 100u8;
            let mut recommendations = Vec::new();

            if server_disclosed {
                score = score.saturating_sub(20);
                recommendations.push("Hide or minimize Server header".to_string());
            }

            if has_x_powered_by {
                score = score.saturating_sub(15);
                recommendations.push("Remove X-Powered-By header".to_string());
            }

            if !has_security_headers {
                score = score.saturating_sub(30);
                recommendations.push("Add HSTS, X-Frame-Options, and CSP headers".to_string());
            }

            if directory_listing_enabled {
                score = score.saturating_sub(25);
                recommendations.push("Disable directory listing".to_string());
            }

            if recommendations.is_empty() {
                recommendations.push("Server hardening appears adequate".to_string());
            }

            Ok(ServerHardeningResult {
                url: req.url.clone(),
                server_disclosed,
                server_header,
                has_x_powered_by,
                has_security_headers,
                directory_listing_enabled,
                hardening_score: score,
                recommendations,
            })
        }
        Err(e) => Ok(ServerHardeningResult {
            url: req.url.clone(),
            server_disclosed: false,
            server_header: None,
            has_x_powered_by: false,
            has_security_headers: false,
            directory_listing_enabled: false,
            hardening_score: 0,
            recommendations: vec![format!("Unable to check: {}", e)],
        }),
    }
}

/// Dangling DNS detection request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DanglingDnsRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Dangling DNS result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DanglingDnsResult {
    pub domain: String,
    pub has_dangling_record: bool,
    pub dangling_cname: Option<String>,
    pub cloud_provider: Option<String>,
    pub risk_level: String,
    pub remediation: Option<String>,
}

/// Detect dangling DNS records pointing to deleted cloud resources.
pub async fn check_dangling_dns(req: &DanglingDnsRequest) -> Result<DanglingDnsResult> {
    let dns_req = crate::api::DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["CNAME".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    match crate::api::check_dns(&dns_req).await {
        Ok(results) => {
            for result in results {
                for record in &result.answers {
                    if let crate::api::RecordData::Cname(cname) = &record.data {
                        let cloud_provider = if cname.contains("s3") && cname.contains("amazonaws.com") {
                            Some("AWS S3".to_string())
                        } else if cname.contains("azurewebsites.net") {
                            Some("Azure".to_string())
                        } else if cname.contains("run.app") {
                            Some("Google Cloud Run".to_string())
                        } else {
                            None
                        };

                        if let Some(provider) = &cloud_provider {
                            return Ok(DanglingDnsResult {
                                domain: req.domain.clone(),
                                has_dangling_record: true,
                                dangling_cname: Some(cname.clone()),
                                cloud_provider: Some(provider.clone()),
                                risk_level: "high".to_string(),
                                remediation: Some(format!(
                                    "Remove CNAME record pointing to {} or provision the cloud resource",
                                    provider
                                )),
                            });
                        }
                    }
                }
            }

            Ok(DanglingDnsResult {
                domain: req.domain.clone(),
                has_dangling_record: false,
                dangling_cname: None,
                cloud_provider: None,
                risk_level: "none".to_string(),
                remediation: None,
            })
        }
        Err(_) => Ok(DanglingDnsResult {
            domain: req.domain.clone(),
            has_dangling_record: false,
            dangling_cname: None,
            cloud_provider: None,
            risk_level: "unknown".to_string(),
            remediation: Some("Unable to check DNS records".to_string()),
        }),
    }
}

fn default_timeout() -> u64 {
    crate::api::helpers::DEFAULT_REQUEST_TIMEOUT_SECS
}
