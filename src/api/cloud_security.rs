//! Cloud Infrastructure Security — IMDS, blob storage, CORS, security.txt scanning.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Cloud metadata exposure check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMetadataExposureRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Cloud metadata exposure result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMetadataExposureResult {
    pub domain: String,
    pub imds_accessible: bool,
    pub cloud_provider: Option<String>,
    pub risk_level: String,
    pub remediation: Option<String>,
}

/// Check if 169.254.169.254 IMDS endpoint is accessible.
pub async fn check_cloud_metadata_exposure(req: &CloudMetadataExposureRequest) -> Result<CloudMetadataExposureResult> {
    // Resolve the target domain's A record and check if it's the IMDS IP (169.254.169.254)
    // or another link-local/private address that should not be publicly reachable.
    // We do NOT directly access 169.254.169.254 — that would query the scanner's own
    // cloud metadata, not the target's, and would be an information leak.
    let dns_req = crate::api::DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["A".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };

    let mut imds_accessible = false;
    let mut cloud_provider: Option<String> = None;

    if let Ok(results) = crate::api::check_dns(&dns_req).await {
        for result in &results {
            for record in &result.answers {
                if let crate::api::RecordData::A(ip_str) = &record.data {
                    // IMDS IP is 169.254.169.254 (AWS) or 169.254.169.254 (GCP/Azure use same IP)
                    if ip_str == "169.254.169.254" {
                        imds_accessible = true;
                        cloud_provider = Some("Cloud IMDS (AWS/GCP/Azure)".to_string());
                    }
                    // Also flag if domain resolves to any link-local (169.254.x.x) address
                    if ip_str.starts_with("169.254.") {
                        imds_accessible = true;
                    }
                }
            }
        }
    }

    let risk_level = if imds_accessible { "critical" } else { "low" }.to_string();

    Ok(CloudMetadataExposureResult {
        domain: req.domain.clone(),
        imds_accessible,
        cloud_provider,
        risk_level,
        remediation: if imds_accessible {
            Some("Domain resolves to IMDS IP (169.254.x.x) — this indicates a critical DNS misconfiguration or SSRF risk".to_string())
        } else {
            None
        },
    })
}

/// Azure Blob Storage exposure check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureBlobExposureRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Azure Blob exposure result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureBlobExposureResult {
    pub domain: String,
    pub has_azure_blob_cname: bool,
    pub blob_account: Option<String>,
    pub publicly_accessible: bool,
    pub risk_level: String,
}

/// Detect Azure Blob Storage CNAME exposure.
pub async fn check_azure_blob_exposure(req: &AzureBlobExposureRequest) -> Result<AzureBlobExposureResult> {
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
                        if cname.contains("blob.core.windows.net") {
                            return Ok(AzureBlobExposureResult {
                                domain: req.domain.clone(),
                                has_azure_blob_cname: true,
                                blob_account: cname.split('.').next().map(|s| s.to_string()),
                                publicly_accessible: true,
                                risk_level: "high".to_string(),
                            });
                        }
                    }
                }
            }
            Ok(AzureBlobExposureResult {
                domain: req.domain.clone(),
                has_azure_blob_cname: false,
                blob_account: None,
                publicly_accessible: false,
                risk_level: "none".to_string(),
            })
        }
        Err(_) => Ok(AzureBlobExposureResult {
            domain: req.domain.clone(),
            has_azure_blob_cname: false,
            blob_account: None,
            publicly_accessible: false,
            risk_level: "unknown".to_string(),
        }),
    }
}

/// GCS bucket exposure check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsBucketExposureRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// GCS bucket exposure result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsBucketExposureResult {
    pub domain: String,
    pub has_gcs_cname: bool,
    pub bucket_name: Option<String>,
    pub publicly_accessible: bool,
    pub risk_level: String,
}

/// Detect Google Cloud Storage CNAME exposure.
pub async fn check_gcs_bucket_exposure(req: &GcsBucketExposureRequest) -> Result<GcsBucketExposureResult> {
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
                        if cname.contains("storage.googleapis.com") {
                            return Ok(GcsBucketExposureResult {
                                domain: req.domain.clone(),
                                has_gcs_cname: true,
                                bucket_name: cname.split('.').next().map(|s| s.to_string()),
                                publicly_accessible: true,
                                risk_level: "high".to_string(),
                            });
                        }
                    }
                }
            }
            Ok(GcsBucketExposureResult {
                domain: req.domain.clone(),
                has_gcs_cname: false,
                bucket_name: None,
                publicly_accessible: false,
                risk_level: "none".to_string(),
            })
        }
        Err(_) => Ok(GcsBucketExposureResult {
            domain: req.domain.clone(),
            has_gcs_cname: false,
            bucket_name: None,
            publicly_accessible: false,
            risk_level: "unknown".to_string(),
        }),
    }
}

/// CORS policy check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsPolicyRequest {
    pub url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// CORS policy result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsPolicyResult {
    pub url: String,
    pub cors_enabled: bool,
    pub allow_origin: Option<String>,
    pub allow_methods: Option<String>,
    pub allow_credentials: bool,
    pub risk_level: String,
    pub issues: Vec<String>,
}

/// Analyze CORS policy from HTTP response headers.
pub async fn check_cors_policy(req: &CorsPolicyRequest) -> Result<CorsPolicyResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    match client.get(&req.url).send().await {
        Ok(response) => {
            let allow_origin = response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let allow_methods = response
                .headers()
                .get("access-control-allow-methods")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let allow_credentials = response
                .headers()
                .get("access-control-allow-credentials")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.contains("true"))
                .unwrap_or(false);

            let cors_enabled = allow_origin.is_some();
            let mut issues = Vec::new();
            let mut risk_level = "low".to_string();

            if let Some(ref origin) = allow_origin {
                if origin == "*" {
                    issues.push("Wildcard origin allows any domain".to_string());
                    risk_level = "medium".to_string();
                    if allow_credentials {
                        issues.push("Wildcard origin + credentials=true is a critical misconfiguration".to_string());
                        risk_level = "critical".to_string();
                    }
                }
            }

            Ok(CorsPolicyResult {
                url: req.url.clone(),
                cors_enabled,
                allow_origin,
                allow_methods,
                allow_credentials,
                risk_level,
                issues,
            })
        }
        Err(_) => Ok(CorsPolicyResult {
            url: req.url.clone(),
            cors_enabled: false,
            allow_origin: None,
            allow_methods: None,
            allow_credentials: false,
            risk_level: "unknown".to_string(),
            issues: vec!["Unable to fetch URL".to_string()],
        }),
    }
}

/// Security.txt check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTxtRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Security.txt result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTxtResult {
    pub domain: String,
    pub file_found: bool,
    pub contact: Option<String>,
    pub policy: Option<String>,
    pub encryption: Option<String>,
    pub expires: Option<String>,
    pub security_score: u8,
}

/// Fetch and parse .well-known/security.txt (RFC 9116).
pub async fn check_security_txt(req: &SecurityTxtRequest) -> Result<SecurityTxtResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let url = format!("https://{}/.well-known/security.txt", req.domain);

    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => {
            match response.text().await {
                Ok(body) => {
                    let mut contact = None;
                    let mut policy = None;
                    let mut encryption = None;
                    let mut expires = None;
                    let mut score = 50u8;

                    for line in body.lines() {
                        if line.starts_with("Contact:") {
                            contact = line.split_once(':').map(|(_, v)| v.trim().to_string());
                            score = score.saturating_add(20);
                        } else if line.starts_with("Policy:") {
                            policy = line.split_once(':').map(|(_, v)| v.trim().to_string());
                            score = score.saturating_add(15);
                        } else if line.starts_with("Encryption:") {
                            encryption = line.split_once(':').map(|(_, v)| v.trim().to_string());
                            score = score.saturating_add(10);
                        } else if line.starts_with("Expires:") {
                            expires = line.split_once(':').map(|(_, v)| v.trim().to_string());
                            score = score.saturating_add(5);
                        }
                    }

                    Ok(SecurityTxtResult {
                        domain: req.domain.clone(),
                        file_found: true,
                        contact,
                        policy,
                        encryption,
                        expires,
                        security_score: std::cmp::min(100, score),
                    })
                }
                Err(_) => Ok(SecurityTxtResult {
                    domain: req.domain.clone(),
                    file_found: true,
                    contact: None,
                    policy: None,
                    encryption: None,
                    expires: None,
                    security_score: 0,
                }),
            }
        }
        _ => Ok(SecurityTxtResult {
            domain: req.domain.clone(),
            file_found: false,
            contact: None,
            policy: None,
            encryption: None,
            expires: None,
            security_score: 0,
        }),
    }
}

fn default_timeout() -> u64 {
    crate::api::helpers::DEFAULT_REQUEST_TIMEOUT_SECS
}
