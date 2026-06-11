//! Supply Chain Security — exposed files, package registry security, SBOM, dependency confusion.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Exposed files check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedFilesRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Exposed files result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedFilesResult {
    pub domain: String,
    pub exposed_files: Vec<String>,
    pub file_count: usize,
    pub risk_level: String,
    pub remediation: Option<String>,
}

/// Probe common sensitive paths for exposure.
pub async fn check_exposed_files(req: &ExposedFilesRequest) -> Result<ExposedFilesResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let sensitive_paths = vec![
        ".env",
        "package.json",
        "requirements.txt",
        ".git/config",
        "Dockerfile",
        "docker-compose.yml",
        "config.php",
        "wp-config.php",
        ".htpasswd",
        ".aws/credentials",
    ];

    let mut exposed_files = Vec::new();

    for path in sensitive_paths {
        let url = format!("https://{}/{}", req.domain, path);
        if let Ok(response) = client.head(&url).send().await {
            if response.status().is_success() {
                exposed_files.push(path.to_string());
            }
        }
    }

    let risk_level = match exposed_files.len() {
        0 => "low".to_string(),
        1..=2 => "medium".to_string(),
        _ => "high".to_string(),
    };

    let file_count = exposed_files.len();

    let remediation = if !exposed_files.is_empty() {
        Some(format!(
            "Remove exposed files: {}",
            exposed_files.join(", ")
        ))
    } else {
        None
    };

    Ok(ExposedFilesResult {
        domain: req.domain.clone(),
        exposed_files,
        file_count,
        risk_level,
        remediation,
    })
}

/// NPM package security check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackageSecurityRequest {
    pub package: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// NPM package security result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackageSecurityResult {
    pub package: String,
    pub found: bool,
    pub version: Option<String>,
    pub maintainers: usize,
    pub download_count: Option<u64>,
    pub risk_indicators: Vec<String>,
}

/// Query npm registry for package metadata and security info.
pub async fn check_npm_package_security(req: &NpmPackageSecurityRequest) -> Result<NpmPackageSecurityResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let url = format!("https://registry.npmjs.org/{}", req.package);

    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => {
            match response.json::<serde_json::Value>().await {
                Ok(data) => {
                    let version = data
                        .get("dist-tags")
                        .and_then(|dt| dt.get("latest"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let maintainers = data
                        .get("maintainers")
                        .and_then(|m| m.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);

                    let mut risk_indicators = Vec::new();

                    if maintainers < 2 {
                        risk_indicators.push("Single maintainer — bus factor risk".to_string());
                    }

                    if req.package.contains("@") && !req.package.starts_with("@") {
                        risk_indicators.push("Package name contains @ — typosquatting indicator".to_string());
                    }

                    Ok(NpmPackageSecurityResult {
                        package: req.package.clone(),
                        found: true,
                        version,
                        maintainers,
                        download_count: None,
                        risk_indicators,
                    })
                }
                Err(_) => Ok(NpmPackageSecurityResult {
                    package: req.package.clone(),
                    found: true,
                    version: None,
                    maintainers: 0,
                    download_count: None,
                    risk_indicators: vec!["Unable to parse package data".to_string()],
                }),
            }
        }
        _ => Ok(NpmPackageSecurityResult {
            package: req.package.clone(),
            found: false,
            version: None,
            maintainers: 0,
            download_count: None,
            risk_indicators: vec!["Package not found on npm".to_string()],
        }),
    }
}

/// PyPI package security check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiPackageSecurityRequest {
    pub package: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// PyPI package security result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiPackageSecurityResult {
    pub package: String,
    pub found: bool,
    pub version: Option<String>,
    pub maintainers: usize,
    pub risk_indicators: Vec<String>,
}

/// Query PyPI for package metadata and security info.
pub async fn check_pypi_package_security(req: &PypiPackageSecurityRequest) -> Result<PypiPackageSecurityResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let url = format!("https://pypi.org/pypi/{}/json", req.package);

    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => {
            match response.json::<serde_json::Value>().await {
                Ok(data) => {
                    let version = data
                        .get("info")
                        .and_then(|i| i.get("version"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let author = data
                        .get("info")
                        .and_then(|i| i.get("author"))
                        .and_then(|a| a.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false);

                    let mut risk_indicators = Vec::new();

                    if !author {
                        risk_indicators.push("No author metadata — suspicious".to_string());
                    }

                    if req.package.len() < 3 {
                        risk_indicators.push("Very short package name — typosquatting target".to_string());
                    }

                    Ok(PypiPackageSecurityResult {
                        package: req.package.clone(),
                        found: true,
                        version,
                        maintainers: if author { 1 } else { 0 },
                        risk_indicators,
                    })
                }
                Err(_) => Ok(PypiPackageSecurityResult {
                    package: req.package.clone(),
                    found: true,
                    version: None,
                    maintainers: 0,
                    risk_indicators: vec!["Unable to parse package data".to_string()],
                }),
            }
        }
        _ => Ok(PypiPackageSecurityResult {
            package: req.package.clone(),
            found: false,
            version: None,
            maintainers: 0,
            risk_indicators: vec!["Package not found on PyPI".to_string()],
        }),
    }
}

/// Dependency confusion check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyConfusionRequest {
    pub internal_package: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Dependency confusion result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyConfusionResult {
    pub package_name: String,
    pub exists_on_npm: bool,
    pub exists_on_pypi: bool,
    pub exists_on_crates: bool,
    pub risk_level: String,
    pub remediation: Option<String>,
}

/// Check if internal package exists on public registries (typosquatting/confusion).
pub async fn check_dependency_confusion(req: &DependencyConfusionRequest) -> Result<DependencyConfusionResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let npm_url = format!("https://registry.npmjs.org/{}", req.internal_package);
    let pypi_url = format!("https://pypi.org/pypi/{}/json", req.internal_package);
    let crates_url = format!("https://crates.io/api/v1/crates/{}", req.internal_package);

    let exists_on_npm = client
        .head(&npm_url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let exists_on_pypi = client
        .head(&pypi_url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let exists_on_crates = client
        .head(&crates_url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let risk_count = (exists_on_npm as u8 + exists_on_pypi as u8 + exists_on_crates as u8) as usize;
    let risk_level = match risk_count {
        0 => "low".to_string(),
        1 => "medium".to_string(),
        _ => "high".to_string(),
    };

    let remediation = if risk_count > 0 {
        Some("Register internal package on public registries or use organization scoping".to_string())
    } else {
        None
    };

    Ok(DependencyConfusionResult {
        package_name: req.internal_package.clone(),
        exists_on_npm,
        exists_on_pypi,
        exists_on_crates,
        risk_level,
        remediation,
    })
}

/// SBOM disclosure check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDisclosureRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// SBOM disclosure result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDisclosureResult {
    pub domain: String,
    pub sbom_found: bool,
    pub sbom_paths: Vec<String>,
    pub risk_level: String,
    pub remediation: Option<String>,
}

/// Detect accidentally exposed SBOM files.
pub async fn check_sbom_disclosure(req: &SbomDisclosureRequest) -> Result<SbomDisclosureResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .build()
        .map_err(|e| crate::error::ShoheError::Transport(e.to_string()))?;

    let sbom_paths = vec!["/sbom.json", "/bom.xml", "/.well-known/sbom"];
    let mut found_paths = Vec::new();

    for path in sbom_paths {
        let url = format!("https://{}{}", req.domain, path);
        if let Ok(response) = client.head(&url).send().await {
            if response.status().is_success() {
                found_paths.push(path.to_string());
            }
        }
    }

    let risk_level = if found_paths.is_empty() {
        "low".to_string()
    } else {
        "medium".to_string()
    };

    let remediation = if !found_paths.is_empty() {
        Some(format!(
            "Move SBOM files away from web root or restrict access: {}",
            found_paths.join(", ")
        ))
    } else {
        None
    };

    Ok(SbomDisclosureResult {
        domain: req.domain.clone(),
        sbom_found: !found_paths.is_empty(),
        sbom_paths: found_paths,
        risk_level,
        remediation,
    })
}

fn default_timeout() -> u64 {
    crate::api::helpers::DEFAULT_REQUEST_TIMEOUT_SECS
}
