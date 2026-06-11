//! CVE lookup via NVD API — no API key required.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request to search for CVEs via NVD API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveLookupRequest {
    pub keyword: String,
    #[serde(default = "default_max_results")]
    pub max_results: u32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_max_results() -> u32 { 10 }
fn default_timeout() -> u64 { 10 }

/// A single CVE entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub severity: Option<String>,
    pub published: String,
}

/// Result of CVE lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveLookupResult {
    pub keyword: String,
    pub total_results: u32,
    pub cves: Vec<CveEntry>,
    pub error: Option<String>,
}

/// Search for CVEs in the NVD database (keyless API).
pub async fn check_cve(req: &CveLookupRequest) -> Result<CveLookupResult> {
    let keyword = req.keyword.clone();
    let max_results = std::cmp::min(req.max_results, 20);

    let encoded_keyword = urlencoding::encode(&keyword);
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage={}",
        encoded_keyword, max_results
    );

    let client = reqwest::Client::new();
    let response = match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(req.timeout_secs))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(CveLookupResult {
                keyword,
                total_results: 0,
                cves: vec![],
                error: Some(format!("API request failed: {}", e)),
            });
        }
    };

    if !response.status().is_success() {
        return Ok(CveLookupResult {
            keyword,
            total_results: 0,
            cves: vec![],
            error: Some(format!("HTTP {}", response.status().as_u16())),
        });
    }

    // Parse NVD JSON response
    #[derive(Deserialize)]
    struct NvdVulnerability {
        cve: NvdCveData,
    }

    #[derive(Deserialize)]
    struct NvdCveData {
        id: String,
        descriptions: Option<Vec<NvdDescription>>,
        metrics: Option<NvdMetrics>,
        published: String,
    }

    #[derive(Deserialize)]
    struct NvdDescription {
        value: String,
    }

    #[derive(Deserialize)]
    struct NvdMetrics {
        #[serde(rename = "cvssMetricV31")]
        cvss_v31: Option<Vec<NvdCvssMetric>>,
    }

    #[derive(Deserialize)]
    struct NvdCvssMetric {
        cvssData: NvdCvssData,
    }

    #[derive(Deserialize)]
    struct NvdCvssData {
        baseScore: f64,
        baseSeverity: String,
    }

    #[derive(Deserialize)]
    struct NvdApiResponse {
        vulnerabilities: Option<Vec<NvdVulnerability>>,
        resultsPerPage: Option<u32>,
    }

    match response.json::<NvdApiResponse>().await {
        Ok(api_resp) => {
            let vulnerabilities = api_resp.vulnerabilities.unwrap_or_default();
            let total = vulnerabilities.len() as u32;

            let cves: Vec<CveEntry> = vulnerabilities
                .into_iter()
                .map(|v| {
                    let description = v
                        .cve
                        .descriptions
                        .as_ref()
                        .and_then(|descs| descs.first())
                        .map(|d| {
                            if d.value.len() > 200 {
                                format!("{}...", &d.value[..200])
                            } else {
                                d.value.clone()
                            }
                        })
                        .unwrap_or_default();

                    let (cvss_score, severity) = v
                        .cve
                        .metrics
                        .as_ref()
                        .and_then(|m| m.cvss_v31.as_ref())
                        .and_then(|metrics| metrics.first())
                        .map(|m| (Some(m.cvssData.baseScore), Some(m.cvssData.baseSeverity.clone())))
                        .unwrap_or((None, None));

                    CveEntry {
                        id: v.cve.id,
                        description,
                        cvss_score,
                        severity,
                        published: v.cve.published,
                    }
                })
                .collect();

            Ok(CveLookupResult {
                keyword,
                total_results: total,
                cves,
                error: None,
            })
        }
        Err(e) => {
            Ok(CveLookupResult {
                keyword,
                total_results: 0,
                cves: vec![],
                error: Some(format!("JSON parse error: {}", e)),
            })
        }
    }
}
