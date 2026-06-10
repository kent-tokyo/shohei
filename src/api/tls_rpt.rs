//! TLS-RPT (SMTP TLS Reporting Policy) checker — RFC 8460

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Check TLS-RPT policy for a domain.
pub async fn check_tls_rpt(req: &TlsRptRequest) -> Result<TlsRptResult> {
    let domain = &req.domain;
    let query_domain = format!("_smtp._tls.{}", domain);

    let dns_req = crate::api::DnsCheckRequest {
        domain: query_domain.clone(),
        record_types: vec!["TXT".to_string()],
        transport: crate::api::Transport::System,
        validate_dnssec: req.dnssec,
        timeout_secs: req.timeout_secs,
        ipv4_only: false,
        ipv6_only: false,
        no_recurse: false,
        force_tcp: false,
    };

    match crate::api::check_dns(&dns_req).await {
        Ok(dns_results) => {
            let mut tlsrpt_records = Vec::new();

            for dns_result in dns_results {
                for record in &dns_result.answers {
                    if let crate::api::RecordData::Txt(txt_data) = &record.data {
                        let txt_value = txt_data.join("");
                        if txt_value.starts_with("v=TLSRPTv1") {
                            if let Ok(parsed) = parse_tlsrpt_record(&txt_value) {
                                tlsrpt_records.push(parsed);
                            }
                        }
                    }
                }
            }

            if tlsrpt_records.is_empty() {
                return Ok(TlsRptResult {
                    domain: domain.clone(),
                    present: false,
                    version: None,
                    rua: None,
                    rua_email: None,
                    rua_https: None,
                    record: None,
                    error: Some("No TLSRPTv1 record found".to_string()),
                });
            }

            let record = &tlsrpt_records[0];
            Ok(TlsRptResult {
                domain: domain.clone(),
                present: true,
                version: Some("TLSRPTv1".to_string()),
                rua: record.rua.clone(),
                rua_email: record.rua_email.clone(),
                rua_https: record.rua_https.clone(),
                record: Some(record.clone()),
                error: None,
            })
        }
        Err(e) => Ok(TlsRptResult {
            domain: domain.clone(),
            present: false,
            version: None,
            rua: None,
            rua_email: None,
            rua_https: None,
            record: None,
            error: Some(e.to_string()),
        }),
    }
}

fn parse_tlsrpt_record(txt: &str) -> Result<TlsRptRecord> {
    let parts: Vec<&str> = txt.split(';').collect();

    let mut version = None;
    let mut rua = None;
    let mut rua_email = None;
    let mut rua_https = None;

    for part in parts {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("v=") {
            version = Some(v.to_string());
        } else if let Some(r) = part.strip_prefix("rua=") {
            rua = Some(r.trim_matches(|c| c == '"').to_string());

            if r.contains("mailto:") {
                if let Some(email) = r.split("mailto:").nth(1) {
                    let email_part = email.split(',').next().unwrap_or("").trim().to_string();
                    if !email_part.is_empty() {
                        rua_email = Some(email_part);
                    }
                }
            }
            if r.contains("https://") {
                if let Some(url) = r.split("https://").nth(1) {
                    let url_part = url.split(',').next().unwrap_or("").trim().to_string();
                    if !url_part.is_empty() {
                        rua_https = Some(format!("https://{}", url_part));
                    }
                }
            }
        }
    }

    Ok(TlsRptRecord {
        version: version.unwrap_or_default(),
        rua,
        rua_email,
        rua_https,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptRequest {
    pub domain: String,
    #[serde(default)]
    pub dnssec: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptResult {
    pub domain: String,
    pub present: bool,
    pub version: Option<String>,
    pub rua: Option<String>,
    pub rua_email: Option<String>,
    pub rua_https: Option<String>,
    pub record: Option<TlsRptRecord>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptRecord {
    pub version: String,
    pub rua: Option<String>,
    pub rua_email: Option<String>,
    pub rua_https: Option<String>,
}
