//! Compliance assessment — map domain checks to CIS, PCI-DSS, HIPAA controls.

use serde::{Deserialize, Serialize};
use crate::error::Result;

/// Request for compliance assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequest {
    pub domain: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 15 }

/// Single compliance item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceItem {
    pub control_id: String,
    pub framework: String,
    pub description: String,
    pub status: String,    // "pass" | "fail" | "warning" | "not_checked"
    pub evidence: String,
}

/// Compliance assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub domain: String,
    pub score: u8,
    pub items: Vec<ComplianceItem>,
    pub frameworks_checked: Vec<String>,
    pub error: Option<String>,
}

/// Assess domain compliance against CIS, PCI-DSS, HIPAA controls.
pub async fn check_compliance(req: &ComplianceRequest) -> Result<ComplianceResult> {
    // Run checks in parallel
    let tls_req = crate::api::TlsCheckRequest {
        hostname: req.domain.clone(),
        port: 443,
        check_dane: false,
        timeout_secs: req.timeout_secs,
    };

    let email_req = crate::api::EmailSecurityRequest {
        domain: req.domain.clone(),
        dkim_selectors: vec!["default".to_string(), "google".to_string(), "selector1".to_string(), "selector2".to_string()],
        timeout_secs: req.timeout_secs,
    };

    let caa_req = crate::api::CaaCheckRequest {
        domain: req.domain.clone(),
        issued_by_ca: None,
        timeout_secs: req.timeout_secs,
    };

    let (tls_result, email_result, http_result, caa_result) = tokio::join!(
        crate::api::check_tls_chain(&tls_req),
        crate::api::check_email_security(&email_req),
        async {
            if let Some(url) = &req.url {
                let http_req = crate::api::HttpCheckRequest {
                    url: url.clone(),
                    follow_redirects: true,
                    timeout_secs: req.timeout_secs,
                };
                crate::api::check_http(&http_req).await.ok()
            } else {
                None
            }
        },
        crate::api::check_caa(&caa_req),
    );

    let mut items = Vec::new();

    // PCI-DSS-4.2.1: Valid TLS certificate
    if let Ok(tls) = &tls_result {
        let status = if tls.valid && tls.days_until_expiry.map_or(false, |d| d > 0) {
            "pass"
        } else {
            "fail"
        };
        let evidence = format!(
            "TLS valid: {}, expires in {} days",
            tls.valid,
            tls.days_until_expiry.unwrap_or(0)
        );
        items.push(ComplianceItem {
            control_id: "PCI-DSS-4.2.1".to_string(),
            framework: "PCI-DSS".to_string(),
            description: "Use strong cryptography and security protocols in transit".to_string(),
            status: status.to_string(),
            evidence,
        });
    }

    // PCI-DSS-4.2.1b: TLS 1.2 or higher
    if let Ok(tls) = &tls_result {
        let tls_ok = tls.tls_version.as_ref().map_or(false, |v| {
            v.contains("1.2") || v.contains("1.3")
        });
        let status = if tls_ok { "pass" } else { "fail" };
        items.push(ComplianceItem {
            control_id: "PCI-DSS-4.2.1b".to_string(),
            framework: "PCI-DSS".to_string(),
            description: "TLS version 1.2 or higher required".to_string(),
            status: status.to_string(),
            evidence: format!("TLS version: {:?}", tls.tls_version),
        });
    }

    // HIPAA-164.312e2ii: Encryption in transit
    if let Ok(tls) = &tls_result {
        let status = if tls.valid { "pass" } else { "fail" };
        items.push(ComplianceItem {
            control_id: "HIPAA-164.312e2ii".to_string(),
            framework: "HIPAA".to_string(),
            description: "Encryption in transit for patient health information".to_string(),
            status: status.to_string(),
            evidence: format!("TLS connection valid: {}", tls.valid),
        });
    }

    // CIS-9.3-SPF: SPF record configured
    if let Ok(email) = &email_result {
        let spf_ok = email.spf.raw.is_some() && email.spf.valid;
        let status = if spf_ok { "pass" } else { "fail" };
        items.push(ComplianceItem {
            control_id: "CIS-9.3-SPF".to_string(),
            framework: "CIS".to_string(),
            description: "SPF record present and valid".to_string(),
            status: status.to_string(),
            evidence: format!("SPF raw: {:?}, valid: {}", email.spf.raw.is_some(), email.spf.valid),
        });
    }

    // CIS-9.3-DMARC: DMARC record configured
    if let Ok(email) = &email_result {
        let dmarc_ok = email.dmarc.raw.is_some() && email.dmarc.valid &&
                       email.dmarc.policy.as_ref().map_or(false, |p| p != &crate::api::DmarcPolicy::None);
        let status = if dmarc_ok { "pass" } else { "fail" };
        items.push(ComplianceItem {
            control_id: "CIS-9.3-DMARC".to_string(),
            framework: "CIS".to_string(),
            description: "DMARC policy present and enforced".to_string(),
            status: status.to_string(),
            evidence: format!("DMARC raw: {:?}, valid: {}, policy: {:?}", email.dmarc.raw.is_some(), email.dmarc.valid, email.dmarc.policy),
        });
    }

    // OWASP-A05-HSTS: HSTS header
    if let Some(http) = &http_result {
        let status = if http.hsts_present { "pass" } else { "warning" };
        items.push(ComplianceItem {
            control_id: "OWASP-A05-HSTS".to_string(),
            framework: "OWASP".to_string(),
            description: "HTTP Strict-Transport-Security header present".to_string(),
            status: status.to_string(),
            evidence: format!("HSTS present: {}", http.hsts_present),
        });
    } else if req.url.is_none() {
        items.push(ComplianceItem {
            control_id: "OWASP-A05-HSTS".to_string(),
            framework: "OWASP".to_string(),
            description: "HTTP Strict-Transport-Security header present".to_string(),
            status: "not_checked".to_string(),
            evidence: "No URL provided".to_string(),
        });
    }

    // OWASP-A05-CSP: Content-Security-Policy header
    if let Some(http) = &http_result {
        let csp_ok = http.security_headers.as_ref().map_or(false, |sh| {
            sh.headers.get("Content-Security-Policy").map_or(false, |h| h.present)
        });
        let status = if csp_ok { "pass" } else { "warning" };
        items.push(ComplianceItem {
            control_id: "OWASP-A05-CSP".to_string(),
            framework: "OWASP".to_string(),
            description: "Content-Security-Policy header present".to_string(),
            status: status.to_string(),
            evidence: format!("CSP header present: {}", csp_ok),
        });
    } else if req.url.is_none() {
        items.push(ComplianceItem {
            control_id: "OWASP-A05-CSP".to_string(),
            framework: "OWASP".to_string(),
            description: "Content-Security-Policy header present".to_string(),
            status: "not_checked".to_string(),
            evidence: "No URL provided".to_string(),
        });
    }

    // OWASP-A05-XFO: X-Frame-Options header
    if let Some(http) = &http_result {
        let xfo_ok = http.security_headers.as_ref().map_or(false, |sh| {
            sh.headers.get("X-Frame-Options").map_or(false, |h| h.present)
        });
        let status = if xfo_ok { "pass" } else { "warning" };
        items.push(ComplianceItem {
            control_id: "OWASP-A05-XFO".to_string(),
            framework: "OWASP".to_string(),
            description: "X-Frame-Options header present".to_string(),
            status: status.to_string(),
            evidence: format!("X-Frame-Options present: {}", xfo_ok),
        });
    } else if req.url.is_none() {
        items.push(ComplianceItem {
            control_id: "OWASP-A05-XFO".to_string(),
            framework: "OWASP".to_string(),
            description: "X-Frame-Options header present".to_string(),
            status: "not_checked".to_string(),
            evidence: "No URL provided".to_string(),
        });
    }

    // PCI-DSS-6.4.3: CAA records
    if let Ok(caa) = &caa_result {
        let status = if !caa.records.is_empty() { "pass" } else { "warning" };
        items.push(ComplianceItem {
            control_id: "PCI-DSS-6.4.3".to_string(),
            framework: "PCI-DSS".to_string(),
            description: "CAA records configured to control certificate issuance".to_string(),
            status: status.to_string(),
            evidence: format!("CAA records found: {}", caa.records.len()),
        });
    }

    // Calculate score
    let pass_count = items.iter().filter(|i| i.status == "pass").count();
    let checked_count = items.iter().filter(|i| i.status != "not_checked").count();
    let score = if checked_count > 0 {
        ((pass_count as f64 / checked_count as f64) * 100.0) as u8
    } else {
        0
    };

    Ok(ComplianceResult {
        domain: req.domain.clone(),
        score,
        items,
        frameworks_checked: vec!["PCI-DSS".to_string(), "HIPAA".to_string(), "CIS".to_string(), "OWASP".to_string()],
        error: None,
    })
}
