//! Attack Surface Mapping — aggregate security signals into a CVSS-like composite score.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::Result;

fn default_timeout() -> u64 { 15 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceFinding {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub score_impact: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceResult {
    pub domain: String,
    pub overall_score: f64,
    pub risk_level: String,
    pub findings: Vec<AttackSurfaceFinding>,
    pub category_scores: HashMap<String, f64>,
    pub summary: String,
}

pub async fn check_attack_surface(req: &AttackSurfaceRequest) -> Result<AttackSurfaceResult> {
    let mut findings = Vec::new();
    let mut category_scores: HashMap<String, f64> = HashMap::new();
    let timeout = req.timeout_secs;
    let domain = req.domain.clone();

    // Run core checks in parallel
    let tls_req = crate::api::TlsCheckRequest {
        hostname: domain.clone(),
        port: 443,
        check_dane: false,
        timeout_secs: timeout,
    };
    let http_req = crate::api::HttpCheckRequest {
        url: format!("https://{}", domain),
        follow_redirects: true,
        timeout_secs: timeout,
    };
    let email_req = crate::api::EmailSecurityRequest {
        domain: domain.clone(),
        timeout_secs: timeout,
        dkim_selectors: vec!["default".to_string(), "google".to_string(), "selector1".to_string()],
    };
    let ports_req = crate::api::PortCheckRequest {
        host: domain.clone(),
        ports: Some(vec![21, 22, 23, 3306, 5432, 6379, 8080, 9200, 27017]),
        timeout_secs: timeout.min(8),
    };

    let (tls_result, http_result, email_result, ports_result) = tokio::join!(
        crate::api::check_tls_chain(&tls_req),
        crate::api::check_http(&http_req),
        crate::api::check_email_security(&email_req),
        crate::api::check_ports(&ports_req),
    );

    // ── TLS (max 25 points) ─────────────────────────────────────────────────
    let tls_score = match tls_result {
        Ok(tls) if tls.connected => {
            let mut s = 15.0f64;
            if tls.valid { s += 5.0; }
            else {
                findings.push(AttackSurfaceFinding {
                    category: "TLS".to_string(),
                    severity: "high".to_string(),
                    description: "Invalid or expired TLS certificate".to_string(),
                    score_impact: -15.0,
                });
            }
            if tls.days_until_expiry.map(|d| d > 30).unwrap_or(false) { s += 5.0; }
            else {
                findings.push(AttackSurfaceFinding {
                    category: "TLS".to_string(),
                    severity: "medium".to_string(),
                    description: "Certificate expiring within 30 days".to_string(),
                    score_impact: -5.0,
                });
            }
            s
        }
        _ => {
            findings.push(AttackSurfaceFinding {
                category: "TLS".to_string(),
                severity: "high".to_string(),
                description: "HTTPS/TLS not reachable".to_string(),
                score_impact: -20.0,
            });
            5.0
        }
    };
    category_scores.insert("TLS".to_string(), tls_score);

    // ── Web Security Headers (max 25 points) ────────────────────────────────
    let http_score = match http_result {
        Ok(http) => {
            let mut s = 25.0f64;
            if !http.hsts_present {
                s -= 8.0;
                findings.push(AttackSurfaceFinding {
                    category: "Web Security".to_string(),
                    severity: "medium".to_string(),
                    description: "Missing HSTS (Strict-Transport-Security) header".to_string(),
                    score_impact: -8.0,
                });
            }
            if let Some(audit) = &http.security_headers {
                if audit.score < 50 {
                    let penalty = (50 - audit.score) as f64 * 0.1;
                    s -= penalty;
                    findings.push(AttackSurfaceFinding {
                        category: "Web Security".to_string(),
                        severity: "medium".to_string(),
                        description: format!("Low security headers score: {}/100", audit.score),
                        score_impact: -penalty,
                    });
                }
            }
            if http.server_header.is_some() {
                s -= 2.0;
            }
            s.max(0.0)
        }
        _ => 12.0,
    };
    category_scores.insert("Web Security".to_string(), http_score);

    // ── Email Security (max 25 points) ──────────────────────────────────────
    let email_score = match email_result {
        Ok(email) => {
            let s = (email.score as f64 / 100.0) * 25.0;
            if email.score < 50 {
                findings.push(AttackSurfaceFinding {
                    category: "Email Security".to_string(),
                    severity: "high".to_string(),
                    description: format!("Low email security score: {}/100 — check SPF/DKIM/DMARC", email.score),
                    score_impact: -(25.0 - s),
                });
            }
            s
        }
        _ => 12.0,
    };
    category_scores.insert("Email Security".to_string(), email_score);

    // ── Network Exposure (max 25 points) ────────────────────────────────────
    let network_score = match ports_result {
        Ok(ports) => {
            let risky: Vec<u16> = vec![21, 23, 3306, 5432, 6379, 9200, 27017];
            let open_risky: Vec<_> = ports.ports.iter()
                .filter(|p| p.status == "open" && risky.contains(&p.port))
                .collect();
            if open_risky.is_empty() {
                25.0
            } else {
                let penalty = (open_risky.len() as f64 * 5.0).min(20.0);
                findings.push(AttackSurfaceFinding {
                    category: "Network Exposure".to_string(),
                    severity: "high".to_string(),
                    description: format!(
                        "Risky ports exposed: {}",
                        open_risky.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ")
                    ),
                    score_impact: -penalty,
                });
                25.0 - penalty
            }
        }
        _ => 20.0,
    };
    category_scores.insert("Network Exposure".to_string(), network_score);

    let overall_score = category_scores.values().sum::<f64>().clamp(0.0, 100.0);

    let risk_level = if overall_score >= 80.0 { "low" }
        else if overall_score >= 60.0 { "medium" }
        else if overall_score >= 40.0 { "high" }
        else { "critical" }.to_string();

    let summary = format!(
        "Attack surface score: {:.0}/100 ({} risk). {} findings across {} categories.",
        overall_score, risk_level, findings.len(), category_scores.len()
    );

    Ok(AttackSurfaceResult {
        domain: req.domain.clone(),
        overall_score,
        risk_level,
        findings,
        category_scores,
        summary,
    })
}
