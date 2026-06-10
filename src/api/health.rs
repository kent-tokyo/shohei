//! Domain health assessment — comprehensive diagnostic report.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{
    check_dns, check_tls_chain, check_email_security, check_propagation_global,
    DnsCheckRequest, TlsCheckRequest, EmailSecurityRequest,
};

/// Perform comprehensive domain health assessment.
pub async fn check_domain_health(req: &DomainHealthRequest) -> Result<DomainHealthReport> {
    let mut dns_health = HealthComponent {
        score: 0,
        status: HealthStatus::Critical,
        details: vec![],
    };
    let mut tls_health = HealthComponent {
        score: 0,
        status: HealthStatus::Critical,
        details: vec![],
    };
    let mut email_health = HealthComponent {
        score: 0,
        status: HealthStatus::Critical,
        details: vec![],
    };
    let mut propagation_health = HealthComponent {
        score: 0,
        status: HealthStatus::Critical,
        details: vec![],
    };
    let mut issues = Vec::new();
    let mut recommendations = Vec::new();

    // Check DNS
    let dns_req = DnsCheckRequest {
        domain: req.domain.clone(),
        record_types: vec!["A".to_string(), "AAAA".to_string(), "MX".to_string()],
        timeout_secs: req.timeout_secs,
        ..Default::default()
    };
    if let Ok(dns_results) = check_dns(&dns_req).await {
        let has_a = dns_results.iter().any(|r| r.query.record_type == "A" && !r.answers.is_empty());
        let has_aaaa = dns_results.iter().any(|r| r.query.record_type == "AAAA" && !r.answers.is_empty());
        let has_mx = dns_results.iter().any(|r| r.query.record_type == "MX" && !r.answers.is_empty());

        dns_health.score = if has_a { 100 } else { 0 };
        dns_health.details.push(format!("A record: {}", if has_a { "✓" } else { "✗" }));
        dns_health.details.push(format!("AAAA record: {}", if has_aaaa { "✓" } else { "✗" }));
        dns_health.details.push(format!("MX record: {}", if has_mx { "✓" } else { "✗" }));

        if !has_a {
            issues.push("No A record found".to_string());
            recommendations.push("Add A record pointing to your web server".to_string());
        }
        if !has_aaaa {
            recommendations.push("Consider adding AAAA (IPv6) record for better compatibility".to_string());
        }
        if !has_mx {
            issues.push("No MX record found (email will not work)".to_string());
            recommendations.push("Add MX record if you use email services".to_string());
        }
    } else {
        issues.push("Failed to resolve domain via DNS".to_string());
    }
    dns_health.status = score_to_status(dns_health.score);

    // Check TLS
    let tls_req = TlsCheckRequest {
        hostname: req.domain.clone(),
        port: 443,
        check_dane: false,
        timeout_secs: req.timeout_secs,
    };
    if let Ok(tls_result) = check_tls_chain(&tls_req).await {
        tls_health.score = if tls_result.valid { 100 } else { 0 };
        tls_health.details.push(format!("Connected: {}", if tls_result.connected { "✓" } else { "✗" }));
        if let Some(days) = tls_result.days_until_expiry {
            tls_health.details.push(format!("Days until expiry: {}", days));
        }

        if !tls_result.connected {
            issues.push("TLS connection failed".to_string());
            recommendations.push("Ensure your web server has a valid HTTPS certificate".to_string());
        } else if tls_result.expired {
            issues.push("SSL certificate is expired".to_string());
            recommendations.push("Renew your SSL certificate immediately".to_string());
        } else if tls_result.expiry_warning {
            issues.push("SSL certificate expiring soon".to_string());
            recommendations.push("Renew your SSL certificate in the next 30 days".to_string());
        }
    } else {
        tls_health.score = 0;
        issues.push("Failed to check TLS certificate".to_string());
    }
    tls_health.status = score_to_status(tls_health.score);

    // Check Email Security
    let email_req = EmailSecurityRequest {
        domain: req.domain.clone(),
        timeout_secs: req.timeout_secs,
        dkim_selectors: vec![
            "default".to_string(),
            "google".to_string(),
            "selector1".to_string(),
            "selector2".to_string(),
        ],
    };
    if let Ok(email_result) = check_email_security(&email_req).await {
        email_health.score = email_result.score;
        email_health.details.push(format!("MX: {}", if email_result.mx.valid { "✓" } else { "✗" }));
        email_health.details.push(format!("SPF: {}", if email_result.spf.valid { "✓" } else { "✗" }));
        email_health.details.push(format!("DMARC: {}", if email_result.dmarc.valid { "✓" } else { "✗" }));
        email_health.details.push(format!("DKIM: {}", email_result.dkim.iter().filter(|d| d.present).count()));

        if !email_result.spf.valid {
            recommendations.push("Add SPF record to prevent email spoofing".to_string());
        }
        if !email_result.dmarc.valid {
            recommendations.push("Add DMARC policy for email protection".to_string());
        }
    }
    email_health.status = score_to_status(email_health.score);

    // Check Propagation
    if let Ok(prop_result) = check_propagation_global(&req.domain).await {
        propagation_health.score = if prop_result.consistent { 100 } else { 50 };
        propagation_health.details.push(format!(
            "Consistent across resolvers: {}",
            if prop_result.consistent { "✓" } else { "✗" }
        ));
        propagation_health.details.push(format!("Checked {} resolvers", prop_result.results.len()));

        if !prop_result.consistent {
            recommendations.push("Wait for DNS propagation or check with your DNS provider".to_string());
        }
    }
    propagation_health.status = score_to_status(propagation_health.score);

    // Calculate overall score (weighted average)
    let overall_score = (
        (dns_health.score as f64 * 0.25)
            + (tls_health.score as f64 * 0.35)
            + (email_health.score as f64 * 0.25)
            + (propagation_health.score as f64 * 0.15)
    ) as u8;

    Ok(DomainHealthReport {
        domain: req.domain.clone(),
        overall_score,
        dns_health,
        tls_health,
        email_health,
        propagation_health,
        issues,
        recommendations,
        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

fn score_to_status(score: u8) -> HealthStatus {
    match score {
        90..=100 => HealthStatus::Excellent,
        70..=89 => HealthStatus::Good,
        50..=69 => HealthStatus::Warning,
        _ => HealthStatus::Critical,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainHealthRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainHealthReport {
    pub domain: String,
    pub overall_score: u8,
    pub dns_health: HealthComponent,
    pub tls_health: HealthComponent,
    pub email_health: HealthComponent,
    pub propagation_health: HealthComponent,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthComponent {
    pub score: u8,
    pub status: HealthStatus,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Excellent,
    Good,
    Warning,
    Critical,
}
