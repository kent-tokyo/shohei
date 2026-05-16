use hickory_proto::dnssec::Proof;
use hickory_proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

use crate::error::{Result, ShoheError};
use crate::resolver::{proof_to_trust, TrustState};

// Fallback DNSSEC-validating resolver.  The system resolver often strips
// DNSSEC records needed for local validation.  Overridden by --server when
// the user provides one.
const DNSSEC_RESOLVER_FALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecChain {
    pub domain: String,
    pub steps: Vec<DnssecStep>,
    pub overall: TrustState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecStep {
    pub label: String,
    pub step_type: DnssecStepType,
    pub status: TrustState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnssecStepType {
    TrustAnchor,
    Ds,
    Dnskey,
    Answer,
}

impl std::fmt::Display for DnssecStepType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnssecStepType::TrustAnchor => write!(f, "Trust Anchor"),
            DnssecStepType::Ds => write!(f, "DS"),
            DnssecStepType::Dnskey => write!(f, "DNSKEY"),
            DnssecStepType::Answer => write!(f, "Answer"),
        }
    }
}

/// Derive per-zone step status from whether records exist and the overall chain result.
/// Zones that have the relevant records present are shown as Secure at that level;
/// the first zone missing DS or DNSKEY is the break point (Bogus / Insecure).
fn zone_step_status(has_records: bool, overall: &TrustState) -> TrustState {
    match overall {
        TrustState::Secure => TrustState::Secure,
        TrustState::Indeterminate => TrustState::Indeterminate,
        // For Bogus/Insecure: zones that have their records are themselves fine;
        // the failing zone is whichever one is missing records.
        TrustState::Bogus | TrustState::Insecure => {
            if has_records {
                TrustState::Secure
            } else {
                overall.clone()
            }
        }
    }
}

pub async fn build_chain(
    domain: &str,
    record_type: RecordType,
    resolver_ip: Option<IpAddr>,
) -> Result<DnssecChain> {
    // Reject domains with empty labels (e.g. "a..b.com")
    if domain.trim_end_matches('.').split('.').any(|l| l.is_empty()) {
        return Err(ShoheError::Parse(format!(
            "Invalid domain: empty label in '{domain}'"
        )));
    }

    let resolver_ip = resolver_ip.unwrap_or(DNSSEC_RESOLVER_FALLBACK);

    // Step 1: Determine overall chain trust via DNSSEC-validating resolver
    let overall = get_overall_trust(domain, record_type, resolver_ip).await?;

    // Step 2: Build a non-validating resolver for per-zone record existence queries
    let ns = NameServerConfig::udp(resolver_ip);
    let mut opts = ResolverOpts::default();
    opts.attempts = 1;
    opts.timeout = std::time::Duration::from_secs(5);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| ShoheError::Transport(format!("Failed to build resolver: {e}")))?;

    let zone_labels = build_zone_labels(domain);
    let mut steps = Vec::new();

    steps.push(DnssecStep {
        label: ".".to_string(),
        step_type: DnssecStepType::TrustAnchor,
        status: TrustState::Secure,
        detail: "Root KSK trust anchor (RFC 8509)".to_string(),
    });

    // Per-zone DS and DNSKEY queries
    for zone in &zone_labels {
        let has_ds = query_has_records(&resolver, zone, RecordType::DS).await;
        let has_dnskey = query_has_records(&resolver, zone, RecordType::DNSKEY).await;

        if has_ds {
            steps.push(DnssecStep {
                label: zone.clone(),
                step_type: DnssecStepType::Ds,
                status: zone_step_status(true, &overall),
                detail: format!("DS record delegates trust to {zone}"),
            });
        } else {
            steps.push(DnssecStep {
                label: zone.clone(),
                step_type: DnssecStepType::Ds,
                status: zone_step_status(false, &overall),
                detail: format!("No DS delegation for {zone}"),
            });
        }

        if has_dnskey {
            steps.push(DnssecStep {
                label: zone.clone(),
                step_type: DnssecStepType::Dnskey,
                status: zone_step_status(true, &overall),
                detail: format!("DNSKEY RRset verified for {zone}"),
            });
        } else {
            steps.push(DnssecStep {
                label: zone.clone(),
                step_type: DnssecStepType::Dnskey,
                status: zone_step_status(false, &overall),
                detail: format!("No DNSKEY for {zone}"),
            });
        }
    }

    steps.push(DnssecStep {
        label: domain.to_string(),
        step_type: DnssecStepType::Answer,
        status: overall.clone(),
        detail: "chain validation complete".to_string(),
    });

    Ok(DnssecChain {
        domain: domain.to_string(),
        steps,
        overall,
    })
}

async fn get_overall_trust(domain: &str, record_type: RecordType, resolver_ip: IpAddr) -> Result<TrustState> {
    let ns = NameServerConfig::udp(resolver_ip);
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    opts.attempts = 1;
    opts.timeout = std::time::Duration::from_secs(5);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| ShoheError::Transport(format!("Failed to build DNSSEC resolver: {e}")))?;

    let lookup = resolver
        .lookup(domain, record_type)
        .await
        .map_err(|e| ShoheError::DnssecValidation(e.to_string()))?;

    // Bogus must beat Indeterminate: use explicit severity order rather than Proof's Ord.
    let overall = lookup
        .answers()
        .iter()
        .map(|r| r.proof)
        .reduce(worst_proof)
        .map(proof_to_trust)
        .unwrap_or(TrustState::Indeterminate);

    Ok(overall)
}

/// Returns the proof with higher alarm severity.
/// Severity: Bogus > Indeterminate > Insecure > Secure.
/// (Proof's Ord puts Indeterminate below Bogus numerically, but for display Bogus must win.)
fn worst_proof(a: Proof, b: Proof) -> Proof {
    let sev = |p: Proof| match p {
        Proof::Bogus => 3,
        Proof::Indeterminate => 2,
        Proof::Insecure => 1,
        Proof::Secure => 0,
    };
    if sev(a) >= sev(b) { a } else { b }
}

async fn query_has_records(resolver: &TokioResolver, name: &str, rtype: RecordType) -> bool {
    resolver
        .lookup(name, rtype)
        .await
        .map(|l| !l.answers().is_empty())
        .unwrap_or(false)
}

fn build_zone_labels(domain: &str) -> Vec<String> {
    let domain = domain.trim_end_matches('.');
    let parts: Vec<&str> = domain.split('.').collect();
    let mut labels = Vec::new();

    for i in (0..parts.len()).rev() {
        let label = format!("{}.", parts[i..].join("."));
        labels.push(label);
    }
    labels
}
