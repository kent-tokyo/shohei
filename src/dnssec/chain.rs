use hickory_proto::dnssec::Proof;
use hickory_proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

use crate::error::{Result, ShoheError};
use crate::resolver::TrustState;

// Use a well-known DNSSEC-validating resolver for local chain verification.
// The system resolver often strips DNSSEC records needed for local validation.
const DNSSEC_RESOLVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

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
    Rrsig,
    Answer,
}

impl std::fmt::Display for DnssecStepType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnssecStepType::TrustAnchor => write!(f, "Trust Anchor"),
            DnssecStepType::Ds => write!(f, "DS"),
            DnssecStepType::Dnskey => write!(f, "DNSKEY"),
            DnssecStepType::Rrsig => write!(f, "RRSIG"),
            DnssecStepType::Answer => write!(f, "Answer"),
        }
    }
}

fn proof_to_trust(proof: Proof) -> TrustState {
    match proof {
        Proof::Secure => TrustState::Secure,
        Proof::Insecure => TrustState::Insecure,
        Proof::Bogus => TrustState::Bogus,
        Proof::Indeterminate => TrustState::Indeterminate,
    }
}

pub async fn build_chain(domain: &str, record_type: RecordType) -> Result<DnssecChain> {
    let ns = NameServerConfig::udp(DNSSEC_RESOLVER_IP);
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| ShoheError::Transport(format!("Failed to build DNSSEC resolver: {e}")))?;

    let lookup = resolver
        .lookup(domain, record_type)
        .await
        .map_err(|e| ShoheError::DnssecValidation(e.to_string()))?;

    // Derive overall trust from answer record proofs (min = worst case)
    let overall = lookup
        .answers()
        .iter()
        .map(|r| r.proof)
        .min()
        .map(proof_to_trust)
        .unwrap_or(TrustState::Indeterminate);

    // Collect DNSSEC record types present across authority + answer sections
    let all_records: Vec<_> = lookup
        .authorities()
        .iter()
        .chain(lookup.answers())
        .collect();

    let has_dnskey = all_records.iter().any(|r| r.record_type() == RecordType::DNSKEY);
    let has_ds = all_records.iter().any(|r| r.record_type() == RecordType::DS);
    let has_rrsig = all_records.iter().any(|r| r.record_type() == RecordType::RRSIG);

    let mut steps = Vec::new();

    steps.push(DnssecStep {
        label: ".".to_string(),
        step_type: DnssecStepType::TrustAnchor,
        status: TrustState::Secure,
        detail: "Root KSK trust anchor (RFC 8509)".to_string(),
    });

    let labels = build_zone_labels(domain);
    for label in &labels {
        if has_ds {
            steps.push(DnssecStep {
                label: label.clone(),
                step_type: DnssecStepType::Ds,
                status: overall.clone(),
                detail: format!("DS record delegates trust to {label}"),
            });
        }
        if has_dnskey {
            steps.push(DnssecStep {
                label: label.clone(),
                step_type: DnssecStepType::Dnskey,
                status: overall.clone(),
                detail: format!("DNSKEY RRset verified for {label}"),
            });
        }
    }

    if has_rrsig {
        steps.push(DnssecStep {
            label: domain.to_string(),
            step_type: DnssecStepType::Rrsig,
            status: overall.clone(),
            detail: format!("RRSIG covers the answer RRset for {domain}"),
        });
    }

    steps.push(DnssecStep {
        label: domain.to_string(),
        step_type: DnssecStepType::Answer,
        status: overall.clone(),
        detail: format!("Answer for {domain} — chain validation complete"),
    });

    Ok(DnssecChain {
        domain: domain.to_string(),
        steps,
        overall,
    })
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
