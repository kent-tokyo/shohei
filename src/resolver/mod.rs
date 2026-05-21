use std::net::SocketAddr;

use hickory_proto::dnssec::Proof;
use hickory_proto::rr::RecordType;
use hickory_resolver::config::ResolverConfig;
use serde::{Deserialize, Serialize};

pub mod iterative;
pub mod standard;
pub mod zone_transfer;

#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub domain: String,
    pub record_type: RecordType,
    pub server: Option<SocketAddr>,
    /// Pre-built transport config (DoH/DoT). Takes priority over `server`.
    pub transport: Option<(ResolverConfig, String)>,
    pub validate_dnssec: bool,
    /// Force TCP transport instead of UDP (requires `server` to be set).
    pub force_tcp: bool,
    /// Clear the RD (Recursion Desired) bit — useful for querying authoritative servers directly.
    pub no_recurse: bool,
    /// Query timeout in seconds.
    pub timeout_secs: u64,
    /// Restrict transport to IPv4 (like dig -4).
    pub ipv4_only: bool,
    /// Restrict transport to IPv6 (like dig -6).
    pub ipv6_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryResult {
    pub query: DnsQuery,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
    pub duration_ms: u64,
    pub server_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub name: String,
    pub record_type: String,
    pub class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub ttl: u32,
    pub class: String,
    pub record_type: String,
    pub data: RecordData,
    pub trust: TrustState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum RecordData {
    A(String),
    Aaaa(String),
    Cname(String),
    Mx {
        priority: u16,
        exchange: String,
    },
    Ns(String),
    Txt(Vec<String>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Ptr(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: String,
    },
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: String,
    },
    Rrsig {
        type_covered: String,
        algorithm: u8,
        labels: u8,
        orig_ttl: u32,
        sig_expiration: String,
        sig_inception: String,
        key_tag: u16,
        signer_name: String,
        signature: String,
    },
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
    Tlsa {
        usage: u8,
        selector: u8,
        matching_type: u8,
        cert_data: String,
    },
    Sshfp {
        algorithm: u8,
        fingerprint_type: u8,
        fingerprint: String,
    },
    Https {
        priority: u16,
        target: String,
        params: String,
    },
    Svcb {
        priority: u16,
        target: String,
        params: String,
    },
    Naptr {
        order: u16,
        preference: u16,
        flags: String,
        services: String,
        regexp: String,
        replacement: String,
    },
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsComparison {
    pub domain: String,
    pub record_type: String,
    pub left: DnsQueryResult,
    pub right: DnsQueryResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMultiQuery {
    pub domain: String,
    pub record_type: String,
    pub results: Vec<DnsQueryResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TrustState {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

impl std::fmt::Display for TrustState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustState::Secure => write!(f, "SECURE"),
            TrustState::Insecure => write!(f, "INSECURE"),
            TrustState::Bogus => write!(f, "BOGUS"),
            TrustState::Indeterminate => write!(f, "INDETERMINATE"),
        }
    }
}

pub(crate) fn proof_to_trust(proof: Proof) -> TrustState {
    match proof {
        Proof::Secure => TrustState::Secure,
        Proof::Insecure => TrustState::Insecure,
        Proof::Bogus => TrustState::Bogus,
        Proof::Indeterminate => TrustState::Indeterminate,
    }
}
