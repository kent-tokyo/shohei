use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use futures_util::future::join_all;
use hickory_proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use serde::{Deserialize, Serialize};

use crate::error::{Result, ShoheError};

// IANA root hints (a–m root servers)
const ROOT_HINTS: &[(&str, Ipv4Addr)] = &[
    ("a.root-servers.net", Ipv4Addr::new(198, 41, 0, 4)),
    ("b.root-servers.net", Ipv4Addr::new(170, 247, 170, 2)),
    ("c.root-servers.net", Ipv4Addr::new(192, 33, 4, 12)),
    ("d.root-servers.net", Ipv4Addr::new(199, 7, 91, 13)),
    ("e.root-servers.net", Ipv4Addr::new(192, 203, 230, 10)),
    ("f.root-servers.net", Ipv4Addr::new(192, 5, 5, 241)),
    ("g.root-servers.net", Ipv4Addr::new(192, 112, 36, 4)),
    ("h.root-servers.net", Ipv4Addr::new(198, 97, 190, 53)),
    ("i.root-servers.net", Ipv4Addr::new(192, 36, 148, 17)),
    ("j.root-servers.net", Ipv4Addr::new(192, 58, 128, 30)),
    ("k.root-servers.net", Ipv4Addr::new(193, 0, 14, 129)),
    ("l.root-servers.net", Ipv4Addr::new(199, 7, 83, 42)),
    ("m.root-servers.net", Ipv4Addr::new(202, 12, 27, 33)),
];

const MAX_HOPS: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionTrace {
    pub target: String,
    pub record_type: String,
    pub steps: Vec<ResolutionStep>,
    /// Set when trace was cut short by the hop limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionStep {
    pub zone: String,
    pub server_name: String,
    pub server_addr: String,
    pub response_type: StepResponseType,
    pub duration_ms: u64,
    pub referral_to: Option<Vec<String>>,
    pub records_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepResponseType {
    Referral,
    Answer,
    Nxdomain,
    Error(String),
}

impl StepResponseType {
    pub fn label(&self) -> &'static str {
        match self {
            StepResponseType::Answer => "ANSWER",
            StepResponseType::Referral => "REFERRAL",
            StepResponseType::Nxdomain => "NXDOMAIN",
            StepResponseType::Error(_) => "ERROR",
        }
    }
}

/// `current_servers` entry: (delegated_zone, server_name, server_addr)
type ServerEntry = (String, String, SocketAddr);

pub async fn trace(
    domain: &str,
    record_type: RecordType,
    fallback_ns_ip: Option<IpAddr>,
) -> Result<ResolutionTrace> {
    let mut steps = Vec::new();
    let mut truncated = None;

    // Try root servers in order until one responds without error
    let mut root_step_opt: Option<ResolutionStep> = None;
    let mut root_next: Vec<ServerEntry> = vec![];
    for &(root_name, root_ip) in ROOT_HINTS {
        let root_addr = SocketAddr::new(IpAddr::V4(root_ip), 53);
        let (step, next) = query_server(root_name, root_addr, ".", domain, record_type, fallback_ns_ip).await;
        let ok = !matches!(step.response_type, StepResponseType::Error(_));
        root_step_opt = Some(step);
        root_next = next;
        if ok {
            break;
        }
    }
    let root_step = root_step_opt.ok_or_else(|| {
        ShoheError::Transport("All root servers unreachable".to_string())
    })?;
    if let StepResponseType::Error(msg) = &root_step.response_type {
        return Err(ShoheError::Transport(format!(
            "All root servers unreachable: {msg}"
        )));
    }
    steps.push(root_step);

    let mut current_servers: Vec<ServerEntry> = root_next;
    let mut hops = 0usize;

    loop {
        let Some((zone, server_name, server_addr)) = current_servers.first().cloned() else {
            break;
        };

        let (step, next) =
            query_server(&server_name, server_addr, &zone, domain, record_type, fallback_ns_ip).await;

        match &step.response_type {
            StepResponseType::Referral => {
                // Only count actual referrals toward the hop budget.
                hops += 1;
                if hops >= MAX_HOPS {
                    steps.push(step);
                    truncated = Some(format!(
                        "Trace stopped after {MAX_HOPS} hops without reaching an authoritative answer."
                    ));
                    break;
                }
                steps.push(step);
                if next.is_empty() {
                    break;
                }
                current_servers = next;
            }
            StepResponseType::Answer | StepResponseType::Nxdomain => {
                steps.push(step);
                break;
            }
            StepResponseType::Error(_) => {
                // Errors do not consume the hop budget — try the next server candidate.
                steps.push(step);
                if current_servers.len() > 1 {
                    current_servers = current_servers[1..].to_vec();
                } else {
                    break;
                }
            }
        }
    }

    Ok(ResolutionTrace {
        target: domain.to_string(),
        record_type: format!("{record_type}"),
        steps,
        truncated,
    })
}

fn make_resolver(ip: IpAddr) -> Result<TokioResolver> {
    let ns = NameServerConfig::udp(ip);
    let mut opts = ResolverOpts::default();
    opts.recursion_desired = false;
    opts.attempts = 1;
    opts.timeout = std::time::Duration::from_secs(5);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| ShoheError::Transport(format!("Failed to build resolver for {ip}: {e}")))
}

async fn query_server(
    server_name: &str,
    server_addr: SocketAddr,
    zone: &str,
    domain: &str,
    record_type: RecordType,
    fallback_ns_ip: Option<IpAddr>,
) -> (ResolutionStep, Vec<ServerEntry>) {
    let resolver = match make_resolver(server_addr.ip()) {
        Ok(r) => r,
        Err(e) => {
            return (
                ResolutionStep {
                    zone: zone.to_string(),
                    server_name: server_name.to_string(),
                    server_addr: server_addr.to_string(),
                    response_type: StepResponseType::Error(e.to_string()),
                    duration_ms: 0,
                    referral_to: None,
                    records_count: 0,
                },
                vec![],
            );
        }
    };

    let start = Instant::now();
    let result = resolver.lookup(domain, record_type).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(lookup) => {
            let records_count = lookup.answers().len();
            (
                ResolutionStep {
                    zone: zone.to_string(),
                    server_name: server_name.to_string(),
                    server_addr: server_addr.to_string(),
                    response_type: StepResponseType::Answer,
                    duration_ms,
                    referral_to: None,
                    records_count,
                },
                vec![],
            )
        }
        Err(e) => {
            if let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &e {
                if no_records.response_code == hickory_proto::op::ResponseCode::NXDomain {
                    return (
                        ResolutionStep {
                            zone: zone.to_string(),
                            server_name: server_name.to_string(),
                            server_addr: server_addr.to_string(),
                            response_type: StepResponseType::Nxdomain,
                            duration_ms,
                            referral_to: None,
                            records_count: 0,
                        },
                        vec![],
                    );
                }

                if let Some(ns_data) = &no_records.ns {
                    let mut next_servers: Vec<ServerEntry> = Vec::new();
                    let mut referral_names: Vec<String> = Vec::new();
                    let mut unglued: Vec<(String, String)> = Vec::new(); // (zone, ns_name)

                    for fwd in ns_data.iter() {
                        // Zone is the NS record owner name (the delegated zone, e.g. "com.")
                        let delegated_zone = fwd.ns.name.to_string();
                        // NS target is the nameserver hostname
                        let ns_name = if let hickory_proto::rr::RData::NS(ns) = &fwd.ns.data {
                            ns.0.to_string()
                        } else {
                            fwd.ns.name.to_string()
                        };
                        referral_names.push(ns_name.clone());

                        let mut found_glue = false;
                        for glue in fwd.glue.iter() {
                            let ip = match &glue.data {
                                hickory_proto::rr::RData::A(a) => Some(IpAddr::V4(a.0)),
                                hickory_proto::rr::RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                                _ => None,
                            };
                            if let Some(ip) = ip {
                                next_servers.push((
                                    delegated_zone.clone(),
                                    ns_name.clone(),
                                    SocketAddr::new(ip, 53),
                                ));
                                found_glue = true;
                                break;
                            }
                        }
                        if !found_glue {
                            unglued.push((delegated_zone, ns_name));
                        }
                    }

                    if next_servers.is_empty() && !unglued.is_empty() {
                        let names: Vec<String> = unglued.iter().map(|(_, n)| n.clone()).collect();
                        let resolved = resolve_ns_to_addrs(&names, fallback_ns_ip).await;
                        // Re-attach zone from unglued list
                        for (zone_u, ns_name_u) in &unglued {
                            if let Some((_, addr)) = resolved.iter().find(|(n, _)| n == ns_name_u) {
                                next_servers.push((zone_u.clone(), ns_name_u.clone(), *addr));
                            }
                        }
                    }

                    return (
                        ResolutionStep {
                            zone: zone.to_string(),
                            server_name: server_name.to_string(),
                            server_addr: server_addr.to_string(),
                            response_type: StepResponseType::Referral,
                            duration_ms,
                            referral_to: Some(referral_names),
                            records_count: 0,
                        },
                        next_servers,
                    );
                }
            }

            (
                ResolutionStep {
                    zone: zone.to_string(),
                    server_name: server_name.to_string(),
                    server_addr: server_addr.to_string(),
                    response_type: StepResponseType::Error(e.to_string()),
                    duration_ms,
                    referral_to: None,
                    records_count: 0,
                },
                vec![],
            )
        }
    }
}

/// Resolve unglued NS hostnames.  Uses `fallback_ip` when provided (honouring the user's
/// --server flag), otherwise falls back to a well-known public resolver.  The system resolver
/// is intentionally avoided to preserve the "iterative from root" isolation contract.
///
/// All NS names (up to 5) are resolved concurrently with `join_all`.
async fn resolve_ns_to_addrs(
    ns_names: &[String],
    fallback_ip: Option<IpAddr>,
) -> Vec<(String, SocketAddr)> {
    let ip = fallback_ip.unwrap_or(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let resolver = match make_resolver(ip) {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    // Cap at 5 to bound parallelism; real-world delegations rarely exceed this.
    // TokioResolver wraps Arc internally, so clone is cheap.
    let futs = ns_names.iter().take(5).map(|ns| {
        let ns = ns.clone();
        let resolver = resolver.clone();
        async move {
            if let Ok(response) = resolver.lookup_ip(ns.as_str()).await {
                if let Some(ip) = response.iter().next() {
                    return Some((ns, SocketAddr::new(ip, 53)));
                }
            }
            None
        }
    });

    join_all(futs).await.into_iter().flatten().collect()
}
