use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionTrace {
    pub target: String,
    pub record_type: String,
    pub steps: Vec<ResolutionStep>,
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

pub async fn trace(domain: &str, record_type: RecordType) -> Result<ResolutionTrace> {
    let mut steps = Vec::new();

    let (root_name, root_ip) = ROOT_HINTS[0];
    let root_addr = SocketAddr::new(IpAddr::V4(root_ip), 53);

    let (step, next_servers) =
        query_server(root_name, root_addr, ".", domain, record_type).await;
    steps.push(step);

    let mut current_servers = next_servers;
    let mut hops = 0usize;
    loop {
        hops += 1;
        if hops > 10 {
            break;
        }

        let Some((server_name, server_addr)) = current_servers.first().cloned() else {
            break;
        };

        let zone = extract_zone(&server_name);
        let (step, next) =
            query_server(&server_name, server_addr, &zone, domain, record_type).await;

        match &step.response_type {
            StepResponseType::Referral => {
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
        record_type: format!("{record_type:?}"),
        steps,
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
) -> (ResolutionStep, Vec<(String, SocketAddr)>) {
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
                // NXDOMAIN — domain does not exist
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

                // Referral: NS records in authority section
                if let Some(ns_data) = &no_records.ns {
                    let mut next_servers: Vec<(String, SocketAddr)> = Vec::new();
                    let mut referral_names: Vec<String> = Vec::new();
                    let mut unglu_names: Vec<String> = Vec::new();

                    for fwd in ns_data.iter() {
                        // ns.data is RData::NS(hostname); ns.name is the zone owner
                        let ns_name = if let hickory_proto::rr::RData::NS(ns) = &fwd.ns.data {
                            ns.0.to_string()
                        } else {
                            fwd.ns.name.to_string()
                        };
                        referral_names.push(ns_name.clone());

                        // Prefer glue records (avoid extra DNS lookup)
                        let mut found_glue = false;
                        for glue in fwd.glue.iter() {
                            let ip = match &glue.data {
                                hickory_proto::rr::RData::A(a) => Some(IpAddr::V4(a.0)),
                                hickory_proto::rr::RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                                _ => None,
                            };
                            if let Some(ip) = ip {
                                next_servers.push((ns_name.clone(), SocketAddr::new(ip, 53)));
                                found_glue = true;
                                break;
                            }
                        }
                        if !found_glue {
                            unglu_names.push(ns_name);
                        }
                    }

                    // Resolve unglu'd NS names if we don't have enough servers yet
                    if next_servers.is_empty() && !unglu_names.is_empty() {
                        next_servers = resolve_ns_to_addrs(&unglu_names).await;
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

async fn resolve_ns_to_addrs(ns_names: &[String]) -> Vec<(String, SocketAddr)> {
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let mut addrs = Vec::new();
    for ns in ns_names.iter().take(3) {
        if let Ok(response) = resolver.lookup_ip(ns.as_str()).await {
            if let Some(ip) = response.iter().next() {
                addrs.push((ns.clone(), SocketAddr::new(ip, 53)));
            }
        }
    }
    addrs
}

fn extract_zone(server_name: &str) -> String {
    let parts: Vec<&str> = server_name.trim_end_matches('.').splitn(2, '.').collect();
    if parts.len() > 1 {
        format!("{}.", parts[1])
    } else {
        ".".to_string()
    }
}
