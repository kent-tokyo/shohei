use std::time::Instant;

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::PublicKey;
use hickory_proto::rr::RData;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::TokioResolver;

use crate::error::Result;
use crate::resolver::{proof_to_trust, DnsQuery, DnsQueryResult, DnsRecord, QueryOptions, RecordData};

pub async fn query(opts: &QueryOptions) -> Result<DnsQueryResult> {
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.attempts = 1;
    resolver_opts.timeout = std::time::Duration::from_secs(opts.timeout_secs);
    if opts.validate_dnssec {
        resolver_opts.validate = true;
    }
    if opts.no_recurse {
        resolver_opts.recursion_desired = false;
    }

    let (resolver, server_addr) = if let Some((config, label)) = &opts.transport {
        // DoH / DoT transport takes highest priority
        let r = TokioResolver::builder_with_config(config.clone(), TokioRuntimeProvider::default())
            .with_options(resolver_opts)
            .build()?;
        (r, label.clone())
    } else if let Some(server) = &opts.server {
        // Custom server with correct port
        let mut ns = if opts.force_tcp {
            NameServerConfig::tcp(server.ip())
        } else {
            NameServerConfig::udp(server.ip())
        };
        debug_assert!(!ns.connections.is_empty(), "hickory NameServerConfig::udp must yield ≥1 connection");
        if let Some(conn) = ns.connections.first_mut() {
            conn.port = server.port();
        }
        let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
        let r = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(resolver_opts)
            .build()?;
        (r, server.to_string())
    } else {
        let r = TokioResolver::builder_tokio()?
            .with_options(resolver_opts)
            .build()?;
        (r, "system".to_string())
    };

    let start = Instant::now();
    let lookup_result = resolver.lookup(opts.domain.as_str(), opts.record_type).await;
    let duration_ms = start.elapsed().as_millis() as u64;

    let dns_query = DnsQuery {
        name: opts.domain.clone(),
        record_type: opts.record_type.to_string(),
        class: "IN".to_string(),
    };

    match lookup_result {
        Ok(lookup) => {
            let answers = lookup.answers().iter().map(record_to_dns_record).collect();
            let authority = lookup.authorities().iter().map(record_to_dns_record).collect();
            let additional = lookup.additionals().iter().map(record_to_dns_record).collect();
            Ok(DnsQueryResult {
                query: dns_query,
                answers,
                authority,
                additional,
                duration_ms,
                server_addr,
            })
        }
        Err(e) => {
            // Referral response: ANSWER is empty but AUTHORITY (NS) + ADDITIONAL (glue) are present.
            // hickory returns this as NoRecordsFound rather than a successful Lookup.
            if let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &e {
                if let Some(ns_data) = &no_records.ns {
                    let mut authority: Vec<DnsRecord> = Vec::new();
                    let mut additional: Vec<DnsRecord> = Vec::new();
                    for fwd in ns_data.iter() {
                        authority.push(record_to_dns_record(&fwd.ns));
                        for glue in fwd.glue.iter() {
                            additional.push(record_to_dns_record(glue));
                        }
                    }
                    if !authority.is_empty() {
                        return Ok(DnsQueryResult {
                            query: dns_query,
                            answers: vec![],
                            authority,
                            additional,
                            duration_ms,
                            server_addr,
                        });
                    }
                }
            }
            Err(e.into())
        }
    }
}

fn record_to_dns_record(record: &hickory_proto::rr::Record) -> DnsRecord {
    let name = record.name.to_string();
    let ttl = record.ttl;
    let record_type = record.record_type().to_string();
    let data = rdata_to_record_data(&record.data);
    let trust = proof_to_trust(record.proof);

    DnsRecord {
        name,
        ttl,
        class: "IN".to_string(),
        record_type,
        data,
        trust,
    }
}

fn rdata_to_record_data(rdata: &RData) -> RecordData {
    match rdata {
        RData::A(a) => RecordData::A(a.to_string()),
        RData::AAAA(aaaa) => RecordData::Aaaa(aaaa.to_string()),
        RData::CNAME(cname) => RecordData::Cname(cname.0.to_string()),
        RData::MX(mx) => RecordData::Mx {
            priority: mx.preference,
            exchange: mx.exchange.to_string(),
        },
        RData::NS(ns) => RecordData::Ns(ns.0.to_string()),
        RData::TXT(txt) => {
            let strings: Vec<String> = txt
                .txt_data
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect();
            RecordData::Txt(strings)
        }
        RData::SOA(soa) => RecordData::Soa {
            mname: soa.mname.to_string(),
            rname: soa.rname.to_string(),
            serial: soa.serial,
            refresh: soa.refresh.max(0) as u32,
            retry: soa.retry.max(0) as u32,
            expire: soa.expire.max(0) as u32,
            minimum: soa.minimum,
        },
        RData::PTR(ptr) => RecordData::Ptr(ptr.0.to_string()),
        RData::SRV(srv) => RecordData::Srv {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: srv.target.to_string(),
        },
        RData::CAA(caa) => RecordData::Caa {
            flags: caa.issuer_critical as u8,
            tag: caa.tag.clone(),
            value: String::from_utf8_lossy(&caa.value).into_owned(),
        },
        RData::TLSA(tlsa) => RecordData::Tlsa {
            usage: u8::from(tlsa.cert_usage),
            selector: u8::from(tlsa.selector),
            matching_type: u8::from(tlsa.matching),
            cert_data: hex_encode(&tlsa.cert_data),
        },
        RData::SSHFP(fp) => RecordData::Sshfp {
            algorithm: u8::from(fp.algorithm),
            fingerprint_type: u8::from(fp.fingerprint_type),
            fingerprint: hex_encode(&fp.fingerprint),
        },
        RData::DNSSEC(dnssec) => rdata_dnssec_to_record_data(dnssec),
        other => RecordData::Unknown(format!("{other}")),
    }
}

fn rdata_dnssec_to_record_data(dnssec: &DNSSECRData) -> RecordData {
    match dnssec {
        DNSSECRData::DNSKEY(key) => RecordData::Dnskey {
            flags: key.flags(),
            protocol: 3,
            algorithm: key.public_key().algorithm().into(),
            public_key: hex_encode(key.public_key().public_bytes()),
        },
        DNSSECRData::DS(ds) => RecordData::Ds {
            key_tag: ds.key_tag(),
            algorithm: ds.algorithm().into(),
            digest_type: ds.digest_type().into(),
            digest: hex_encode(ds.digest()),
        },
        DNSSECRData::RRSIG(rrsig) => {
            let input = rrsig.input();
            RecordData::Rrsig {
                type_covered: input.type_covered.to_string(),
                algorithm: input.algorithm.into(),
                labels: input.num_labels,
                orig_ttl: input.original_ttl,
                sig_expiration: input.sig_expiration.get().to_string(),
                sig_inception: input.sig_inception.get().to_string(),
                key_tag: input.key_tag,
                signer_name: input.signer_name.to_string(),
                signature: hex_encode(rrsig.sig()),
            }
        }
        other => RecordData::Unknown(format!("{other:?}")),
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
