use std::net::IpAddr;
use std::time::Instant;

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::PublicKey;
use hickory_proto::rr::RData;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

use crate::error::Result;
use crate::resolver::{DnsQuery, DnsQueryResult, DnsRecord, QueryOptions, RecordData, TrustState};

pub async fn query(opts: &QueryOptions) -> Result<DnsQueryResult> {
    let mut resolver_opts = ResolverOpts::default();
    if opts.validate_dnssec {
        resolver_opts.validate = true;
    }

    let (resolver, server_addr) = if let Some(server) = &opts.server {
        let ip: IpAddr = server.ip();
        let ns = NameServerConfig::udp(ip);
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
    let lookup = resolver
        .lookup(opts.domain.as_str(), opts.record_type)
        .await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    let dns_query = DnsQuery {
        name: opts.domain.clone(),
        record_type: format!("{:?}", opts.record_type),
        class: "IN".to_string(),
    };

    let answers: Vec<DnsRecord> = lookup.answers().iter().map(record_to_dns_record).collect();

    Ok(DnsQueryResult {
        query: dns_query,
        answers,
        authority: vec![],
        additional: vec![],
        duration_ms,
        server_addr,
    })
}

fn record_to_dns_record(record: &hickory_proto::rr::Record) -> DnsRecord {
    let name = record.name.to_string();
    let ttl = record.ttl;
    let record_type = record.record_type().to_string();
    let data = rdata_to_record_data(&record.data);

    DnsRecord {
        name,
        ttl,
        class: "IN".to_string(),
        record_type,
        data,
        trust: TrustState::Indeterminate,
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
            refresh: soa.refresh as u32,
            retry: soa.retry as u32,
            expire: soa.expire as u32,
            minimum: soa.minimum,
        },
        RData::PTR(ptr) => RecordData::Ptr(ptr.0.to_string()),
        RData::SRV(srv) => RecordData::Srv {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: srv.target.to_string(),
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
