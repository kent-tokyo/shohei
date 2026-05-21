use comfy_table::{Cell, CellAlignment, Table};

use crate::display::colors::{paint_dim, trust_badge};
use crate::resolver::{DnsQueryResult, RecordData};

fn format_ttl(secs: u32) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        if s == 0 { format!("{m}m") } else { format!("{m}m{s}s") }
    } else if secs < 86400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m == 0 { format!("{h}h") } else { format!("{h}h{m}m") }
    } else {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        if h == 0 { format!("{d}d") } else { format!("{d}d{h}h") }
    }
}

pub fn render_result(result: &DnsQueryResult, use_color: bool) -> String {
    let mut output = String::new();

    if use_color {
        output.push_str(&format!(
            "\n  {} {} {}\n\n",
            paint_dim("Query:"),
            result.query.name,
            paint_dim(&format!(
                "({} {})",
                result.query.record_type, result.query.class
            ))
        ));
    } else {
        output.push_str(&format!(
            "\nQuery: {} ({} {})\n\n",
            result.query.name, result.query.record_type, result.query.class
        ));
    }

    if result.answers.is_empty() {
        output.push_str("  No records found.\n");
    } else {
        output.push_str(&render_records_table(&result.answers, use_color));
    }

    if !result.authority.is_empty() {
        if use_color {
            output.push_str(&format!("\n  {}\n\n", paint_dim("Authority Section:")));
        } else {
            output.push_str("\nAuthority Section:\n\n");
        }
        output.push_str(&render_records_table(&result.authority, use_color));
    }

    if !result.additional.is_empty() {
        if use_color {
            output.push_str(&format!("\n  {}\n\n", paint_dim("Additional Section:")));
        } else {
            output.push_str("\nAdditional Section:\n\n");
        }
        output.push_str(&render_records_table(&result.additional, use_color));
    }

    if use_color {
        output.push_str(&format!(
            "\n  {}\n",
            paint_dim(&format!(
                "Resolved in {}ms via {}",
                result.duration_ms, result.server_addr
            ))
        ));
    } else {
        output.push_str(&format!(
            "\nResolved in {}ms via {}\n",
            result.duration_ms, result.server_addr
        ));
    }

    output
}

fn render_records_table(records: &[crate::resolver::DnsRecord], use_color: bool) -> String {
    let mut table = Table::new();
    table.set_header(vec!["NAME", "TTL", "TYPE", "DATA", "TRUST"]);

    for record in records {
        let trust_cell = if use_color {
            trust_badge(&record.trust)
        } else {
            record.trust.to_string()
        };

        table.add_row(vec![
            Cell::new(&record.name),
            Cell::new(format_ttl(record.ttl)).set_alignment(CellAlignment::Right),
            Cell::new(&record.record_type),
            Cell::new(format_record_data(&record.data)),
            Cell::new(trust_cell),
        ]);
    }

    let mut out = table.to_string();
    out.push('\n');
    out
}

/// Strip ASCII control characters from DNS-sourced strings before terminal output (S1).
/// Prevents ANSI/VT escape injection from crafted TXT, CAA, NAPTR records.
fn sanitize_display(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().any(|b| matches!(b, 0..=0x1f | 0x7f)) {
        std::borrow::Cow::Owned(
            s.chars()
                .map(|c| if c.is_ascii_control() { '?' } else { c })
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

pub fn format_record_data(data: &RecordData) -> String {
    match data {
        RecordData::A(ip) => ip.clone(),
        RecordData::Aaaa(ip) => ip.clone(),
        RecordData::Cname(name) => name.clone(),
        RecordData::Mx { priority, exchange } => format!("{priority} {exchange}"),
        RecordData::Ns(name) => name.clone(),
        RecordData::Txt(strings) => strings
            .iter()
            .map(|s| sanitize_display(s).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
        RecordData::Soa {
            mname,
            rname,
            serial,
            ..
        } => format!("{mname} {rname} {serial}"),
        RecordData::Ptr(name) => name.clone(),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        RecordData::Dnskey {
            flags,
            protocol: _,
            algorithm,
            public_key,
        } => {
            let key_preview = if public_key.len() > 20 {
                format!("{}…", &public_key[..20])
            } else {
                public_key.clone()
            };
            format!("flags={flags} alg={algorithm} key={key_preview}")
        }
        RecordData::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            let digest_preview = if digest.len() > 16 {
                format!("{}…", &digest[..16])
            } else {
                digest.clone()
            };
            format!("tag={key_tag} alg={algorithm} dtype={digest_type} {digest_preview}")
        }
        RecordData::Rrsig {
            type_covered,
            key_tag,
            signer_name,
            ..
        } => format!("{type_covered} tag={key_tag} signer={signer_name}"),
        RecordData::Caa { flags, tag, value } => {
            format!("{flags} {tag} \"{}\"", sanitize_display(value))
        }
        RecordData::Tlsa {
            usage,
            selector,
            matching_type,
            cert_data,
        } => {
            let preview = if cert_data.len() > 20 {
                format!("{}…", &cert_data[..20])
            } else {
                cert_data.clone()
            };
            format!("usage={usage} sel={selector} type={matching_type} {preview}")
        }
        RecordData::Sshfp {
            algorithm,
            fingerprint_type,
            fingerprint,
        } => format!("alg={algorithm} type={fingerprint_type} {fingerprint}"),
        RecordData::Https { priority, target, params } => {
            if params.is_empty() {
                format!("{priority} {target}")
            } else {
                format!("{priority} {target} {params}")
            }
        }
        RecordData::Svcb { priority, target, params } => {
            if params.is_empty() {
                format!("{priority} {target}")
            } else {
                format!("{priority} {target} {params}")
            }
        }
        RecordData::Naptr { order, preference, flags, services, regexp, replacement } => {
            format!(
                "{order} {preference} \"{}\" \"{}\" \"{}\" {replacement}",
                sanitize_display(flags),
                sanitize_display(services),
                sanitize_display(regexp),
            )
        }
        RecordData::Unknown(s) => sanitize_display(s).into_owned(),
    }
}
