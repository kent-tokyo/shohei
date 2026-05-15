use comfy_table::{Cell, CellAlignment, Table};

use crate::display::colors::{paint_dim, trust_badge};
use crate::resolver::{DnsQueryResult, RecordData};

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
        return output;
    }

    let mut table = Table::new();
    table.set_header(vec!["NAME", "TTL", "TYPE", "DATA", "TRUST"]);

    for record in &result.answers {
        let trust_cell = if use_color {
            trust_badge(&record.trust)
        } else {
            record.trust.to_string()
        };

        table.add_row(vec![
            Cell::new(&record.name),
            Cell::new(record.ttl.to_string()).set_alignment(CellAlignment::Right),
            Cell::new(&record.record_type),
            Cell::new(format_record_data(&record.data)),
            Cell::new(trust_cell),
        ]);
    }

    output.push_str(&table.to_string());
    output.push('\n');

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

pub fn format_record_data(data: &RecordData) -> String {
    match data {
        RecordData::A(ip) => ip.clone(),
        RecordData::Aaaa(ip) => ip.clone(),
        RecordData::Cname(name) => name.clone(),
        RecordData::Mx { priority, exchange } => format!("{priority} {exchange}"),
        RecordData::Ns(name) => name.clone(),
        RecordData::Txt(strings) => strings.join(" "),
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
        RecordData::Unknown(s) => s.clone(),
    }
}
