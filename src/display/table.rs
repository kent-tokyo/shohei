use crate::display::colors::{paint_dim, trust_badge};
use crate::resolver::{DnsQueryResult, RecordData};

// ── Simple ASCII table renderer (replaces comfy-table) ─────────────────────

struct SimpleTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    right_align: Vec<bool>,  // true → right-align that column
}

impl SimpleTable {
    fn new(headers: Vec<&str>, right_align: Vec<bool>) -> Self {
        Self {
            headers: headers.iter().map(|s| s.to_string()).collect(),
            rows: Vec::new(),
            right_align,
        }
    }

    fn add_row(&mut self, row: Vec<String>) { self.rows.push(row); }

    fn render(&self) -> String {
        let cols = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate().take(cols) {
                // visible_len strips ANSI escape codes for width calc
                widths[i] = widths[i].max(visible_len(cell));
            }
        }

        let sep: String = widths.iter().map(|&w| "─".repeat(w + 2)).collect::<Vec<_>>().join("┼");
        let top: String = widths.iter().map(|&w| "─".repeat(w + 2)).collect::<Vec<_>>().join("┬");
        let bot: String = widths.iter().map(|&w| "─".repeat(w + 2)).collect::<Vec<_>>().join("┴");

        let mut out = format!("┌{}┐\n", top);
        // Header
        let hcells: Vec<String> = self.headers.iter().enumerate().map(|(i, h)| {
            pad(h, widths[i], false)
        }).collect();
        out.push_str(&format!("│ {} │\n", hcells.join(" │ ")));
        out.push_str(&format!("├{}┤\n", sep));
        // Rows
        for row in &self.rows {
            let cells: Vec<String> = (0..cols).map(|i| {
                let cell = row.get(i).map(|s| s.as_str()).unwrap_or("");
                pad(cell, widths[i], self.right_align.get(i).copied().unwrap_or(false))
            }).collect();
            out.push_str(&format!("│ {} │\n", cells.join(" │ ")));
        }
        out.push_str(&format!("└{}┘", bot));
        out
    }
}

/// Terminal display width of a character per UAX #11 East Asian Width.
/// Returns 0 for control/combining, 2 for CJK/fullwidth, 1 for everything else.
fn char_display_width(c: char) -> usize {
    let cp = c as u32;
    match cp {
        // Control characters and non-spacing marks
        0x0000..=0x001F | 0x007F..=0x009F => 0,
        // Combining diacritical marks (soft hyphen etc.)
        0x00AD | 0x0300..=0x036F | 0x0483..=0x0489 => 0,
        // Wide: Hangul Jamo
        0x1100..=0x115F | 0xA960..=0xA97F | 0xAC00..=0xD7FF => 2,
        // Wide: CJK Radicals, Kangxi, Bopomofo, Hiragana, Katakana, Kana, CJK symbols
        0x2E80..=0x303E | 0x3041..=0x33FF => 2,
        // Wide: CJK Extension A
        0x3400..=0x4DBF => 2,
        // Wide: CJK Unified Ideographs
        0x4E00..=0x9FFF => 2,
        // Wide: Yi Syllables
        0xA000..=0xA4CF => 2,
        // Wide: CJK Compatibility Ideographs
        0xF900..=0xFAFF => 2,
        // Wide: Vertical Forms, CJK Compatibility Forms
        0xFE10..=0xFE19 | 0xFE30..=0xFE4F => 2,
        // Wide: Fullwidth ASCII and halfwidth/fullwidth forms
        0xFF01..=0xFF60 | 0xFFE0..=0xFFE6 => 2,
        // Wide: CJK Extension B through H and compatibility
        0x20000..=0x2FFFD | 0x30000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// Strip ANSI escape codes and compute visible terminal width (handles CJK full-width chars).
fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c == 'm' { in_escape = false; }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            len += char_display_width(c);
        }
    }
    len
}

/// Pad `s` to `width` visible chars. `right` = right-align.
fn pad(s: &str, width: usize, right: bool) -> String {
    let vlen = visible_len(s);
    let padding = width.saturating_sub(vlen);
    if right {
        format!("{}{}", " ".repeat(padding), s)
    } else {
        format!("{}{}", s, " ".repeat(padding))
    }
}

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
    // right_align: NAME=false, TTL=true, TYPE=false, DATA=false, TRUST=false
    let mut table = SimpleTable::new(
        vec!["NAME", "TTL", "TYPE", "DATA", "TRUST"],
        vec![false, true, false, false, false],
    );

    for record in records {
        let trust_cell = if use_color {
            trust_badge(&record.trust)
        } else {
            record.trust.to_string()
        };
        table.add_row(vec![
            record.name.clone(),
            format_ttl(record.ttl),
            record.record_type.clone(),
            format_record_data(&record.data),
            trust_cell,
        ]);
    }

    format!("{}\n", table.render())
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
                format!("{}…", public_key.get(..20).unwrap_or(public_key))
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
                format!("{}…", cert_data.get(..20).unwrap_or(cert_data))
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
