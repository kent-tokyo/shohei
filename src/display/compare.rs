use std::collections::HashSet;

use owo_colors::{OwoColorize, Stream};

use crate::display::table::format_record_data;
use crate::resolver::DnsComparison;

pub fn render_comparison(cmp: &DnsComparison, use_color: bool) -> String {
    let left_set: HashSet<String> = cmp
        .left
        .answers
        .iter()
        .map(|r| format_record_data(&r.data))
        .collect();
    let right_set: HashSet<String> = cmp
        .right
        .answers
        .iter()
        .map(|r| format_record_data(&r.data))
        .collect();

    // Sorted union for deterministic display order
    let mut all: Vec<&String> = left_set.union(&right_set).collect();
    all.sort();

    let mut out = String::new();

    if use_color {
        out.push_str(&format!(
            "\n{} {}\n",
            "Comparing".if_supports_color(Stream::Stdout, |t| t.dimmed()),
            format!("{} {}", cmp.record_type, cmp.domain)
                .if_supports_color(Stream::Stdout, |t| t.bold())
        ));
        out.push_str(&format!(
            "  {}  {}\n\n",
            format!("← {}", cmp.left.server_addr)
                .if_supports_color(Stream::Stdout, |t| t.dimmed()),
            format!("→ {}", cmp.right.server_addr)
                .if_supports_color(Stream::Stdout, |t| t.dimmed()),
        ));
    } else {
        out.push_str(&format!(
            "\nComparing {} {}\n  ← {}  → {}\n\n",
            cmp.record_type, cmp.domain, cmp.left.server_addr, cmp.right.server_addr
        ));
    }

    let mut matches = 0usize;
    for data in &all {
        let in_left = left_set.contains(*data);
        let in_right = right_set.contains(*data);
        match (in_left, in_right) {
            (true, true) => {
                matches += 1;
                out.push_str(&format!("  =  {data}\n"));
            }
            (true, false) => {
                if use_color {
                    out.push_str(&format!(
                        "  {}  {data}  {}\n",
                        "<".if_supports_color(Stream::Stdout, |t| t.yellow()),
                        format!("(only ←{})", cmp.left.server_addr)
                            .if_supports_color(Stream::Stdout, |t| t.dimmed()),
                    ));
                } else {
                    out.push_str(&format!(
                        "  <  {data}  (only ←{})\n",
                        cmp.left.server_addr
                    ));
                }
            }
            (false, true) => {
                if use_color {
                    out.push_str(&format!(
                        "  {}  {data}  {}\n",
                        ">".if_supports_color(Stream::Stdout, |t| t.cyan()),
                        format!("(only →{})", cmp.right.server_addr)
                            .if_supports_color(Stream::Stdout, |t| t.dimmed()),
                    ));
                } else {
                    out.push_str(&format!(
                        "  >  {data}  (only →{})\n",
                        cmp.right.server_addr
                    ));
                }
            }
            _ => unreachable!(),
        }
    }

    let total = all.len();
    let summary = format!(
        "  {}/{} records match  [←{}: {} records, {}ms]  [→{}: {} records, {}ms]",
        matches,
        total,
        cmp.left.server_addr,
        cmp.left.answers.len(),
        cmp.left.duration_ms,
        cmp.right.server_addr,
        cmp.right.answers.len(),
        cmp.right.duration_ms,
    );
    if use_color {
        out.push_str(&format!(
            "\n{}\n",
            summary.if_supports_color(Stream::Stdout, |t| t.dimmed())
        ));
    } else {
        out.push_str(&format!("\n{summary}\n"));
    }

    out
}
