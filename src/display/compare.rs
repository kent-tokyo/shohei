use std::collections::HashSet;

use crate::display::colors::{paint_bold, paint_cyan, paint_dim};
use crate::display::table::{format_record_data, render_result};
use crate::resolver::{DnsComparison, DnsMultiQuery};

pub fn render_multi_query(multi: &DnsMultiQuery, use_color: bool) -> String {
    let mut out = String::new();
    if use_color {
        out.push_str(&format!(
            "\n{} {} {}\n",
            paint_dim("Multi-server query:"),
            paint_bold(&format!("{} {}", multi.record_type, multi.domain)),
            paint_dim(&format!("({} servers)", multi.results.len())),
        ));
    } else {
        out.push_str(&format!(
            "\nMulti-server query: {} {} ({} servers)\n",
            multi.record_type, multi.domain, multi.results.len()
        ));
    }
    for result in &multi.results {
        if use_color {
            out.push_str(&format!("\n{}\n", paint_cyan(&format!("─── {} ───", result.server_addr))));
        } else {
            out.push_str(&format!("\n--- {} ---\n", result.server_addr));
        }
        out.push_str(&render_result(result, use_color));
    }
    out
}

pub fn render_comparison(cmp: &DnsComparison, use_color: bool) -> String {
    let left_set: HashSet<String> = cmp.left.answers.iter()
        .map(|r| format_record_data(&r.data)).collect();
    let right_set: HashSet<String> = cmp.right.answers.iter()
        .map(|r| format_record_data(&r.data)).collect();

    let mut all: Vec<&String> = left_set.union(&right_set).collect();
    all.sort();

    let mut out = String::new();

    if use_color {
        out.push_str(&format!(
            "\n{} {}\n  {}  {}\n\n",
            paint_dim("Comparing"),
            paint_bold(&format!("{} {}", cmp.record_type, cmp.domain)),
            paint_dim(&format!("← {}", cmp.left.server_addr)),
            paint_dim(&format!("→ {}", cmp.right.server_addr)),
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
                        "\x1b[33m<\x1b[0m",
                        paint_dim(&format!("(only ←{})", cmp.left.server_addr)),
                    ));
                } else {
                    out.push_str(&format!("  <  {data}  (only ←{})\n", cmp.left.server_addr));
                }
            }
            (false, true) => {
                if use_color {
                    out.push_str(&format!(
                        "  {}  {data}  {}\n",
                        paint_cyan(">"),
                        paint_dim(&format!("(only →{})", cmp.right.server_addr)),
                    ));
                } else {
                    out.push_str(&format!("  >  {data}  (only →{})\n", cmp.right.server_addr));
                }
            }
            _ => unreachable!(),
        }
    }

    let summary = format!(
        "  {}/{} records match  [←{}: {} records, {}ms]  [→{}: {} records, {}ms]",
        matches, all.len(),
        cmp.left.server_addr, cmp.left.answers.len(), cmp.left.duration_ms,
        cmp.right.server_addr, cmp.right.answers.len(), cmp.right.duration_ms,
    );
    if use_color {
        out.push_str(&format!("\n{}\n", paint_dim(&summary)));
    } else {
        out.push_str(&format!("\n{summary}\n"));
    }

    out
}
