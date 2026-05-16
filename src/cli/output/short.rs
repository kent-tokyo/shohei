use std::collections::BTreeSet;

use crate::cli::output::Render;
use crate::display::table::format_record_data;
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::ResolutionTrace;
use crate::resolver::{DnsComparison, DnsQueryResult};

pub struct ShortRenderer;

impl Render for ShortRenderer {
    fn render_records(&self, result: &DnsQueryResult) -> String {
        if result.answers.is_empty() {
            return String::new();
        }
        result
            .answers
            .iter()
            .map(|r| format_record_data(&r.data))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    fn render_trace(&self, trace: &ResolutionTrace) -> String {
        trace
            .steps
            .iter()
            .map(|s| format!("{} {}", s.response_type.label(), s.server_name))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    fn render_dnssec(&self, chain: &DnssecChain) -> String {
        format!("{}\n", chain.overall)
    }

    fn render_compare(&self, cmp: &DnsComparison) -> String {
        let left: BTreeSet<String> = cmp.left.answers.iter().map(|r| format_record_data(&r.data)).collect();
        let right: BTreeSet<String> = cmp.right.answers.iter().map(|r| format_record_data(&r.data)).collect();
        let mut lines: Vec<String> = Vec::new();
        for v in left.intersection(&right) {
            lines.push(format!("= {v}"));
        }
        for v in left.difference(&right) {
            lines.push(format!("< {v}"));
        }
        for v in right.difference(&left) {
            lines.push(format!("> {v}"));
        }
        if lines.is_empty() {
            return String::new();
        }
        lines.join("\n") + "\n"
    }
}
