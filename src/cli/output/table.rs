use crate::cli::output::Render;
use crate::display::compare;
use crate::display::table as display_table;
use crate::display::tree::{render_dnssec_tree, render_trace_tree};
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::ResolutionTrace;
use crate::resolver::{DnsComparison, DnsMultiQuery, DnsQueryResult};

pub struct ColoredRenderer;

impl Render for ColoredRenderer {
    fn render_records(&self, result: &DnsQueryResult) -> String {
        display_table::render_result(result, true)
    }

    fn render_trace(&self, trace: &ResolutionTrace) -> String {
        render_trace_tree(trace)
    }

    fn render_dnssec(&self, chain: &DnssecChain) -> String {
        render_dnssec_tree(chain)
    }

    fn render_compare(&self, cmp: &DnsComparison) -> String {
        compare::render_comparison(cmp, true)
    }

    fn render_multi(&self, multi: &DnsMultiQuery) -> String {
        compare::render_multi_query(multi, true)
    }
}
