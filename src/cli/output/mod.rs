use crate::display::compare;
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::ResolutionTrace;
use crate::resolver::{DnsComparison, DnsQueryResult};

pub mod json;
pub mod plain;
pub mod short;
pub mod table;

pub trait Render {
    fn render_records(&self, result: &DnsQueryResult) -> String;
    fn render_trace(&self, trace: &ResolutionTrace) -> String;
    fn render_dnssec(&self, chain: &DnssecChain) -> String;

    /// Default: plain-text diff. Override in ColoredRenderer for colored output.
    fn render_compare(&self, cmp: &DnsComparison) -> String {
        compare::render_comparison(cmp, false)
    }
}
