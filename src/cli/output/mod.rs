use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::ResolutionTrace;
use crate::resolver::DnsQueryResult;

pub mod json;
pub mod plain;
pub mod table;

pub trait Render {
    fn render_records(&self, result: &DnsQueryResult) -> String;
    fn render_trace(&self, trace: &ResolutionTrace) -> String;
    fn render_dnssec(&self, chain: &DnssecChain) -> String;
}
