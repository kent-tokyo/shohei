use crate::cli::output::Render;
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::ResolutionTrace;
use crate::resolver::{DnsComparison, DnsQueryResult};

pub struct JsonRenderer;

fn json_error(e: &serde_json::Error) -> String {
    let msg = serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"serialization error\"".to_string());
    format!("{{\"error\": {msg}}}")
}

impl Render for JsonRenderer {
    fn render_records(&self, result: &DnsQueryResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|e| json_error(&e))
    }

    fn render_trace(&self, trace: &ResolutionTrace) -> String {
        serde_json::to_string_pretty(trace).unwrap_or_else(|e| json_error(&e))
    }

    fn render_dnssec(&self, chain: &DnssecChain) -> String {
        serde_json::to_string_pretty(chain).unwrap_or_else(|e| json_error(&e))
    }

    fn render_compare(&self, cmp: &DnsComparison) -> String {
        serde_json::to_string_pretty(cmp).unwrap_or_else(|e| json_error(&e))
    }
}
