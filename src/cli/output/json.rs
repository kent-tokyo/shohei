use crate::cli::output::Render;
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::ResolutionTrace;
use crate::resolver::DnsQueryResult;

pub struct JsonRenderer;

impl Render for JsonRenderer {
    fn render_records(&self, result: &DnsQueryResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    fn render_trace(&self, trace: &ResolutionTrace) -> String {
        serde_json::to_string_pretty(trace).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    fn render_dnssec(&self, chain: &DnssecChain) -> String {
        serde_json::to_string_pretty(chain).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}
