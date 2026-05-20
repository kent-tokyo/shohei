use crate::cli::output::Render;
use crate::display::table as display_table;
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::ResolutionTrace;
use crate::resolver::DnsQueryResult;

pub struct PlainRenderer;

impl Render for PlainRenderer {
    fn render_records(&self, result: &DnsQueryResult) -> String {
        display_table::render_result(result, false)
    }

    fn render_trace(&self, trace: &ResolutionTrace) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\nIterative Resolution Trace: {} {}\n\n",
            trace.record_type, trace.target
        ));
        for (i, step) in trace.steps.iter().enumerate() {
            let status = step.response_type.label();
            let indent = "  ".repeat(i);
            output.push_str(&format!(
                "{}[{}] {} @ {} ({}ms)\n",
                indent, status, step.server_name, step.server_addr, step.duration_ms
            ));
            if let Some(refs) = &step.referral_to {
                output.push_str(&format!("{}    Referred to: {}\n", indent, refs.join(", ")));
            }
        }
        if let Some(msg) = &trace.truncated {
            output.push_str(&format!("\nWARNING: {msg}\n"));
        }
        output
    }

    fn render_dnssec(&self, chain: &DnssecChain) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\nDNSSEC Chain of Trust: {} [{}]\n\n",
            chain.domain, chain.overall
        ));
        for (i, step) in chain.steps.iter().enumerate() {
            let indent = if i == 0 { "" } else { "  " };
            let connector = if i == 0 { "" } else { "- " };
            output.push_str(&format!(
                "{}{}[{}] {} ({}) — {}\n",
                indent, connector, step.status, step.label, step.step_type, step.detail
            ));
            for line in &step.verbose_lines {
                output.push_str(&format!("{}   {line}\n", indent));
            }
        }
        output.push('\n');
        output
    }
}
