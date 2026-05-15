use crate::cli::output::Render;
use crate::display::colors::trust_badge;
use crate::display::table as display_table;
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::{ResolutionTrace, StepResponseType};
use crate::resolver::DnsQueryResult;

pub struct ColoredRenderer;

impl Render for ColoredRenderer {
    fn render_records(&self, result: &DnsQueryResult) -> String {
        display_table::render_result(result, true)
    }

    fn render_trace(&self, trace: &ResolutionTrace) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\nIterative Resolution Trace: {} {}\n\n",
            trace.record_type, trace.target
        ));
        for (i, step) in trace.steps.iter().enumerate() {
            let status = match &step.response_type {
                StepResponseType::Answer => "✓ ANSWER",
                StepResponseType::Referral => "→ REFERRAL",
                StepResponseType::Nxdomain => "✗ NXDOMAIN",
                StepResponseType::Error(_) => "✗ ERROR",
            };
            let indent = "  ".repeat(i);
            output.push_str(&format!(
                "{}[{}] {} @ {} ({}ms)\n",
                indent, status, step.server_name, step.server_addr, step.duration_ms
            ));
            if let Some(refs) = &step.referral_to {
                output.push_str(&format!(
                    "{}    → Referred to: {}\n",
                    indent,
                    refs.join(", ")
                ));
            }
        }
        output
    }

    fn render_dnssec(&self, chain: &DnssecChain) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "\nDNSSEC Chain of Trust: {} — {}\n\n",
            chain.domain,
            trust_badge(&chain.overall)
        ));
        for (i, step) in chain.steps.iter().enumerate() {
            let indent = if i == 0 { "" } else { "  " };
            let connector = if i == 0 { "" } else { "└─ " };
            output.push_str(&format!(
                "{}{}{} [{}] {} — {}\n",
                indent,
                connector,
                trust_badge(&step.status),
                step.step_type,
                step.label,
                step.detail
            ));
        }
        output.push('\n');
        output
    }
}
