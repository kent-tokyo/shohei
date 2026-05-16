use crate::display::colors::trust_badge;
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::{ResolutionTrace, StepResponseType};

/// Render DNSSEC chain as a colored tree string (used by ColoredRenderer).
pub fn render_dnssec_tree(chain: &DnssecChain) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\nDNSSEC Chain of Trust: {} — {}\n\n",
        chain.domain,
        trust_badge(&chain.overall)
    ));
    for (i, step) in chain.steps.iter().enumerate() {
        let indent = if i == 0 { "" } else { "  " };
        let connector = if i == 0 { "" } else { "└─ " };
        out.push_str(&format!(
            "{}{}{} [{}] {} — {}\n",
            indent,
            connector,
            trust_badge(&step.status),
            step.step_type,
            step.label,
            step.detail
        ));
    }
    out.push('\n');
    out
}

/// Render iterative trace as an indented tree string (used by ColoredRenderer).
pub fn render_trace_tree(trace: &ResolutionTrace) -> String {
    let mut out = String::new();
    out.push_str(&format!(
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
        out.push_str(&format!(
            "{}[{}] {} @ {} ({}ms)\n",
            indent, status, step.server_name, step.server_addr, step.duration_ms
        ));
        if let Some(refs) = &step.referral_to {
            out.push_str(&format!(
                "{}    → Referred to: {}\n",
                indent,
                refs.join(", ")
            ));
        }
    }

    if let Some(msg) = &trace.truncated {
        out.push_str(&format!("\n⚠ {msg}\n"));
    }

    out.push('\n');
    out
}
