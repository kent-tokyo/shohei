use ptree::{print_tree, TreeItem};
use std::borrow::Cow;
use std::io;

use crate::display::colors::trust_badge;
use crate::dnssec::chain::DnssecChain;
use crate::resolver::iterative::{ResolutionTrace, StepResponseType};

// --- DNSSEC tree ---

#[derive(Clone)]
struct DnssecNode {
    label: String,
    children: Vec<DnssecNode>,
}

impl DnssecNode {
    fn from_chain(chain: &DnssecChain) -> Self {
        let root_children: Vec<DnssecNode> = chain
            .steps
            .iter()
            .map(|step| DnssecNode {
                label: format!(
                    "{} [{}] {} — {}",
                    trust_badge(&step.status),
                    step.step_type,
                    step.label,
                    step.detail,
                ),
                children: vec![],
            })
            .collect();

        DnssecNode {
            label: format!("DNSSEC chain for {}", chain.domain),
            children: root_children,
        }
    }
}

impl TreeItem for DnssecNode {
    type Child = DnssecNode;

    fn write_self<W: io::Write>(&self, f: &mut W, _style: &ptree::Style) -> io::Result<()> {
        write!(f, "{}", self.label)
    }

    fn children(&self) -> Cow<[Self::Child]> {
        Cow::Borrowed(&self.children)
    }
}

pub fn print_dnssec_chain(chain: &DnssecChain) {
    println!(
        "\nDNSSEC Chain of Trust: {} — {}\n",
        chain.domain,
        trust_badge(&chain.overall)
    );
    let root = DnssecNode::from_chain(chain);
    let _ = print_tree(&root);
    println!();
}

// --- Resolution trace tree ---

#[derive(Clone)]
struct TraceNode {
    label: String,
    children: Vec<TraceNode>,
}

impl TraceNode {
    fn from_trace(trace: &ResolutionTrace) -> Self {
        let children: Vec<TraceNode> = trace
            .steps
            .iter()
            .map(|step| {
                let status = match &step.response_type {
                    StepResponseType::Answer => "✓ ANSWER".to_string(),
                    StepResponseType::Referral => "→ REFERRAL".to_string(),
                    StepResponseType::Nxdomain => "✗ NXDOMAIN".to_string(),
                    StepResponseType::Error(e) => format!("✗ ERROR: {e}"),
                };

                let referral_info = step
                    .referral_to
                    .as_ref()
                    .map(|ns| format!(" → [{}]", ns.join(", ")))
                    .unwrap_or_default();

                TraceNode {
                    label: format!(
                        "{} {} ({}) {}ms{}",
                        status, step.server_name, step.server_addr, step.duration_ms, referral_info,
                    ),
                    children: vec![],
                }
            })
            .collect();

        TraceNode {
            label: format!("Trace: {} {}", trace.record_type, trace.target),
            children,
        }
    }
}

impl TreeItem for TraceNode {
    type Child = TraceNode;

    fn write_self<W: io::Write>(&self, f: &mut W, _style: &ptree::Style) -> io::Result<()> {
        write!(f, "{}", self.label)
    }

    fn children(&self) -> Cow<[Self::Child]> {
        Cow::Borrowed(&self.children)
    }
}

pub fn print_resolution_trace(trace: &ResolutionTrace) {
    println!("\nIterative Resolution Trace\n");
    let root = TraceNode::from_trace(trace);
    let _ = print_tree(&root);
    println!();
}
