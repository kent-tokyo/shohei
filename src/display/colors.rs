use crate::resolver::TrustState;

const GREEN:  &str = "\x1b[92m";
const YELLOW: &str = "\x1b[33m";
const RED:    &str = "\x1b[91m";
const CYAN:   &str = "\x1b[36m";
const BOLD:   &str = "\x1b[1m";
const DIM:    &str = "\x1b[2m";
const RESET:  &str = "\x1b[0m";

fn color_supported() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

fn colored(text: &str, code: &str) -> String {
    if color_supported() {
        format!("{}{}{}", code, text, RESET)
    } else {
        text.to_string()
    }
}

pub fn paint_trust(text: &str, state: &TrustState) -> String {
    match state {
        TrustState::Secure        => colored(text, GREEN),
        TrustState::Insecure      => colored(text, YELLOW),
        TrustState::Bogus         => colored(text, RED),
        TrustState::Indeterminate => colored(text, DIM),
    }
}

pub fn paint_dim(text: &str) -> String {
    colored(text, DIM)
}

pub fn paint_cyan(text: &str) -> String {
    colored(text, CYAN)
}

pub fn paint_bold(text: &str) -> String {
    colored(text, BOLD)
}

pub fn trust_badge(state: &TrustState) -> String {
    let label = match state {
        TrustState::Secure        => "✓ SECURE",
        TrustState::Insecure      => "⚠ INSECURE",
        TrustState::Bogus         => "✗ BOGUS",
        TrustState::Indeterminate => "? INDETERMINATE",
    };
    paint_trust(label, state)
}
