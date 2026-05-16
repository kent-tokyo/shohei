use owo_colors::{OwoColorize, Stream};

use crate::resolver::TrustState;

pub fn paint_trust(text: &str, state: &TrustState) -> String {
    match state {
        TrustState::Secure => format!(
            "{}",
            text.if_supports_color(Stream::Stdout, |t| t.bright_green())
        ),
        TrustState::Insecure => {
            format!("{}", text.if_supports_color(Stream::Stdout, |t| t.yellow()))
        }
        TrustState::Bogus => format!(
            "{}",
            text.if_supports_color(Stream::Stdout, |t| t.bright_red())
        ),
        TrustState::Indeterminate => {
            format!("{}", text.if_supports_color(Stream::Stdout, |t| t.dimmed()))
        }
    }
}

pub fn paint_dim(text: &str) -> String {
    format!("{}", text.if_supports_color(Stream::Stdout, |t| t.dimmed()))
}

pub fn trust_badge(state: &TrustState) -> String {
    let label = match state {
        TrustState::Secure => "✓ SECURE",
        TrustState::Insecure => "⚠ INSECURE",
        TrustState::Bogus => "✗ BOGUS",
        TrustState::Indeterminate => "? INDETERMINATE",
    };
    paint_trust(label, state)
}
