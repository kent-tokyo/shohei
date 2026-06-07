//! Next-generation DNS diagnostic CLI library.
//!
//! Visualize DNSSEC chain-of-trust, DoH/DoT/DoQ transports, and
//! iterative resolution paths in the terminal.

pub mod cli;
pub mod display;
pub mod dnssec;
pub mod error;
pub mod resolver;
pub mod transport;
#[cfg(feature = "tui")]
pub mod tui;
