//! shohei — Rust library for infrastructure reachability diagnostics.
//!
//! Validates the complete **trust chain** from DNS through DNSSEC to TLS,
//! designed for automation, AI agents, and embedded use in other tools.
//!
//! # Quick start
//!
//! Start with the [`api`] module for library usage:
//!
//! ```rust,no_run
//! use shohei::api::{check_dns, DnsCheckRequest};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let results = check_dns(&DnsCheckRequest {
//!     domain: "example.com".to_string(),
//!     ..Default::default()
//! }).await?;
//! println!("Got {} answers", results[0].answers.len());
//! # Ok(())
//! # }
//! ```
//!
//! # Modules
//!
//! - [`api`] — High-level library API (start here for library consumers)
//! - [`resolver`] — Low-level DNS query types and functions
//! - [`dnssec`] — DNSSEC chain-of-trust validation
//! - [`transport`] — DoH / DoT / DoQ transport backends
//! - [`error`] — Error types
//! - [`cli`] — Command-line interface (internal)
//! - [`display`] — Output formatting for terminal display (internal)

pub mod api;
pub mod cli;
pub mod display;
pub mod dnssec;
pub mod error;
pub mod resolver;
pub mod transport;
#[cfg(feature = "tui")]
pub mod tui;
