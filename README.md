# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)

**shohei** is a next-generation DNS diagnostic CLI for the terminal. It goes beyond a simple `dig` replacement — it visualizes the full **DNSSEC chain of trust**, iterative resolution paths from root servers, and supports modern transports like **DNS-over-HTTPS (DoH)** and **DNS-over-TLS (DoT)**.

## Why shohei?

Modern DNS is complex. DNSSEC, DoH, DoT, and layered trust chains make troubleshooting difficult with traditional tools. `shohei` renders the entire chain — from root KSK to the final answer — as a color-coded tree directly in your terminal.

```
DNSSEC Chain of Trust: cloudflare.com — ✓ SECURE

shohei — DNSSEC chain for cloudflare.com
├── [Trust Anchor] . — Root KSK trust anchor (RFC 8509)           ✓ SECURE
├── [DS] com. — DS record delegates trust to com.                  ✓ SECURE
├── [DNSKEY] com. — DNSKEY RRset verified for com.                ✓ SECURE
├── [DS] cloudflare.com. — DS record delegates trust               ✓ SECURE
├── [DNSKEY] cloudflare.com. — DNSKEY RRset verified              ✓ SECURE
├── [RRSIG] cloudflare.com — RRSIG covers the answer RRset        ✓ SECURE
└── [Answer] cloudflare.com — chain validation complete           ✓ SECURE
```

## Installation

```bash
cargo install shohei
```

Or download a pre-built binary from the [releases page](https://github.com/kent-tokyo/shohei/releases).

## Usage

```bash
# Basic A record query
shohei google.com

# Query a specific record type
shohei google.com --type MX

# Validate DNSSEC chain of trust
shohei cloudflare.com --dnssec

# Trace iterative resolution from root servers
shohei google.com --trace

# Use DNS-over-HTTPS
shohei google.com --doh https://dns.google/dns-query

# Use DNS-over-TLS
shohei google.com --dot 1.1.1.1:853

# Use a custom resolver
shohei google.com --server 8.8.8.8

# JSON output for scripting
shohei google.com --output json

# No colors (CI-friendly)
shohei google.com --output plain
```

## Options

| Flag | Short | Description |
|------|-------|-------------|
| `--type <TYPE>` | `-t` | Record type: `a`, `aaaa`, `mx`, `ns`, `txt`, `cname`, `soa`, `ptr`, `srv`, `dnskey`, `ds`, `rrsig`, `any` |
| `--dnssec` | `-d` | Show DNSSEC chain-of-trust validation tree |
| `--trace` | | Show iterative resolution path from root servers |
| `--doh <URL>` | | Use DNS-over-HTTPS (e.g. `https://dns.google/dns-query`) |
| `--dot <HOST:PORT>` | | Use DNS-over-TLS (e.g. `1.1.1.1:853`) |
| `--server <ADDR>` | `-s` | Custom DNS server address |
| `--output <FORMAT>` | `-o` | Output format: `colored` (default), `plain`, `json` |

## Trust States

| Badge | Meaning |
|-------|---------|
| `✓ SECURE` | DNSSEC-validated, full chain of trust verified |
| `⚠ INSECURE` | Zone is not signed, but parent has no DS record (expected) |
| `✗ BOGUS` | Validation failed — signature mismatch or chain broken |
| `? INDETERMINATE` | Validation not requested or result unclear |

## Built with

- [hickory-dns](https://hickory-dns.org/) — DNSSEC, DoH, DoT support
- [clap](https://crates.io/crates/clap) — CLI argument parsing
- [ratatui](https://ratatui.rs/) — TUI framework (optional feature)
- [owo-colors](https://crates.io/crates/owo-colors) — Terminal colors

## License

MIT — see [LICENSE](LICENSE)
