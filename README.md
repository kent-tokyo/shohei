# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)

[日本語](README_ja.md) | [中文](README_zh.md)

**shohei** is a next-generation DNS diagnostic CLI. Where `dig` shows raw records, shohei visualizes the complete picture: the **DNSSEC chain of trust** from root to answer, the iterative resolution path hop-by-hop, and modern transports (DoH / DoT) — all rendered as color-coded trees in your terminal.

- **DNSSEC chain tree** — see every DS, DNSKEY, and trust step from `.` to your domain
- **Iterative resolution trace** — watch queries travel from root servers to TLD to authoritative NS
- **Server comparison** — diff two resolvers side-by-side with `--compare`
- **DoH and DoT** — DNS-over-HTTPS and DNS-over-TLS built in
- **JSON output** — pipe-friendly for scripting and automation
- **Watch mode** — auto-refresh at a set interval with `--watch`
- **Short output** — data values only, one per line, with `--short`
- **Interactive TUI** — browse records, DNSSEC chain, and trace in a single terminal window (`--features tui`)

## Why shohei?

| Feature | shohei | dig | dog |
|---------|:------:|:---:|:---:|
| Colored table output | ✓ | | ✓ |
| DNSSEC chain-of-trust tree | **✓** | | |
| Iterative resolution trace | **✓** | | |
| Two-server comparison (`--compare`) | **✓** | | |
| Watch / auto-refresh (`--watch`) | **✓** | | |
| Short / script-friendly output (`--short`) | **✓** | | |
| DNS-over-HTTPS (DoH) | ✓ | ✓ | ✓ |
| DNS-over-TLS (DoT) | ✓ | ✓ | ✓ |
| JSON output | ✓ | | ✓ |
| Interactive TUI | **✓** | | |

![DNSSEC chain of trust](images/demo_dnssec.svg)

## Installation

```bash
cargo install shohei
```

For the interactive TUI mode:

```bash
cargo install shohei --features tui
```

Or download a pre-built binary from the [releases page](https://github.com/kent-tokyo/shohei/releases).

## Usage

### DNS record query

```bash
shohei google.com              # A records (default)
shohei google.com --type AAAA  # AAAA records
shohei google.com --type NS    # Nameservers
shohei gmail.com  --type MX    # Mail exchangers
```

![DNS record query](images/demo_basic.svg)

![MX records](images/demo_mx.svg)

### DNSSEC chain of trust

Validate the full DNSSEC chain from the root trust anchor down to the target domain.
Each zone's DS and DNSKEY records are checked individually.

```bash
shohei cloudflare.com --dnssec
```

![DNSSEC chain of trust](images/demo_dnssec.svg)

### Iterative resolution trace

Step through the full resolution path — root servers → TLD nameservers → authoritative nameservers.

```bash
shohei google.com --trace
```

![Iterative resolution trace](images/demo_trace.svg)

### Modern transports

```bash
# DNS-over-HTTPS
shohei google.com --doh https://dns.google/dns-query

# DNS-over-TLS
shohei google.com --dot 1.1.1.1:853

# Custom resolver
shohei google.com --server 8.8.8.8
```

### Short output

Strip all decoration and return just the record data — one value per line. Ideal for shell scripting.

```bash
shohei gmail.com --type MX --short
```

![Short output](images/demo_short.svg)

### Compare two resolvers

Query the same domain from two DNS servers simultaneously and diff the results. Useful for detecting CDN anycast differences or verifying a new resolver.

```bash
# Show that both servers return the same NS records
shohei cloudflare.com --type NS --server 8.8.8.8 --compare 1.1.1.1

# Reveal CDN-induced A record differences
shohei google.com --server 8.8.8.8 --compare 1.1.1.1
```

![Compare — matching](images/demo_compare_match.svg)

![Compare — diverging](images/demo_compare_diff.svg)

### Watch mode

Repeat the query every N seconds and auto-refresh the display. Press Ctrl+C to stop.

```bash
shohei google.com --watch 5         # refresh every 5 seconds
shohei google.com --type A --watch 10
```

### Output formats

```bash
shohei google.com --output json   # JSON for scripting
shohei google.com --output plain  # No colors (CI-friendly)
```

### Interactive TUI (requires `--features tui`)

Pre-loads records, DNSSEC chain, and trace in parallel, then presents all three as navigable views.

```bash
shohei google.com --tui
```

```
 shohei — google.com
┌─ Records ──────────────────────────────────────────────────────────┐
│ Query: google.com (A IN)                                           │
│                                                                    │
│ NAME                                    TTL   TYPE   DATA          │
│ ────────────────────────────────────────────────────────────────── │
│ google.com.                             120   A      142.250.x.x   │
│ ...                                                                │
└────────────────────────────────────────────────────────────────────┘
 [r] Records  [d] DNSSEC  [t] Trace  [↑↓/jk] Scroll  [q] Quit
```

| Key | Action |
|-----|--------|
| `r` | Records view |
| `d` | DNSSEC chain view |
| `t` | Iterative trace view |
| `↑` / `k` | Scroll up |
| `↓` / `j` | Scroll down |
| `q` / `Esc` | Quit |

## Options

| Flag | Short | Description |
|------|-------|-------------|
| `--type <TYPE>` | `-t` | Record type: `a`, `aaaa`, `mx`, `ns`, `txt`, `cname`, `soa`, `ptr`, `srv`, `dnskey`, `ds`, `rrsig`, `any` |
| `--dnssec` | `-d` | DNSSEC chain-of-trust validation tree |
| `--trace` | | Iterative resolution path from root servers |
| `--short` | | Output data values only, one per line (script-friendly) |
| `--watch <SECS>` | | Repeat query every N seconds; Ctrl+C to stop |
| `--compare <ADDR>` | | Query a second server and diff the results |
| `--doh <URL>` | | DNS-over-HTTPS (e.g. `https://dns.google/dns-query`) |
| `--dot <IP:PORT>` | | DNS-over-TLS (e.g. `1.1.1.1:853`) |
| `--server <ADDR>` | `-s` | Custom DNS server (`8.8.8.8` or `8.8.8.8:53`) |
| `--output <FORMAT>` | `-o` | `colored` (default) · `plain` · `json` |
| `--tui` | | Interactive TUI (requires `--features tui`) |

## Trust States

| Badge | Meaning |
|-------|---------|
| `✓ SECURE` | DNSSEC-validated, full chain of trust verified |
| `⚠ INSECURE` | Zone unsigned, but parent has no DS delegation (expected) |
| `✗ BOGUS` | Validation failed — signature mismatch or broken chain |
| `? INDETERMINATE` | DNSSEC not requested, or result unclear |

## Built with

- [hickory-dns](https://hickory-dns.org/) — DNSSEC, DoH, DoT support
- [clap](https://crates.io/crates/clap) — CLI argument parsing
- [ratatui](https://ratatui.rs/) — TUI framework (optional `tui` feature)
- [owo-colors](https://crates.io/crates/owo-colors) — Terminal colors
- [comfy-table](https://crates.io/crates/comfy-table) — Record table rendering

## License

MIT — see [LICENSE](LICENSE)
