# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-06-10

### Added
- **MCP tools expansion** — Exposed 3 previously-private library functions as new MCP tools:
  - `check_dnssec` — Full DNSSEC chain-of-trust validation with configurable resolver
  - `trace_resolution` — Iterative resolution trace from root to authoritative nameserver
  - `check_propagation` — Custom propagation check with user-supplied resolver list
- **Enhanced propagation checking** — `check_propagation_global` now accepts `record_type` parameter to check AAAA, MX, TXT propagation (was hardcoded to A records)
- **Improved latency benchmarking** — `benchmark_latency` MCP tool now respects user-supplied `transports` parameter (System/DoH/DoT/DoQ/IP); previously ignored

### Fixed
- **Email security details** — DKIM check results now populate `raw` field with actual TXT record value (was always `None`)
- **Benchmark transport parameter** — `benchmark_latency` MCP tool was silently ignoring `transports` argument; now parses and uses custom transport list

## [0.5.0] - 2026-06-07

### Added
- **Library-first API redesign** — Pure async functions (`check_dns`, `check_tls_chain`, `check_email_security`, `check_propagation`, `benchmark_latency`) with serializable request/response types for AI agent consumption
- **TLS certificate chain inspection** — `check_tls_chain()` captures leaf + intermediate certificates via TLS handshake; parses CN, SANs, issuer, validity dates with x509-parser
- **Full DANE/TLSA RFC 6698 matching** — Support all 6 selector/matching_type combinations (selector 0/1 × matching_type 0/1/2); extracts SubjectPublicKeyInfo DER via `cert.public_key().raw`; SHA256/SHA512 hash validation with sha2 crate
- **Email security validator** — `check_email_security()` checks MX records, SPF, DKIM (4 common selectors), and DMARC; computes security score (0-100)
- **DNS propagation checker** — `check_propagation()` queries domain across custom resolver list; `check_propagation_global()` convenience function tests against 6 global resolvers (Google, Cloudflare, Quad9, OpenDNS, CleanBrowsing, Comodo)
- **Multi-protocol latency benchmarking** — `benchmark_latency()` measures DNS query latency across System/DoH/DoT/DoQ transports; reports min/max/avg/success_rate per round
- **MCP server (shohei-mcp)** — Expose all library APIs as Model Context Protocol tools for Claude and other AI agents; implements JSON-RPC 2.0 over stdio; 5 tools: check_dns, check_tls_chain, check_email_security, check_propagation_global, benchmark_latency

### Changed
- **Transport abstraction** — Added `Transport` enum (System, Server, Doh, Dot, Doq) with serialization support for JSON-RPC/AI integration
- **API module restructure** — `src/api/` now a directory with `mod.rs` (core), `tls.rs`, `propagation.rs`, `email.rs`, `bench.rs` for scalability
- **Documentation** — Updated lib.rs and module docstrings to emphasize library-first usage; CLI is now a thin demo wrapper

### Dependencies
- **New**: `x509-parser` 0.16 (cert field parsing), `sha2` 0.10 (TLSA hash matching), `hex` 0.4 (hex encoding), `rmcp` 1.7 (MCP server framework)
- **Promoted to direct**: `rustls` 0.23 (was transitive), `tokio-rustls` 0.26 (was transitive)

## [0.4.0] - 2026-05-26

### Performance
- **DNSSEC chain parallelization** — per-zone DS and DNSKEY queries now run concurrently via `join_all`; overall trust determination launches at the same time as zone queries; typical 3-zone chain (`.` → `com.` → `domain.`) validates up to ~2× faster
- **Multi-type concurrent queries** — `--type a --type aaaa --type mx` now issues all record-type queries in parallel; transport config (DoH/DoT/DoQ) is built once and reused across types via `Clone`
- **Parallel unglued NS resolution** — iterative trace resolves all unglued nameservers concurrently instead of sequentially (up to 5 in parallel)
- **`hex_encode` micro-optimization** — replaced per-byte `format!("{:02x}")` with a pre-computed lookup table (`String::with_capacity` + direct write); ~5× throughput for DNSKEY, TLSA, SSHFP, and DS record data rendering

### Changed (internal)
- **`main.rs` dispatch refactoring** — extracted `dispatch_axfr`, `dispatch_compare_two`, `dispatch_compare_nway`, `dispatch_trace`, `dispatch_dnssec`, `dispatch_standard` functions; `run_once` is now a clean ~20-line dispatcher
- **Batch deduplication** — file-mode and stdin batch paths unified into a single `run_batch()` helper; eliminates ~30 lines of duplicated code
- **`build_non_validating_resolver` extracted** — DNSSEC chain builder now uses a dedicated helper instead of inlining resolver construction

## [0.3.0] - 2026-05-21

### Added
- **`--doq <IP:PORT>`** — DNS-over-QUIC transport (`quic-ring` feature)
- **`--axfr`** — Full zone transfer over a dedicated raw TCP connection; requires `-s`; caps at 500,000 records; validates SOA serial per RFC 5936
- **N-way `--compare`** — `--compare` can now be specified multiple times for 3+ server comparison; all queries run in parallel; per-server failures warn and continue
- **`-4` / `-6`** — Force IPv4-only or IPv6-only transport
- **`-f <FILE>` / `--file <FILE>`** — Read domains from a file (one per line), like `dig -f`
- **HTTPS, SVCB, NAPTR record types** — added to `--type`; structured display and JSON support

### Fixed
- **S1** — Sanitize ASCII control characters (`0x00–0x1f`, `0x7f`) in DNS TXT, CAA, NAPTR, and Unknown record data before terminal output; prevents ANSI/VT escape injection
- **S2** — AXFR zone transfer capped at 500,000 records to prevent memory exhaustion
- **S3/B7** — Validate each domain in stdin/file batch modes; invalid entries print an error and continue; exits 1 if any failed
- **B1** — AXFR returns error immediately on non-NoError RCODE (REFUSED, SERVFAIL, etc.)
- **B3** — N-way `--compare` warns on per-server failure and continues; previously aborted on first error
- **B4** — Watch loop prints error and retries on transient query failure; previously exited the loop
- **B6** — Batch modes (stdin, `--file`) exit with code 1 when any domain query fails
- **B8** — TUI mode warns when multiple `--type` flags are given (only the first type is used)
- **B9** — Custom `--server` port is now applied to all hickory connections, not just the first

## [0.2.0] - 2026-05-20

### Added
- **`-x` / `--reverse <IP>`** — reverse DNS shorthand: auto-converts IPv4/IPv6 to PTR query (like `dig -x`)
- **Multiple `--type` flags** — `--type a --type aaaa --type mx` runs one query per type and renders results sequentially
- **Stdin batch mode** — pipe newline-separated domain names; lines starting with `#` are skipped
- **DNSSEC verbose (`-v` / `--verbose`)** — adds key tags, algorithm names, and KSK/ZSK roles to the DNSSEC chain tree
- **Human-readable TTL** — `300` shown as `5m`, `3600` as `1h`, `86400` as `1d` in table output
- Competitor comparison table in README now covers doggo, q, delv, drill
- **Authority + Additional sections** — displayed below the answer table when the server returns NS referrals or glue records; works automatically with `--no-recurse` against authoritative nameservers
- **`--no-recurse`** — clears the RD (Recursion Desired) bit, enabling direct queries to authoritative servers (like `dig +norecurse`); combined with `-s <auth-ns>` surfaces the Authority and Additional sections
- **`--tcp`** — force DNS queries over TCP instead of UDP (requires `-s`; like `dig +tcp`)
- **CAA, TLSA, SSHFP, NSEC, NSEC3 record types** — added to `--type` enum; CAA, TLSA, SSHFP have structured display and JSON; NSEC/NSEC3 display via hickory's native format
- **`--timeout <SECS>`** — configurable DNS query timeout (1–60 seconds, default 5; previously hardcoded)

### Fixed
- Integration test call sites for `build_chain` and `trace` that were missing the `Option<IpAddr>` argument

## [0.1.0] - 2026-05-15

### Added
- Basic DNS query with colored table output (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR`, `SRV`, `DNSKEY`, `DS`, `RRSIG`)
- DNSSEC chain-of-trust visualization (`--dnssec`)
- Iterative resolution path tracing from root servers (`--trace`)
- DNS-over-HTTPS support (`--doh`)
- DNS-over-TLS support (`--dot`)
- JSON output for scripting (`--output json`)
- Plain text output for CI environments (`--output plain`)
- Custom resolver address (`--server`)
- Progress spinner via `indicatif`
