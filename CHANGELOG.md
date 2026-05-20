# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
