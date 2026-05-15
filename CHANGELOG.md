# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
