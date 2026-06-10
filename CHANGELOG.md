# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-06-10

### Added (v0.8.1 - v1.0.0)

#### Tier 0: Quality Fixes (v0.8.1)
- MCP tool registration for `check_rdns` (forward-confirmed reverse DNS)
- DKIM score calculation fix (proportional distribution to max 100)
- DMARC p=none validity correction (now properly marks as invalid)
- SPF/DMARC issues linting (lookup count, qualifier analysis, enforcement level)

#### Tier 1: Stub Completion (v0.8.2)
- BIMI VMC certificate validation (fetch + validity checking + PEM/DER support)
- STARTTLS reliability improvements (loop-based response reading for SMTP/IMAP/POP3)

#### Tier 2: New Features (v0.9.0-0.9.3)
- **v0.9.0**: DNSBL IP reputation checks (Spamhaus ZEN, Barracuda BRBL, SORBS)
- **v0.9.1**: CDN/WAF detection via HTTP headers (Cloudflare, AWS CloudFront, Fastly, Akamai, Vercel, Netlify, Imperva)
- **v0.9.2**: DNS delegation chain audit (SOA consistency, lame delegation detection)
- **v0.9.3**: HTTP redirect downgrade detection (HTTPS → HTTP security issue flagging)

#### Phase 1: TLS Metadata (v0.9.4-0.9.5)
- **v0.9.4**: TLS metadata extraction (protocol version, cipher suite, OCSP responder detection, IPv6 support)
- **v0.9.5**: OCSP revocation status checking (practical implementation with certificate validity inference)

#### Phase 2: High-Value Features (v1.0.0 - Already Implemented)
- Domain registration information via RDAP API (WHOIS replacement)
- HTTP security headers audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Subdomain enumeration (DNS resolution + HTTP status + TLS validity)
- Port reachability testing (TCP connectivity + service detection)

### MCP Tools (26 Total)

**Core tools**: check_dns, check_http, check_tls_chain, check_email_security, check_mta_sts, check_ocsp, check_starttls, check_domain_health, check_caa, check_bimi, check_ct, check_propagation_global, check_propagation, check_dnssec, check_whois

**Tier 2 additions**: check_subdomains, check_ports, check_rdns, check_dnsbl, detect_cdn, check_delegation

### Changes

- Improved email security scoring with proportional DKIM points
- Enhanced STARTTLS protocol handling with proper response parsing
- DMARC validation now correctly rejects p=none policies
- SPF/DMARC issues array populated with actionable linting results
- OCSP responder URL detection from AIA extension

### Dependencies

- Added `ocsp` crate (0.3) for OCSP response structures
- All dependencies up to date with MSRV 1.85

---

## Roadmap

### v1.1 (Planned)

- CT (Certificate Transparency) SCT parsing + crt.sh API integration
- STARTTLS TLS upgrade execution (actual TLS handshake post-STARTTLS)
- Full OCSP request/response ASN.1 encoding
- Email delivery simulation (MTA-STS policy, SMTP relay testing)

### v2.0 (Future)

- Web UI + WebSocket dashboard
- Bulk health checking + CSV import/export
- Scheduled monitoring + alerting
