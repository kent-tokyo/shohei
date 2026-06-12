# Changelog

All notable changes to this project will be documented in this file.

## [2.4.0] - 2026-06-13

### Added

#### Phase 9: Competitor Gap-Filling (15 new tools)

**Module: web_intelligence**
- `check_robots_txt` — Fetch and parse robots.txt; identify sensitive disallowed paths (admin, backup, .git, credentials)
- `check_well_known` — Discover all accessible .well-known/ endpoints (OIDC, security.txt, JWKS, MTA-STS, SBOM, ai-plugin.json, and more)
- `check_oauth_oidc` — Audit OAuth 2.0 / OIDC configuration from .well-known/openid-configuration; detect implicit flow, PKCE support, grant types
- `check_cert_pinning` — Check Expect-CT enforce mode, HPKP remnants (deprecated), and CAA iodef reporting
- `check_api_exposure` — Probe for exposed debug/API endpoints (Spring Actuator, Swagger UI, GraphQL, phpinfo, server-status) and version disclosure headers

**Module: service_exposure**
- `check_exposed_databases` — Detect unauthenticated Redis (6379), MongoDB (27017), Elasticsearch (9200), Memcached (11211), CouchDB (5984)
- `check_container_exposure` — Detect exposed Docker API (2375/2376), Kubernetes API (6443), etcd (2379)
- `check_service_fingerprint` — Banner-based service fingerprinting for SSH, FTP, SMTP, MySQL, PostgreSQL, Redis with CVE hints
- `check_dga_risk` — Algorithmically score domain names for DGA risk (entropy, vowel ratio, digit ratio, consonant cluster analysis)

**Module: subdomain_takeover_ext**
- `check_subdomain_takeover` — Detect subdomain takeover across 30+ cloud services (GitHub Pages, Heroku, Netlify, Vercel, Azure, AWS EB, Shopify, Fastly, Tumblr, SendGrid, Mailgun, and more)
- `check_passive_dns` — Query RIPE Stat passive DNS API for historical DNS records (no API key required)
- `check_azure_ad_exposure` — Discover Azure AD / Entra ID tenant info via public Microsoft Graph endpoints (tenant ID, federation type)

**Module: email_advanced**
- `check_dkim_key_strength` — Detect weak 1024-bit DKIM RSA keys; validate 2048-bit and Ed25519 keys across common selectors
- `check_mx_security` — Deep MX server audit: STARTTLS support, ESMTP features, banner leak via live SMTP connection

**Module: dga_and_threat**
- `check_attack_surface` — Composite attack surface score (0–100): aggregates TLS, web security headers, email security, and open port exposure (CVSS-like)

### Fixed (Security)

- **[CRITICAL] SSRF prevention** — Added `validate_url_safety()` in `helpers.rs`; blocks `file://`, loopback, RFC1918, link-local (169.254.x.x) URLs
- **[CRITICAL] cloud_security** — `check_cloud_metadata_exposure` no longer queries the MCP server's own IMDS; now checks if target domain resolves to IMDS IP via DNS
- **[HIGH] identity_security** — JWT `token_valid` logic was inverted (`alg=none` returned `valid=true`); fixed to `critical_issues.is_empty() && alg_secure`
- **[HIGH] identity_security** — Cookie security score `u8` arithmetic overflow fixed (use `u32`, then clamp to 100)
- **[HIGH] shohei_mcp** — All 169 error responses now use `serde_json::json!` for proper escaping (was: unsafe `format!` with user-controlled strings)
- **[HIGH] typosquat** — IDN domain panic fixed: `remove(i)` / `insert(i, '-')` / `replace_range(i..i+1)` now use byte offsets from `char_indices()` instead of character ordinals
- **[HIGH] shohei_mcp** — `rate_limit_policy` `u32` multiplication overflow fixed with `saturating_mul`
- **[HIGH] mta_sts** — `fetch_mta_sts_policy` now uses `Client::builder().timeout()` instead of `Client::new()` (no-timeout)
- **[MEDIUM] propagation** — `check_propagation` resolver count capped at 50 to prevent unbounded `tokio::spawn` DoS
- **[MEDIUM] username_osint** — Eliminated duplicate `check_email_security` call (was making 2 identical DNS queries)

---

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
