# GitHub Actions Integration

(Coming in v0.5.0+ Phase 4)

## Overview

Use shohei in GitHub Actions to automatically validate DNS propagation, TLS certificates, and email security before deploying.

## Planned Action

```yaml
name: Infrastructure Health Check
on:
  pull_request:
  schedule:
    - cron: '0 */6 * * *'

jobs:
  check-dns:
    runs-on: ubuntu-latest
    steps:
      - uses: kent-tokyo/shohei-action@v1
        with:
          domain: example.com
          check: propagation  # or tls-chain, email-security, all
```

## Use Cases

### 1. Pre-deployment DNS check
Verify domain is propagated before pushing changes live:

```yaml
- uses: kent-tokyo/shohei-action@v1
  with:
    domain: api.example.com
    check: propagation
    fail-if-not-propagated: true  # Fail PR if not ready
```

### 2. Certificate expiry alerts
Monitor TLS certs in nightly jobs:

```yaml
- uses: kent-tokyo/shohei-action@v1
  with:
    domain: api.example.com
    check: tls-chain
    fail-if-expires-in-days: 30  # Alert if <30 days left
```

### 3. Email security validation
Ensure SPF/DKIM/DMARC are configured:

```yaml
- uses: kent-tokyo/shohei-action@v1
  with:
    domain: example.com
    check: email-security
```

## Output

Results are written to GitHub workflow annotations and a JSON report artifact:

```json
{
  "domain": "example.com",
  "propagation": {
    "live": true,
    "resolvers": [
      { "name": "Google", "ip": "8.8.8.8", "status": "✓" },
      { "name": "Cloudflare", "ip": "1.1.1.1", "status": "✓" }
    ]
  },
  "tls": {
    "valid": true,
    "expires": "2025-06-01"
  }
}
```

## More Information

Phase 4 timeline: See `CLAUDE.md`
