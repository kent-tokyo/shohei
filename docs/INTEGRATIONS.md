# shohei Integrations & Use Cases

This page lists official and planned integrations for shohei across different platforms and automation frameworks.

## As a Library (Rust)

**Status**: Available now (v0.4.0+)

Add shohei to your `Cargo.toml`:

```toml
[dependencies]
shohei = "0.4"
```

See [docs.rs/shohei](https://docs.rs/shohei) for full API documentation.

**Use cases:**
- Testing frameworks: Validate DNS/TLS before tests run
- Infrastructure tools: Diagnostics built into custom tools
- CLI tools: Add diagnostics as a subcommand

---

## As an AI Agent Backend (MCP Server)

**Status**: Planned (v0.5.0+ Phase 3)

Register shohei with Claude Code or other MCP clients to enable AI-driven infrastructure diagnostics.

See [docs/MCP_SERVER.md](MCP_SERVER.md) for details.

**Use cases:**
- Automated diagnostics: "Is example.com ready?" → Agent checks propagation + TLS + DNS
- Troubleshooting: Agents propose fixes based on what they find
- CI/CD agents: Validate infrastructure during deployment

---

## GitHub Actions

**Status**: Planned (v0.5.0+ Phase 4)

Automatically check DNS propagation, TLS certs, and email security in CI/CD workflows.

See [docs/GITHUB_ACTIONS.md](GITHUB_ACTIONS.md) for examples.

**Use cases:**
- Pre-deployment DNS validation
- Nightly certificate expiry checks
- Email security compliance verification

---

## Terraform Module

**Status**: Planned (v0.5.0+ Phase 4)

Validate infrastructure resources using shohei diagnostics:

```hcl
resource "shohei_domain_check" "api" {
  domain = aws_route53_zone.main.name
  checks = ["propagation", "tls-chain", "dnssec"]
}
```

---

## Ansible Integration

**Status**: Future (v0.6.0+)

Ansible module for infrastructure validation playbooks.

---

## Monitoring & Alerting

**Status**: Future (v0.6.0+)

Webhook-based monitoring:
- DNS change detected → Auto-trigger cert validation
- Certificate expiry detected → Alert on Slack/PagerDuty

---

## Command Line (CLI)

**Status**: Available now (v0.4.0+)

The shohei CLI is a demo/reference tool. Primary use is testing and manual inspection.

```bash
shohei example.com --dnssec
shohei example.com --trace
shohei example.com --type MX
```

---

## Questions?

- Phase roadmap: See [CLAUDE.md](../CLAUDE.md)
- Examples: See `examples/` directory
- API docs: `cargo doc --open`
