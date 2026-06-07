# shohei MCP Server — AI Agent Integration

(Coming in v0.5.0+ Phase 3)

## Overview

shohei will be available as an MCP (Model Context Protocol) server, allowing AI agents like Claude to perform automated infrastructure diagnostics directly from conversations.

## How it works

1. **Register** the shohei MCP server in your Claude Code settings
2. **Compose**: Agents can call shohei tools like `shohei_check_propagation`, `shohei_verify_tls_chain`, etc.
3. **Automate**: Agents diagnose infrastructure issues without human intervention

## Planned Tools

- `shohei_check_propagation(domain)` — Global resolver consistency check
- `shohei_check_tls_chain(hostname, port)` — Certificate chain validation
- `shohei_check_dnssec(domain)` — DNSSEC chain validation
- `shohei_check_email_security(domain)` — SPF/DKIM/DMARC validation
- `shohei_benchmark_latency(domain, resolvers)` — Multi-protocol latency comparison

## Example Agent Workflow

```
User: "Is example.com ready for production?"

Agent: 
  1. Calls shohei_check_propagation("example.com")
  2. Sees propagation is live across all resolvers
  3. Calls shohei_check_tls_chain("example.com", 443)
  4. Sees cert is valid and not expiring soon
  5. Calls shohei_check_email_security("example.com")
  6. Reports: "✓ DNS propagated, ✓ TLS cert valid (expires 2025-06-01), ⚠ SPF record missing"
```

## Configuration

(Coming in v0.5.0)

```json
{
  "enabledMcpjsonServers": ["shohei"]
}
```

## More Information

- Phase 3 timeline: See `CLAUDE.md`
- For now: Use shohei as a library or CLI tool
