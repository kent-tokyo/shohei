# MCP Registry Registration

This document tracks shohei's registration across MCP server registries and directories.

## Registry Status

### Smithery.ai
- **Status**: ⏳ Pending (UI access issue)
- **URL**: https://smithery.ai
- **Method**: Web form or CLI
- **Entry Format**: MCP server metadata (name, repo, command, tools)

### mcp.so
- **Status**: 📋 Ready for PR
- **Repository**: https://github.com/mcp-registry/mcp-registry
- **File**: `servers.json`
- **Entry**:
```json
{
  "name": "shohei",
  "repository": "https://github.com/kent-tokyo/shohei",
  "description": "Infrastructure diagnostics library with MCP server for Claude. Automate DNS, TLS, email security, and DNS propagation checks via AI agents.",
  "homepage": "https://docs.rs/shohei",
  "command": "shohei-mcp",
  "install": "cargo install shohei",
  "language": "rust",
  "tags": ["dns", "tls", "mcp", "claude", "infrastructure"],
  "version": "0.5.1",
  "license": "MIT"
}
```

### GitHub Topics
- **Status**: ✅ Complete
- **Topics Added**: `mcp`, `claude`, `ai-agents`, `infrastructure-diagnostics`, `dns`
- **Command**: `gh repo edit kent-tokyo/shohei --add-topic mcp ...`

## How to Register

### For mcp.so PR
1. Visit: https://github.com/mcp-registry/mcp-registry
2. Open `servers.json`
3. Add shohei entry (see format above)
4. Create PR with title: "Add shohei MCP server"

### For Smithery.ai
1. Visit: https://smithery.ai
2. Locate registration form
3. Fill in server details and tool list (5 tools available)
4. Submit and verify email

## Maintained By
- Author: kent-tokyo
- Last Updated: 2026-06-07
- Version: 0.5.1
