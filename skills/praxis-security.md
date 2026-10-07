---
name: praxis-sec
version: 8.0.0
description: Run Praxis security scans from within a Hermes Agent workflow. Detects vulnerabilities in codebases, MCP servers, agent manifests, and Hermes deployments.
author: Praxis contributors
tools:
  - praxis_audit
  - praxis_scan_mcp
  - praxis_get_findings
  - praxis_suppress_finding
  - praxis_memory_list
tags:
  - security
  - devsecops
  - hermes
  - mcp
  - agent-security
---

# Praxis Security Skill

This skill enables a Hermes Agent to run security audits on codebases and MCP server manifests, retrieve findings, suppress false positives, and query the persistent security memory.

## When to use this skill

Use this skill when the agent needs to:
- Audit a codebase for security vulnerabilities before deployment
- Validate an MCP server manifest before connecting to it
- Check historical scan findings for a project
- Suppress known-safe findings to reduce noise in future scans
- List what the security memory has learned about a project

## Tool guide

### praxis_audit
Runs a full security audit on a local codebase directory.

```
praxis_audit({ path: "/path/to/project", severity: "high", deep: true })
```

Returns a findings report with severity-graded issues, CWE/OWASP mappings, and remediation guidance.

### praxis_scan_mcp
Analyzes an MCP server manifest (URL or local file) for tool poisoning, prompt injection, and Hermes function-call poisoning patterns.

```
praxis_scan_mcp({ target: "https://mcp.example.com" })
praxis_scan_mcp({ target: "/path/to/manifest.json" })
```

Returns per-tool findings including any embedded `<tool_call>` injection, credential harvesting patterns, and schema bypass indicators.

### praxis_get_findings
Retrieves findings from the last saved scan report for a project.

```
praxis_get_findings({ path: "/path/to/project", severity: "critical" })
```

### praxis_suppress_finding
Inserts an inline `praxis-ignore` comment in source code to suppress a known-safe finding.

```
praxis_suppress_finding({ file: "src/api.js", line: 42, reason: "False positive — value is sanitized upstream" })
```

### praxis_memory_list
Lists all entries in the project's security memory (previously learned false positives).

```
praxis_memory_list({ path: "/path/to/project" })
```

## Security constraints

- Register the tool definitions from `cli/utils/hermes-tool-registry.js` in the host agent. This document does not itself enforce host permissions.
- Audits read a project and may write local cache/history state. The default Hermes audit skips dependency auditing and AI classification; disclose those omissions.
- `deep: true` sends source context to the configured LLM provider. Remote MCP manifests require network access. Configure host permissions accordingly.
- `praxis_suppress_finding` writes a trailing comment to the matched source line. Invoke it only for an authorized, reviewed suppression; it does not repair the vulnerability.
- Audit handlers return structured results. To use `praxis_get_findings`, explicitly save a full JSON report as `.praxis/last-report.json`; it is not saved automatically.
- Require `scanComplete === true` before treating an audit as complete. Never display credential values.

## Example workflow

```
1. Agent receives task: "Audit the codebase before merging PR #42"
2. Agent calls: praxis_audit({ path: process.cwd(), severity: "high" })
3. Agent checks scan completion and discloses skipped checks; an incomplete audit cannot support a pass
4. If high findings only: agent calls praxis_get_findings to get details
5. Agent surfaces remediation suggestions from the findings' `fix` fields
6. If an authorized review establishes a false positive: agent calls praxis_suppress_finding to mark it
```
