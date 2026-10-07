# Praxis — Complete Usage Guide

Security CLI for AI applications and codebases. Praxis runs 28 built-in scanners
in parallel batches, maps findings to security standards, and supports reviewed
LLM remediations with verification and an undo log. Requires Node.js 18 or newer.

For a local static audit, use `praxis scan . --no-ai --no-deps`. Default dependency
audits contact package services, and configured LLM providers may classify findings.
`--deep`, swarm analysis, LLM fixes, credential verification, feed updates, Git
clones, and live probes can also contact external services. `--no-ai` disables
classification; it does not disable those separately requested features.

---

## Table of contents

1. [Install](#install)
2. [Quick start](#quick-start)
3. [Command groups overview](#command-groups-overview)
4. [`praxis scan` — security scans](#praxis-scan--security-scans)
5. [`praxis fix` — apply remediations](#praxis-fix--apply-remediations)
6. [`praxis agents` — AI agent surface](#praxis-agents--ai-agent-surface)
   - [MCP trust registry](#mcp-trust-registry)
   - [Governance absence-audits](#governance-absence-audits)
7. [`praxis intel` — threat intelligence](#praxis-intel--threat-intelligence)
8. [`praxis report` — format/share results](#praxis-report--formatshare-results)
9. [`praxis project` — setup & state](#praxis-project--setup--state)
10. [`praxis rules` — portable rule inventory](#praxis-rules--portable-rule-inventory)
11. [`praxis web` — local web UI](#praxis-web--local-web-ui)
12. [Top-level shortcuts](#top-level-shortcuts)
13. [AI security standards alignment](#ai-security-standards-alignment)
14. [AST & CST dataflow analysis engine](#ast--cst-dataflow-analysis-engine)
15. [Threat packs (AI attack-vector signatures)](#threat-packs-ai-attack-vector-signatures)
16. [Environment variables](#environment-variables)
17. [Configuration files](#configuration-files)
18. [Output formats](#output-formats)
19. [CI/CD integration](#cicd-integration)
20. [Custom plugins](#custom-plugins)
21. [Troubleshooting](#troubleshooting)
22. [`praxis mcp` — MCP server mode](#praxis-mcp--mcp-server-mode)
23. [Get help](#get-help)

---

## Install

```bash
# From source (this repo)
npm ci
npm link                         # exposes `praxis` globally

# Or run directly without linking
node cli/bin/praxis.js --help
```

Requires Node.js ≥ 18. No build step — Praxis runs from source via the `bin`
entry in `package.json`.

---

## Quick start

```bash
praxis scan .                    # Full audit: secrets + 28 agents + deps + score
praxis fix .                     # Interactive LLM-guided fixes
praxis agents audit .            # Audit CLAUDE.md, .cursorrules, MCP, skills
praxis intel update              # Refresh threat-intel feed
praxis project init              # Add security configs to your project
praxis vibe .                    # Emoji-graded A–F score
praxis --help                    # Show all groups
```

Running `praxis` with no args on a TTY drops into the interactive REPL.

---

## Command groups overview

| Group | Purpose |
| --- | --- |
| `scan` | Run security scans |
| `fix` | Apply remediations |
| `agents` | Audit the AI/agent surface (skills, MCP, configs, attestation, BOM) |
| `intel` | Threat-intelligence feed updates and advisory operations |
| `report` | Format, diff, or share existing scan results |
| `project` | Init, hooks, watch, doctor, baseline, plugins, policies |
| `rules` | Inspect and export the detection rules (portable Semgrep-compatible bundle) |
| `web` | Local web UI for running scans and managing scan projects |

Plus three top-level shortcuts: `praxis vibe`, `praxis score`, and `praxis` alone (REPL on a TTY), plus [legacy flat aliases](#legacy-top-level-aliases) for the original command names.

---

## `praxis scan` — security scans

### `scan full [path]` (default)

Full audit: secrets + 28 agents + deps + score + remediation plan.

Local scan roots must be existing directories. Passing a file produces an error.
Use `scan changed` for a change-based scan; the editor's current-file command
scans its workspace and selects findings for that file.

Full-scan JSON contains:

- `scanComplete`: true only when required scan stages completed.
- `scanErrors`: errors from discovery, agents, dependency auditing, or requested legal analysis.
- `dependencyAudit`: `complete`, `skipped`, `not-applicable`, or `failed`.

Incomplete scans exit 1, do not refresh scan cache/history/playbook state, and
cannot verify a fix. Findings alone do not fail a normal full scan; use `scan ci`
for severity or score gates. Keep stderr and inspect completion before treating
JSON output or a high score as a successful assessment. Skipped checks provide
no assurance for that part of the project.

| Flag | Description |
| --- | --- |
| `--json` | Output results as JSON |
| `--sarif` | Output as SARIF 2.1.0 |
| `--csv` | Output as CSV |
| `--md` | Output as Markdown |
| `--html [file]` | HTML report path (default: `praxis-report.html`) |
| `--pdf [file]` | Generate PDF (requires Chrome/Chromium) |
| `--compare` | Detailed comparison with last scan |
| `--timeout <ms>` | Per-agent timeout in ms (default 30000) |
| `--no-deps` | Skip dependency audit |
| `--no-ai` | Skip AI classification |
| `--no-cache` | Force full rescan |
| `--baseline` | Only show findings not in the baseline |
| `--deep` | LLM-powered taint analysis for critical/high findings |
| `--think` | Enable extended thinking mode |
| `--local` | Use local Ollama for deep analysis |
| `--model <model>` | LLM model for deep/AI analysis |
| `--provider <name>` | LLM provider (anthropic/openai/google/ollama/openai-compatible) |
| `--base-url <url>` | Custom OpenAI-compatible endpoint |
| `--budget <cents>` | Max spend in cents for deep analysis (default 50) |
| `--verify` | Check if leaked secrets are still active |
| `--include-legal` | Also run the legal risk scan |
| `--agentic [iterations]` | Legacy annotation loop: adds review comments, then re-scans; does not apply the proposed remediation |
| `--agentic-target <score>` | Target security score for agentic loop |
| `--hermes-only` | Run only Hermes-relevant agents |
| `--fail-below <threshold>` | Exit 1 if score < threshold |
| `-b, --branch <name>` | Branch or tag to scan (when target is a Git URL) |
| `--depth <n>` | Git clone depth (default: 1 for shallow clone, 0 for full history) |
| `--git-token <token>` | Auth token for private Git repositories (or set `PRAXIS_GIT_TOKEN` / `GITHUB_TOKEN`) |
| `--git-history` | Include Git commit history secret audit |
| `--keep-clone` | Retain cloned repository on disk after scan instead of deleting |
| `--submodules` | Recursively clone Git submodules |
| `-v, --verbose` | Verbose output |

> **Direct Git Repository Scanning:** You can pass any remote Git URL directly to `praxis scan` (e.g., `praxis scan https://github.com/OWASP/wrongsecrets`). Praxis clones the repository into an isolated, secure temporary directory, executes the audit, and automatically purges the workspace upon completion.

### `scan git <url>` / `scan repo <url>`

Direct remote Git repository audit. Clones the remote repository to an isolated temporary workspace, runs the 28-agent audit, generates compliance and remediation reports, and cleans up the temporary files safely.

```bash
# Scan a public GitHub repository with depth 1 (fast SAST audit)
praxis scan git https://github.com/OWASP/wrongsecrets

# Scan a specific branch with full commit history secret audit
praxis scan git https://github.com/org/repo -b staging --git-history

# Scan a private repository using an auth token
praxis scan git https://github.com/private-org/repo --git-token "$GITHUB_TOKEN" --json > report.json

# Shorthand syntax also supported:
praxis scan gh:OWASP/wrongsecrets
```

### `scan secrets [path]`

Fast pattern-based secret scan only (no agents).

| Flag | Description |
| --- | --- |
| `-v, --verbose` | Show all files being scanned |
| `--no-color` | Disable colored output |
| `--json` | JSON output |
| `--sarif` | SARIF output |
| `--include-tests` | Also scan test files |
| `--no-cache` | Force full rescan |

### `scan changed [ref]`

Scan only files changed since `<ref>` (default: `HEAD`).

| Flag | Description |
| --- | --- |
| `--staged` | Scan only staged changes |
| `--json` | JSON output |
| `-p, --path <path>` | Project path (default: cwd) |
| `--timeout <ms>` | Per-agent timeout in ms |

### `scan env [path]`

Credential health check: `.env` coverage, source cross-ref, git history.

| Flag | Description |
| --- | --- |
| `--json` | JSON output |

### `scan redteam [path]` / `praxis redteam [target]`

`scan redteam <directory>` runs the static adversarial agent pack.
`praxis redteam <endpoint>` runs dynamic probes against an authorized live LLM
endpoint. These commands have different options; consult each command's `--help`.
The table below describes the static command.

| Flag | Description |
| --- | --- |
| `--agents <list>` | Comma-separated list of static agents to run |
| `--json` | JSON output |
| `--sarif` | SARIF output |
| `--html [file]` | Generate interactive Pro HTML security report |
| `--sbom [file]` | Generate CycloneDX SBOM / ABOM |
| `--no-deps` | Skip dependency audit |
| `--no-ai` | Skip AI classification |
| `--deep` | LLM-powered taint analysis with AST scope evaluation |
| `--swarm` | Send selected source context and role instructions to a configured swarm provider; provider execution is separate from the 28 local scanners |
| `--think`, `--local`, `--model`, `--provider`, `--base-url`, `--budget` | LLM controls (same as `scan full`) |
| `-v, --verbose` | Verbose output |

### `scan standard [name] [path]`

Filter findings by AI-security standard.

| Flag | Description |
| --- | --- |
| `--list` | List available standards and exit |
| `--control <id>` | Filter to a single control (e.g. `LLM01`) |
| `--json` | JSON output |
| `--sarif` | SARIF output |
| `--format <name>` | Output format from registry (json/sarif) |

Standards available: `owasp-llm`, `mitre-atlas`, `nist-ai-600-1`, `avid`,
`owasp-ml`, `eu-ai-act`, `iso-42001`, `google-saif`. See
[AI security standards alignment](#ai-security-standards-alignment).

### `scan ci [path]`

CI/CD pipeline mode: scan, score, exit 1 on failure.

| Flag | Description |
| --- | --- |
| `--threshold <score>` | Minimum passing score (default 75) |
| `--fail-on <severity>` | Fail on findings ≥ this severity |
| `--always-fail-on <severity>` | Severity floor that even an accepted baseline cannot suppress |
| `--include-findings` | Include finding identities (`file`/`rule`/`severity`) in JSON output — used by the GitHub Action's net-new PR diff |
| `--sarif <file>` | Write SARIF for GitHub Code Scanning |
| `--json` | JSON output |
| `--no-deps` | Skip dependency audit |
| `--baseline` | Only check new findings |
| `--github-pr` | Post findings as a GitHub PR comment |
| `--strict-intel` | Fail if threat-intel feed is stale |
| `--max-intel-age <duration>` | Max acceptable intel age (default `7d`) — accepts `7d`/`24h`/`30m`/`60s` |

---

## `praxis fix` — apply remediations

### `fix interactive [path]` (default)

Interactive LLM-guided: scan → plan → diff → ask → apply → **verification ladder**.

The verification ladder (all gates are executable oracles, never model judgment):

1. **Build/lint** — the project's own build or lint command must still pass (npm/cargo/go/make detected automatically)
2. **Test suite** — the project's test command must still pass
3. **Re-scan** — the original findings must be gone from the fixed file

On failure, the failing tier's evidence is fed into a retry plan; if the final attempt still fails, the fix is **automatically reverted** and the file restored. Fix prompts require sibling-call-site coverage and a regression test in the diff. Every applied fix is recorded in `.praxis/fixes.jsonl` with its verification class.

| Flag | Description |
| --- | --- |
| `--plan-only` | Generate plans for review but never write |
| `--severity <level>` | Minimum severity to fix (default `low`) |
| `--provider <name>` | LLM provider |
| `--model <model>` | Specific model name |
| `--think` | Enable extended thinking |
| `--allow-dirty` | Allow running with uncommitted changes |
| `--branch [name]` | Create a branch and commit one fix per file |
| `--pr` | Push branch + open PR via `gh` (requires `--branch`) |
| `--yolo` | Auto-accept every plan (dangerous) |
| `--auto-low` | Auto-accept plans marked `risk:low` |
| `--max-attempts <n>` | Max plan attempts per file (verification-ladder retries, default 2) |
| `--sandbox` | Verify each fix in a Docker sandbox |
| `--ci` | Non-interactive CI/CD mode (auto-accept fixes) |

### `fix quick [path]`

Deterministic secret fixer: rewrite source + write `.env`. No LLM.

| Flag | Description |
| --- | --- |
| `--dry-run` | Preview without writing |
| `--yes` | Apply all fixes without prompting |
| `--stage` | Run `git add` on modified files |
| `--all` | Also fix common agent findings (debug, TLS bypass, shell injection) |

### `fix from-report [path]`

Apply LLM fixes from a deep-analysis JSON report and open a PR.

| Flag | Description |
| --- | --- |
| `--report <file>` | Path to praxis JSON report |
| `--severity <level>` | Minimum severity to fix |
| `--dry-run` | Preview without applying |
| `--yes` | Skip confirmation |

### `fix rotate [path]`

Open provider dashboards to revoke exposed secrets.

| Flag | Description |
| --- | --- |
| `--provider <name>` | Only rotate secrets for a specific provider |
| `--plan <file>` | Execute a rotation plan |

### `fix undo [path]`

Revert the last interactive fix (or all with `--all`).

| Flag | Description |
| --- | --- |
| `--all` | Revert every fix in the log |
| `--dry-run` | Show what would be reverted |

### `fix env-template`

Generate a `.env.example` with placeholder values from found secrets.

| Flag | Description |
| --- | --- |
| `--dry-run` | Preview without writing |

---

## `praxis agents` — AI agent surface

### `agents audit [path]` (default)

Audit AI agent configs (CLAUDE.md, .cursorrules, MCP servers, skills).

| Flag | Description |
| --- | --- |
| `--fix` | Auto-harden agent configurations |
| `--preflight` | Exit non-zero on critical findings (for CI) |
| `--red-team` | Simulate adversarial attacks against agent configs |
| `--json` | JSON output |

### `agents skill [target]`

Vet an AI agent skill (URL or path) before installing it.

| Flag | Description |
| --- | --- |
| `--all` | Scan all skills defined in `openclaw.json` |
| `--json` | JSON output |

### `agents mcp [target]`

Vet an MCP server's tool manifest before connecting, and optionally perform live protocol probing.

| Flag | Description |
| --- | --- |
| `--test-live` | Perform runtime JSON-RPC handshakes, tool enumeration, schema validation, and tool fuzzing |
| `--json` | JSON output |

### `agents bom [path]`

Generate Agent Bill of Materials (CycloneDX ABOM).

| Flag | Description |
| --- | --- |
| `-o, --output <file>` | Output file path (default `abom.json`) |
| `--json` | Output to stdout as JSON |

### `agents serve`

Start praxis as an MCP server (Claude Desktop, Cursor, Windsurf).

### MCP trust registry

Every scan consults a bundled registry of known MCP servers
(`cli/data/known-mcps.json`, SHA-256 integrity-checked at load):

- **verified** (official reference servers, trust 90) and **community** (trust 50–70) packages pass silently.
- Anything else triggers `MCP_UNVERIFIED_SOURCE` (medium) — an unknown MCP server gains the agent's tools, credentials, and filesystem context.
- Typosquat detection (edit distance ≤ 3) covers the full registry, not just the official list.

Registry updates are quarterly + incident-driven; a tampered registry degrades gracefully (integrity check fails → unknown-tier lookups) instead of silently trusting anything.

---

## Governance absence-audits

Beyond finding what *is* there, Praxis detects what *isn't*:

| Rule | What it checks | Framing |
| --- | --- | --- |
| `NO_HUMAN_OVERSIGHT` (high) | High-blast-radius agent actions (financial/destructive tools, excessive agency) with **no approval-gate pattern** anywhere in the repo (`interrupt_before`, `requires_approval`, `human_in_the_loop`, ...) | EU AI Act Art. 14, ISO 42001 A.12.4 |
| `NO_OBSERVABILITY` (medium) | AI is in use but **no tracing wiring** exists outside dependency manifests (LangSmith, Langfuse, Helicone, OpenTelemetry, ... — a transitive dependency is not proof of wiring) | EU AI Act Art. 12, ISO 42001 A.6.2.6 |

Both run as post-processors on every full scan — no flags needed.

---

## `praxis intel` — threat intelligence

### `intel update`

Refresh OSV, GHSA, KEV, EPSS, NVD, Gitleaks (+optional paid sources).

| Flag | Description |
| --- | --- |
| `--only <sources>` | Comma-separated subset (e.g. `osv,kev,epss`) |
| `--force` | Ignore per-source TTL caches |
| `--list` | Print available sources and exit |

### `intel deps [path]`

Audit deps via package manager (npm/yarn/pnpm/pip-audit/bundler-audit).

| Flag | Description |
| --- | --- |
| `--fix` | Run package manager fix command after auditing |

### `intel advisories [path]`

Check deps against live advisory feeds (OSV.dev, GitHub Advisories).

| Flag | Description |
| --- | --- |
| `--ecosystem <type>` | Filter by ecosystem (`npm`, `PyPI`) |
| `--json` | JSON output |

---

## `praxis report` — format/share results

### `report team [file]`

Convert Hermes Agent team output into a Praxis report.

| Flag | Description |
| --- | --- |
| `--html [path]` | Save as HTML report |
| `--json` | JSON output |

### `report legal [path]`

Legal risk audit: DMCA, leaked-source derivatives, IP disputes.

| Flag | Description |
| --- | --- |
| `--json` | JSON output |

### `report checklist`

Run the launch-day security checklist interactively.

| Flag | Description |
| --- | --- |
| `--no-interactive` | Print checklist without prompts |

### `report sbom [path]`

Generate Software Bill of Materials (CycloneDX SBOM).

| Flag | Description |
| --- | --- |
| `-o, --output <file>` | Output file path (default `sbom.json`) |

### `report benchmark [path]`

Run the ground-truth benchmark harness to evaluate Praxis accuracy, false-positive resistance, precision, recall, and F1 score against curated positive and negative security fixtures.

| Flag | Description |
| --- | --- |
| `--json` | JSON output |
| `--verbose` | Show per-fixture detection details |

---

## `praxis project` — setup & state

### `project init`

Initialize security configs in your project.

| Flag | Description |
| --- | --- |
| `-f, --force` | Overwrite existing files |
| `--gitignore` | Only copy `.gitignore` |
| `--headers` | Only copy security headers config |
| `--agents` | Only add security rules to AI agent instruction files |
| `--openclaw` | Generate a hardened `openclaw.json` template |
| `--hermes` | Bootstrap Hermes Agent security config |
| `--from <url>` | Fetch a pre-built Hermes config bundle from a setup URL |

### `project doctor`

Diagnose environment: Node.js, git, API keys, cache, dependencies.

### `project hooks [action]`

Manage Claude Code hooks — real-time security gate on tool calls.

### `project guard [action]`

Install pre-commit/pre-push git hook to block secret commits.

| Flag | Description |
| --- | --- |
| `--pre-commit` | Install as pre-commit hook (instead of pre-push) |
| `--generate-hooks` | Generate defensive Claude Code hooks |

### `project watch [path]`

Continuous monitoring: watch files for security issues in real-time.

| Flag | Description |
| --- | --- |
| `--poll` | Use polling mode |
| `--configs` | Watch only agent config files |
| `--deep` | Run full agent scanning on changes |
| `--stateful` | Keep Kimi K2.6 conversation context between scans |
| `--model <model>` | LLM model for stateful watch |
| `--provider <name>` | LLM provider for stateful watch |
| `--status` | Show current watch status and exit |
| `--threshold <score>` | Alert when score drops below threshold |
| `--debounce <ms>` | Debounce interval in ms |
| `--slack [webhook]` | Post findings to Slack webhook |
| `--pr-comment` | Post inline findings as GitHub PR review comments |

### `project baseline [path]`

Create/manage a findings baseline — only report new findings.

| Flag | Description |
| --- | --- |
| `--diff` | Show what changed since baseline |
| `--clear` | Remove the baseline |

### `project memory [subcommand]`

Manage false-positive memory. Subcommands: `list`, `forget <key>`, `clear`.

### `project playbook [subcommand]`

Manage repo-specific LLM context playbook. Subcommands: `show`, `add-note "text"`.

### `project plugins [action]`

Manage custom security agent plugins from `.praxis/agents/`. Action `new <name>` scaffolds a new plugin.

### `project policy <action>`

Manage security policies. Action `init` creates a `.praxis.policy.json` template.

---

## `praxis rules` — portable rule inventory

Inspect Praxis's detection rules and export them in a form other tools can read.
The rules are data, not lock-in.

### `rules list`

Summarise the inventory by source, severity and portability.

```bash
praxis rules list
praxis rules list --json
```

Reports how many rules are exportable and validated, the severity mix, and which
sources contribute. Also names the layers that have **no** portable equivalent (see below).

### `rules export`

Write a portable bundle. Three files:

| File | Purpose |
| --- | --- |
| `praxis-rules.yaml` | Semgrep-compatible, using `pattern-regex` (PCRE2) |
| `praxis-rules.json` | Canonical format, re-importable by Praxis |
| `praxis-rules.manifest.json` | What is portable, what is Praxis-only, and why |

```bash
praxis rules export -o ./rules
semgrep --config ./rules/praxis-rules.yaml .
```

Every pattern is validated before the bundle is written, and the export **refuses to
write** if any pattern is malformed — a partially broken bundle would fail inside
someone else's Semgrep with no useful context. Patterns that are valid PCRE2 but have no
JavaScript equivalent (atomic groups, POSIX classes) are reported as *unverifiable* rather
than silently passed off as checked.

Rule **ids are identifiers** (`AWS_ACCESS_KEY_ID`, not `AWS Access Key ID`), because
Semgrep suppressions (`# nosemgrep:`) and baselining key on them.

**Scope — what the export does not cover.** The inventory identifies the rules that are static patterns. Three
layers have no Semgrep representation and are declared in the manifest rather than
approximated:

| Layer | Why it is Praxis-only |
| --- | --- |
| AST / taint dataflow | "User input reaches this sink" is not a pattern |
| Prompt-injection probe corpus | Versioned data with its own compiler and ReDoS guard |
| Entropy-checked secrets (10 rules) | A runtime Shannon-entropy heuristic over the match |
| LLM deep analysis (`--deep`) | Runtime exploitability verdicts |

### `rules import <bundle>`

Load a portable bundle and optionally emit a runnable plugin.

```bash
# Preview: what would be accepted or rejected, and why
praxis rules import ./rules/praxis-rules.json

# Emit a plugin that participates in real scans
praxis rules import ./rules/praxis-rules.json --write-plugin .praxis/agents
```

Import accepts **pattern rules only**. Anything it cannot execute as a static pattern is
**rejected with a stated reason**, never imported in a degraded form.

The canonical round-trip format is the JSON, not the YAML: Praxis has no YAML runtime
dependency, and adding one for this would not be worth it. Handing it the Semgrep YAML
produces an explanation rather than a silent failure.

| Flag | Description |
| --- | --- |
| `--write-plugin <dir>` | Write a runnable plugin (e.g. `.praxis/agents`) |
| `--name <name>` | Plugin class name prefix |
| `--json` | Machine-readable output |

---

## `praxis web` — local web UI

A browser front-end for running scans and managing scan projects: register projects, run
single or concurrent scans, watch live progress over SSE, and browse findings.

**Read-only by design.** It orchestrates scans and shows results; it deliberately does
**not** expose fix application. See [`docs/design/WEB-UI.md`](design/WEB-UI.md) for the
full threat model.

```bash
praxis web                         # http://127.0.0.1:7317
praxis web --port 8080
```

| Flag | Default | Description |
| --- | --- | --- |
| `--port <port>` | `7317` | Port to listen on |
| `--host <host>` | `127.0.0.1` | Host to bind |
| `--allow-remote` | off | Permit a non-loopback bind (requires `--token`) |
| `--token <token>` | — | Bearer token required for every request when remotely bound |

### Security model

- **Loopback-only by default.** A non-loopback bind is refused unless *both*
  `--allow-remote` and a `--token` of at least 16 characters are supplied.
- **The browser never sends a filesystem path.** Projects are registered by the operator,
  resolved and pinned server-side, then addressed only by **id** — so no request can ask
  the server to scan `/` or a home directory.
- **Anti-CSRF.** Mutating requests must carry a header a cross-origin form cannot set,
  plus a same-origin `Origin` (defends against DNS rebinding).
- **Nothing is served from disk.** The frontend is generated in memory from the shared
  theme, so there is no static-file path to traverse.
- **Bounded work.** Concurrency, queue depth and request body size are all capped.
- Loopback-only is a safe default, **not** a boundary against an attacker already on the
  machine. There is no authentication, multi-user or tenancy support.

---

## Top-level shortcuts

### `praxis vibe [path]`

Vibe-graded security score with emoji and shareable badge.

| Flag | Description |
| --- | --- |
| `--badge` | Generate a shields.io markdown badge |

### `praxis score [path]`

Compute a 0–100 security health score.

| Flag | Description |
| --- | --- |
| `--no-deps` | Skip dependency audit |

### `praxis` (no args)

- On a TTY → drops into the interactive REPL.
- Otherwise → prints quick-start help.

### Legacy top-level aliases

Praxis was reorganized into verb-led groups. The original flat commands still work as
aliases, so existing scripts and CI configs keep running. **Prefer the grouped form** in
new work — the aliases are maintained for compatibility, not as the primary interface.

| Alias | Use instead |
| --- | --- |
| `praxis ci` | `praxis scan ci` |
| `praxis audit` · `praxis openclaw` | `praxis agents audit` |
| `praxis scan-mcp` | `praxis agents mcp` |
| `praxis scan-skill` | `praxis agents skill` |
| `praxis abom` | `praxis agents bom` |
| `praxis mcp` | `praxis agents serve` |
| `praxis scan-standard` | `praxis scan standard` |
| `praxis red-team` | `praxis scan redteam` |
| `praxis update-intel` | `praxis intel update` |
| `praxis deps` | `praxis intel deps` |
| `praxis advisories` | `praxis intel advisories` |
| `praxis remediate` | `praxis fix quick` |
| `praxis rotate` | `praxis fix rotate` |
| `praxis undo` | `praxis fix undo` |
| `praxis env-template` | `praxis fix env-template` |
| `praxis legal` | `praxis report legal` |
| `praxis team` | `praxis report team` |
| `praxis checklist` | `praxis report checklist` |
| `praxis benchmark` | `praxis report benchmark` |
| `praxis init` | `praxis project init` |
| `praxis doctor` | `praxis project doctor` |
| `praxis baseline` | `praxis project baseline` |
| `praxis guard` | `praxis project guard` |
| `praxis watch` | `praxis project watch` |
| `praxis shell` | `praxis` (no args, on a TTY) |

Note: `vibe`, `score` and the no-argument REPL are **not** aliases — they are distinct
top-level commands.

---

## AI security standards alignment

Every finding is auto-tagged with all applicable AI-security standards. Reports
include a per-standard coverage summary with a **3-state coverage map**:

| State | Meaning |
| --- | --- |
| **Flagged** | This scan produced evidence for that control |
| **No evidence in this scan** | The tool can detect it; this repo showed nothing — *not proof of safety* |
| **No detection rule** | Praxis has no code-level check for this control (e.g. registration duties, fundamental-rights impact assessments) — an honest tool-gap marker |

MITRE ATLAS findings are enriched from the vendored official knowledge
snapshot (2026-04): every flagged `AML.T####` technique renders its tactic,
recommended mitigations (`AML.M####`), and real-world case studies
(`AML.CS####`). The snapshot date is shown in reports.

| Standard | Module name | Controls |
| --- | --- | --- |
| OWASP Top 10 for LLM Applications (2025) | `owasp-llm` | LLM01–LLM10 |
| MITRE ATLAS (2026-04 snapshot) | `mitre-atlas` | AML.T0010, T0018, T0024, T0034, T0040, T0043, T0048, T0051, T0053, T0054, T0057, T0070 |
| NIST AI 600-1 (Generative AI Profile) | `nist-ai-600-1` | GV/MP/MS/MG actions tagged `-GAI` |
| AVID — AI Vulnerability Database taxonomy | `avid` | S0100, S0200, S0301, S0400, S0500, P0201, P0204, P0301, E0101 |
| OWASP ML Security Top 10 | `owasp-ml` | ML01–ML10 |
| EU AI Act (Regulation 2024/1689) | `eu-ai-act` | Articles 5, 9–15, 17, 25–27, 49, 50, 53, 55, 72, 73 (18 controls) |
| ISO/IEC 42001 (AI Management System) | `iso-42001` | A.5–A.13 Annex outline (21 controls) |
| Google Secure AI Framework (SAIF) | `google-saif` | SAIF-1 through SAIF-6 |

```bash
# List all standards
praxis scan standard --list

# Filter to a single standard
praxis scan standard owasp-llm .

# Filter to a single control within a standard
praxis scan standard owasp-llm . --control LLM01

# Programmatic JSON for tooling (mitre-atlas includes the enrichment block)
praxis scan standard mitre-atlas . --json

# Audit-ready compliance export (GRC report)
praxis scan standard nist-ai-600-1 . --format compliance
```

In the JSON / SARIF / HTML reports:
- Each finding carries `standards: { 'owasp-llm': ['LLM01'], ... }`.
- The top-level `standardsSummary` shows per-standard coverage (e.g. `4/10`) with per-control `status` and `detectable` flags.
- `mitre-atlas` JSON reports include an `atlas` block hydrating flagged techniques with tactics, mitigations, and case studies.
- SARIF embeds standards as `result.properties.standards` plus a flat `tags`
  array — GitHub Code Scanning will display them as labels.
- HTML reports render a "Standards Compliance" section with the 3-state coverage map and a reading legend.

**Adding a new standard**: drop a module under
`cli/utils/standards/sources/<name>.js` exporting `name`, `version`, `title`,
`description`, `url`, `controls`, and `mapFinding(finding)`; register it in
`ALL_STANDARDS` in `cli/utils/standards/index.js`. No other changes needed.
Mark controls with `detectable: false` when no `mapFinding` path can ever
produce them, so reports can distinguish tool gaps from absent evidence.

---

## AST & CST Dataflow Analysis Engine

Praxis incorporates a pure ESM, zero-native-dependency AST & CST analysis engine (`cli/core/ast/`):

- **JS/TS Parsing**: Babel parser based AST engine providing complete syntax trees for modern JavaScript, TypeScript, JSX, and TSX.
- **Python Parsing**: CST tokenizer and indentation block tree parser providing function scope and statement hierarchy without requiring Python runtime dependencies.
- **Lexical Scope Resolution (`scope-tree.js`)**: Tracks variable declarations, parameter bindings, enclosing function contexts, and variable shadowing.
- **Intra-File Source-to-Sink Taint Tracking (`taint-tracker.js`)**: Tracks untrusted user inputs (`req.body`, `req.query`, `process.env`, `input()`, `request.args`) as they propagate across variable assignments, template strings, and function calls into dangerous sinks (`eval`, `exec`, `spawn`, `child_process`, SQL queries, filesystem writes).
- **AI Guardrail Detection (`guardrail-detector.js`)**: Identifies input/output defense wrappers (NeMo Guardrails, Llama Guard, Guardrails AI, LangKit, custom validator functions) and suppresses false positives when inputs are provably sanitized.
- **Tier 0 Syntax Verification**: Integrates with the LLM remediation ladder to immediately reject syntactically broken patches before running heavier test suites.

---

## Environment variables

### LLM providers (auto-detected by `--deep`, `fix`, `watch --stateful`)

| Variable | Purpose |
| --- | --- |
| `ANTHROPIC_API_KEY` | Claude (Opus / Sonnet / Haiku) |
| `OPENAI_API_KEY` | OpenAI (GPT-4 / GPT-4o / o1) |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | Gemini |
| `MOONSHOT_API_KEY` | Kimi |
| `OPENAI_BASE_URL` | Custom OpenAI-compatible endpoint (OpenRouter, Groq, DeepSeek, LM Studio, vLLM, ...) |
| `PRAXIS_LLM_MODEL` | Default model when no `--model` flag is given |
| `PRAXIS_LLM_REASONING` | `low`/`medium`/`high` — enables extended thinking (reasoning_effort) |

`--local` uses Ollama; no key needed.

### `.env` loading

Praxis loads a `.env` file from your **working directory** at startup
(`.env.example` in the repo is the documented template; `.env` is gitignored).
Real environment variables always win over `.env`; CLI flags
(`--provider`, `--model`, `--base-url`) win over both. `OPENAI_BASE_URL`
applies only to OpenAI-shaped providers (never anthropic/google/ollama).

```bash
# .env — cloud LLM features without any flags
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://your-gateway.example/v1/chat/completions
PRAXIS_LLM_MODEL=your-model-name
PRAXIS_LLM_REASONING=high

praxis project doctor          # connectivity check ("custom LLM responding successfully")
praxis scan full . --deep      # LLM taint analysis, no flags needed
praxis fix interactive .       # LLM remediation planning
```

Run Praxis from the directory that holds your `.env` (the config is the
operator's, not the target's).

### Threat intelligence (raise rate limits)

| Variable | Purpose |
| --- | --- |
| `GITHUB_TOKEN` / `GH_TOKEN` | GHSA — raises GitHub rate limit |
| `NVD_API_KEY` | NVD — drops 6s wait between requests to 600ms |

### Optional paid intel sources

| Variable | Source |
| --- | --- |
| `SNYK_TOKEN` (+ `SNYK_ORG_ID`) | Snyk Vulnerability DB |
| `SOCKET_API_KEY` | Socket.dev supply-chain risk |
| `GITGUARDIAN_API_KEY` | GitGuardian secret detector definitions |
| `SONATYPE_USER` + `SONATYPE_TOKEN` | OSS Index (works anonymously too) |
| `PHYLUM_API_KEY` | Phylum supply-chain risk |

None are required. The seven core intel sources — OSV, GHSA, KEV, EPSS, NVD, Gitleaks and
the bundled AI threatpack — plus pattern-based scanning all work with zero config.

### State location override (used by tests)

| Variable | Purpose |
| --- | --- |
| `HOME` (Unix) / `USERPROFILE` (Windows) | Relocates `~/.praxis/` |

---

## Configuration files

### `.praxisignore`

Per-line ignore patterns (gitignore-style) applied during file discovery.

```
# Skip vendored code
vendor/
third_party/
# Skip generated dirs
**/dist/**
```

### Inline suppression

Add `praxis-ignore` (optionally followed by a rule name) on the same line as
the finding:

```js
const fakeKey = "sk_test_dummy"; // praxis-ignore stripe-secret
```

### `.praxis.policy.json`

Project-level policy: severity floors, allowed CWEs, agent enable/disable,
suppression rules. Generate a template with:

```bash
praxis project policy init
```

### `.praxis/agents/*.js`

Custom agent plugins, loaded only when a local scan uses `--trust-plugins`.
Scaffold one with:

```bash
praxis project plugins new my-rule
```

A plugin is any module exporting a class extending `BaseAgent`:

```js
import { BaseAgent, createFinding } from 'praxis-sec';

export default class MyAgent extends BaseAgent {
  constructor() { super('MyAgent', 'description', 'category'); }
  async analyze(context) {
    const findings = [];
    // ...
    return findings;
  }
}
```

### `.praxis/baseline.json`

Snapshot of "known" findings. Created by `praxis project baseline .`. After
that, `--baseline` only surfaces new findings.

### `.praxis/history.json`

Trend tracking — last 100 score snapshots. Drives the `Trend` line in scan
output.

### `~/.praxis/threat-intel.json`

Merged threat-intel feed. Populated by `praxis intel update`. Falls back to
the bundled seed at `cli/data/threat-intel.json` when missing.

---

## Output formats

The output formatter registry lives in `cli/core/output/`. Built-in formats:

| Format | Flag | Notes |
| --- | --- | --- |
| `json` | `--json` | `schemaVersion: 3`, `findings[]`, `standardsSummary`, `compliance`, `agenticSummary`, and a `fingerprint` block (see below) |
| `sarif` | `--sarif [file]` | SARIF 2.1.0 with **`security-severity`** (critical 9.5 / high 7.5 / medium 5.0 / low 2.5) so GitHub Code Scanning ranks alerts correctly; `result.properties.standards` + flat `tags` |
| `html` | `--html [file]` | **Professional assessment report** — tabbed single-file report: Overview (KPIs, severity distribution, category breakdown, discovered attack surface, OWASP ASI agentic-risk coverage, score trend), **Agent Coverage**, Findings & AST Dataflow (per-finding rule IDs, severity filter, search, evidence + dataflow panels, LLM verdicts), Standards Matrix, Agent BOM (ABOM), Remediation Plan + **Remediation Ledger** |
| `pdf` | `--pdf [file]` | Print-rendered PDF (requires Chrome/Chromium) |
| `csv` | `--csv` | Tabular |
| `md` | `--md` | Markdown |

Add a new format by writing `cli/core/output/<name>.js` exporting
`default function(report, options): string` and registering it in `REGISTRY`
in `cli/core/output/index.js`.

All HTML surfaces share one theme in `cli/core/output/html-theme.js`, so severity colours,
badges, tables and escaping stay consistent across reports. Values interpolated into
report markup are escaped centrally, and severities are mapped through a sanitiser that
only ever emits a known class name.

**Scan fingerprint.** JSON output carries a `fingerprint` block, and every HTML report
prints a provenance line in its footer:

```
praxis <version> · node <runtime> · probes <version/count> · threatpack <version/count> · eaa <version> · files <count>
```

It records the tool version, the runtime, and the version of every vendored data asset
that can change detection behaviour. A surprising result should be *attributable* rather
than mysterious.

**Secret redaction invariant:** secret-category findings never expose their
raw matched value in any report output — `matched` is redacted centrally
(`sk-***`) in the output renderers, and SARIF carries no matched values.

---

## Threat packs (AI attack-vector signatures)

New AI attack-vector signatures arrive as **data**, not code. `intel update`
fetches a versioned threat pack (`cli/data/threatpacks/latest.json` is the
bundled seed; `PRAXIS_THREATPACK_URL` overrides the remote source):

```bash
# Fetch/refresh the AI threat pack (probe signatures + registry updates)
praxis intel update --only threatpack

# Pack version + probe count visible in the feed
# ~/.praxis/threat-intel.json → threatPack
```

When a pack contains new prompt-injection probe signatures, the
PromptInjectionProber overlays them onto its bundled corpus automatically
(bundled + pack = total active probes; the ReDoS guard still applies at
compile). This is the mechanism that keeps Praxis current on new attack
families (jailbreak variants, obfuscation tricks, dataset/eval vectors)
between releases.

---

## CI/CD integration

### GitHub Action

The [Marketplace Action](https://github.com/marketplace/actions/praxis-security-scan)
installs dependencies from its own lockfile and scans with the code selected by
the Action ref. It does not depend on npm latest being synchronized with GitHub.

```yaml
name: Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
  pull-requests: write
jobs:
  praxis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: Ganron007/Praxis@v1.2.4
        with:
          path: '.'
          threshold: '80'
          deps: 'true'
          deep: 'false'
          sarif: 'true'
          comment: 'true'
          net-new: 'true'
          fail-on-new: 'high'
          always-fail-on: 'critical'
```

Use a release tag or commit for reproducibility; `v1` is a floating release-line
tag. Inside this repository, `uses: ./` runs the checked-out source.

Outputs: `score`, `grade`, `findings`, `secrets`, `vulns`, `cves`,
`sarif-file`, and `report-url`. See [action.yml](../action.yml) for all inputs.

On pull requests, `net-new: true` scans the base in a worktree and compares
finding identities against the head scan. Introduced findings at or above
`fail-on-new` fail the gate. `always-fail-on` also checks existing findings;
scan and comparison failures fail the job. Other events use the normal gate.

SARIF upload needs `security-events: write`; PR comments need
`pull-requests: write`. Fork PR tokens and repository Code Scanning settings can
restrict these integrations. Set `sarif: 'false'` or `comment: 'false'` when
unavailable. The security gate operates independently of those integrations.

### Plain CLI in CI

After 1.2.4 is published to npm, install that exact version in your CI setup:

```bash
npm install -g praxis-sec@1.2.4
praxis scan ci . --fail-on high --sarif results.sarif
```

Keep the command's exit status. Store JSON as a regular artifact; Praxis JSON
is not the GitLab SAST report schema. Upload SARIF to a compatible service with
the necessary permissions. If using `--strict-intel`, refresh the feed first
and ensure its configured sources completed successfully.

### Determinism gate

A scan's findings should be identical across runs on identical inputs. `check-determinism`
enforces that by comparing finding identities (`file::rule`) between two runs, so a
detection change cannot land unnoticed:

```bash
node scripts/check-determinism.mjs .
```

CI runs this as its own job. A failure means identical inputs produced different
finding identities across runs. Investigate unstable discovery, ordering, caches,
or external state. An intentional detection change between releases does not
justify drift between two scans of the same checkout.

---

### Pre-commit hook

```bash
praxis project guard install --pre-commit
```

### Agentic loop (auto-fix until score target)

```bash
praxis fix . --severity high --branch praxis/fixes --pr
# review, then if needed:
praxis fix undo --all
```

---

## Custom plugins

Praxis loads plugins from `.praxis/agents/` only with explicit trust:

```bash
praxis scan full . --trust-plugins
```

Plugins execute arbitrary JavaScript with your permissions. Remote repository and
web scans do not execute target plugins. Programmatic callers opt in with
`buildOrchestratorAsync(rootPath, { trustPlugins: true })`; the synchronous
`buildOrchestrator()` uses only built-in agents.

A plugin extends `BaseAgent` and follows the standard contract:

```js
import { BaseAgent, createFinding } from 'praxis-sec';

export default class HardcodedAdminCheck extends BaseAgent {
  constructor() {
    super(
      'HardcodedAdminCheck',
      'Detects hardcoded admin credentials',
      'auth'   // category — feeds into ScoringEngine
    );
  }

  shouldRun(recon) {
    return recon.languages?.has('javascript') || recon.languages?.has('typescript');
  }

  async analyze(context) {
    const files = this.getFilesToScan(context);
    const findings = [];
    for (const file of files) {
      // Use scanFileWithPatterns or your own logic
      findings.push(...this.scanFileWithPatterns(file, [
        {
          rule: 'hardcoded-admin',
          title: 'Hardcoded admin credential',
          regex: /admin\s*:\s*['"](password|admin)['"]/gi,
          severity: 'critical',
          cwe: 'CWE-798',
          owasp: 'A07:2021',
          description: 'Admin credential hardcoded in source.',
          fix: 'Move to environment variables.',
        },
      ]));
    }
    return findings;
  }
}
```

The standards registry will auto-tag these findings during scoring — no
plugin-side wiring required.

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `praxis intel update` is slow | NVD rate-limits to 6s/request without a key. Set `NVD_API_KEY`. |
| `praxis scan ci --strict-intel` fails locally | Run `praxis intel update` first. Default freshness window is `7d`. |
| Custom plugins not loading | Use `praxis scan full . --trust-plugins` for a trusted local project, or `buildOrchestratorAsync(rootPath, { trustPlugins: true })`. Remote and web scans use built-in agents only. |
| `node cli/bin/praxis.js` works but `praxis` doesn't | Run `npm link` once (or `npm install -g .` from the repo). |
| Test files report secrets | Confidence is auto-downgraded in test/doc/example paths — but use `praxis-ignore` for explicit suppression. |
| Feed lives somewhere else | Override `HOME` (Unix) or `USERPROFILE` (Windows) — used by the test suite. |
| Standards summary shows `0/X` everywhere | The standards registry maps via `cwe`/`owasp`/`category` on findings. If you've written a custom agent that doesn't set these, populate them in `createFinding({...})`. |
| `rules export` refuses to write | A pattern failed validation. The message names the rule and the error — the bundle is not written rather than shipping broken YAML. Fix the pattern, or pass `--allow-invalid` if you understand the risk. |
| `rules import` rejects a bundle | Only static pattern rules are importable. The rejection reason is printed per rule; AST/taint, probe-corpus and entropy rules cannot be expressed as a pattern. |
| `rules import` says "YAML is an export format" | Import the sibling `praxis-rules.json`. Praxis has no YAML runtime dependency, so YAML is export-only. |
| `praxis web` refuses to start on a non-loopback host | Remote bind requires **both** `--allow-remote` and `--token` of at least 16 characters. This is deliberate. |
| `praxis web` won't load a project path | Projects are registered by the operator and addressed by **id**. The API intentionally does not accept client-supplied paths. |
| Determinism gate fails in CI | Two scans of identical inputs disagreed on `file::rule`. Investigate unstable discovery, caches, ordering, or external state; a detection change between commits does not justify drift in one checkout. |

---

## `praxis mcp` — MCP server mode

Exposes Praxis as a Model Context Protocol (MCP) server over stdio (JSON-RPC
2.0). This lets IDEs (Cursor, Continue, VS Code) call Praxis tools directly
from chat — real-time vulnerability feedback without leaving the editor.

### Quick start

```bash
npx praxis-sec mcp
# → Praxis MCP server listening on stdio (JSON-RPC 2.0)
```

### IDE integration

Illustrative stdio configuration (adapt the wrapper schema to your IDE; the package must be preinstalled):

```yaml
mcpServers:
  - name: praxis
    transport: stdio
    command: npx
    args: ["--no-install", "praxis-sec", "mcp"]
```

In Docker (a container running praxis):

```yaml
mcpServers:
  - name: praxis
    transport: stdio
    command: docker
    args: ["exec", "-i", "your-container", "praxis", "mcp"]
```

### Available MCP tools

| Tool | Input | Returns | Description |
|------|-------|---------|-------------|
| `scan_secrets` | `{ path }` | findings[] | Scan a file/directory for hardcoded secrets |
| `scan_repo` | `{ path, agents?, llm?, outputFile? }` | findings + score + completion | Built-in orchestrator scan; dependency audit skipped; optional LLM analysis |
| `analyze_file` | `{ path }` | findings | Static secret analysis of a file |
| `get_findings` | `{ reportPath, severity? }` | report + findings | Read an explicitly saved JSON report |
| `get_checklist` | — | checklist[] | Launch-day security checklist items |
| `suppress_finding` | `{ file, line, reason }` | suppression status | Append a trailing comment to a reviewed source line; supported comment formats only |
| `explain_and_fix` | `{ file, line, rule }` | explanation + preview | AST-aware explanation and proposed fix preview |

### Example MCP interaction

When connected, an IDE user can ask: *"Scan this file for AI vulnerabilities"*
and the LLM calls `scan_repo` — Praxis findings appear inline in the chat with
file:line references. The `llm` option requests provider-backed analysis. Require `scanComplete === true`, inspect errors, and disclose skipped checks. Suppression writes source and is not remediation.

---

## Get help

```bash
praxis --help                    # all groups
praxis <group> --help            # subcommands for a group
praxis <group> <cmd> --help      # flags for a specific command
```

Report Praxis bugs or feature requests via the project's issue tracker on the
Praxis GitHub repository.
