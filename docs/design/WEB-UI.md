# Praxis Web UI — design & threat model

> **Status:** implemented — read-only scan orchestration, served locally by the CLI.
>
> This document exists because a web UI for Praxis is the one place where adding a
> feature means adding an **attack surface** to a security tool. A CLI runs with the
> privileges of the person who typed the command. A server runs with whatever
> privileges the person who *connected to it* has — and may have more.

---

## 1. What it is

A local web app for driving scans and managing scan projects:

- register projects (directories to scan)
- run single or concurrent scans
- watch live progress
- browse findings, agents, standards, and the fix ledger
- manage baselines

Reuses the existing `Orchestrator` as the scan engine — the UI never reimplements
detection. All UI is **vanilla JS served from the CLI**, with no bundler, no
framework, and no network fetch of assets. Reports use the shared
`cli/core/output/html-theme.js`.

## 2. Threat model — the part that matters

Praxis reads source code, prints code excerpts in findings, and can **write code**
(`praxis fix` applies LLM-guided patches). Exposing that over HTTP is remote code
execution by design if done carelessly. Threats, ranked:

| # | Threat | Why it is serious | Mitigation in v1 |
|---|--------|-------------------|------------------|
| T1 | **Fix application over the network** | An endpoint that accepts a path and writes a patch is arbitrary code write on the host. Even "verified" patches are LLM-authored. | **Not implemented.** v1 is read-only. Remediation stays in the CLI, where a human sees the diff. |
| T2 | **Arbitrary filesystem read via project paths** | A client-supplied path lets a caller scan `/`, read `~/.ssh`, or enumerate the host. | Projects are **registered explicitly by the operator** and stored server-side. The client sends a project *id*, never a path. Paths are resolved once at registration and pinned. |
| T3 | **Finding data leaks other projects** | Findings contain file paths and source excerpts. A multi-project UI that serves them to any caller leaks the whole workspace. | Every API call is scoped to a registered project id. No endpoint enumerates arbitrary paths. Loopback-only by default. |
| T4 | **Remote binding without auth** | `0.0.0.0` with no auth exposes everything above to the network. | **Loopback-only by default.** A non-loopback bind requires an explicit `--allow-remote` flag **and** refuses to start unless a token is provided; the token is required in a header. |
| T5 | **CSRF / DNS rebinding from a browser** | A malicious page can POST to `127.0.0.1:PORT` while the victim has the UI open. | All mutating endpoints require a custom header (`X-Praxis-Client`) that a cross-origin form cannot set, plus `Origin` checking. This is the standard localhost-server defence. |
| T6 | **Path traversal in served assets** | Serving the frontend from disk invites `../../`. | Frontend is generated in memory from the shared theme. No static file serving. |
| T7 | **Resource exhaustion** | 28 agents × many projects; a scan queue can be flooded. | Bounded concurrency, a max project count, and per-request limits. |
| T8 | **Scan data egress** | `--deep` sends code to an LLM provider. | The UI does **not** enable `--deep`; LLM-backed analysis stays a CLI opt-in so egress is always an explicit human decision. |

### Explicit non-goals for v1

- No authentication, no multi-user, no tenancy (it binds to loopback).
- No fix application, no `--agentic`, no `--deep`.
- No remote/multi-tenant deployment story. Exposing this to a network is out of scope
  until there is real auth, and shipping that is a separate, larger piece of work.

## 3. Shape

```
cli/commands/web.js          command wiring, bind/guard logic
cli/core/web/
  server.js                  node:http server, routing, guards
  projects.js                project registry (pinned, resolved paths)
  jobs.js                    bounded job queue driving Orchestrator
  api.js                     JSON API handlers
```

Storage under `.praxis/web/` in the * Praxis home* (`~/.praxis/web`), not inside a
scanned project, so scanning a project never reads the UI's own state.

Endpoints (all project-scoped by id):

```
GET  /api/projects                 list registered projects
POST /api/projects                 register (operator-supplied path, server-side)
POST /api/projects/:id/scan        enqueue a scan
GET  /api/jobs                     job states
GET  /api/jobs/:id/events          SSE progress stream
GET  /api/projects/:id/report      full JSON report (reuses existing renderer)
```

## 4. Honest limitations

- Scanning still runs as the invoking user; the UI does not sandbox the scan.
- Loopback-only is the safe default, not a security boundary against a local attacker.
- Progress is best-effort; the orchestrator reports per-agent completion, not per-file.
- No incremental/streaming findings yet — the report renders after the scan finishes.