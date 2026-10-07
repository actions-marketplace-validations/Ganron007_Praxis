# Praxis plugin for Claude Code

These skills guide Claude Code through Praxis scans, findings, fixes, hooks,
and CI configuration. The plugin uses a preinstalled Praxis CLI so the reviewed
version is explicit and command execution does not silently download a new one.

## Requirements and installation

- Node.js 18 or newer and Claude Code with plugin support.
- Praxis CLI 1.2.4 or newer. Install `praxis-sec` from npm after publication,
  or use the tarball/source from the [GitHub release](https://github.com/Ganron007/Praxis/releases/tag/v1.2.4).
- Verify the CLI with `praxis --version` before invoking these skills.

From a checkout of this repository, load the plugin directly:

```bash
claude --plugin-dir ./claude-code-plugin
```

This uses Claude Code's [local plugin loading](https://code.claude.com/docs/en/plugins)
without requiring a marketplace catalog. The manifest is
[.claude-plugin/plugin.json](.claude-plugin/plugin.json). Skill names are namespaced
by the plugin; use `/praxis:praxis`, `/praxis:praxis-scan`, and the corresponding
names below in the loaded session.

## Skills

| Skill | Purpose |
| --- | --- |
| `/praxis` | Full static audit and prioritized findings |
| `/praxis-scan` | Fast secret/pattern scan |
| `/praxis-score` | Score summary and its limitations |
| `/praxis-red-team` | Static adversarial scanner pack |
| `/praxis-baseline` | Review and manage accepted findings |
| `/praxis-fix` | Preview deterministic fixes, apply authorized changes, verify |
| `/praxis-deep` | Optional provider-backed analysis |
| `/praxis-ci` | Severity/score gates and CI examples |
| `/praxis-hooks` | Install, inspect, or remove Claude Code hooks |

## Interpreting results

Full audits preserve stderr and exit status and check `scanComplete` before
presenting an assessment. Skipped or failed checks must be disclosed. Ordinary
full scans do not fail solely because findings exist; CI gates do.

The static skills disable Praxis's AI classification. Dependency auditing can
contact package services; add `--no-deps` when a local-only audit is required.
Deep analysis explicitly uses a configured provider, and Claude Code itself may
receive source context when interpreting results. Do not treat these workflows
as a guarantee that data stays on the local machine.

Review findings and proposed diffs before modifying code. A baseline accepts
debt; it does not resolve a vulnerability. A high score and an LLM verdict do
not prove that a project is safe to ship.

See the [usage guide](../docs/USAGE.md) and [security reporting policy](../.github/SECURITY.md).
