---
name: praxis-ci
description: Configure Praxis CI gates with correct exit status, report formats and permissions.
argument-hint: "[path] [--threshold <score>] [--fail-on <severity>]"
---

# praxis-ci

Use a preinstalled Praxis CLI 1.2.4 or newer; check `praxis --version`.
Resolve the requested directory and pass arguments literally. `$ARGUMENTS`
below is a placeholder for user-selected arguments, not shell code to evaluate.
Keep stdout, stderr, and exit status separate. Never display credential values.

Run the selected directory through the CI gate:

```bash
praxis scan ci . --fail-on high --json
```

Exit 0 means the enabled gate passed. Exit 1 may mean findings exceeded the gate
or a required scan stage failed. Report the distinction and inspect completion.
Use `--threshold` for a score gate, `--baseline` for reviewed debt, and
`--sarif results.sarif` for compatible SARIF integrations.

For GitHub use the complete, permission-scoped Action workflow in
[the usage guide](../../../docs/USAGE.md#cicd-integration), pinned to `v1.2.4`
or its commit. For a plain CLI job, install `praxis-sec@1.2.4` after npm
publication and keep its exit status. Store JSON as a regular artifact;
Praxis JSON is not GitLab's SAST schema. Explain net-new comparison, the
`always-fail-on` floor, and skipped dependency checks when configured.
