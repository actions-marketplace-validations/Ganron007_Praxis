---
name: praxis-scan
description: Scan a directory for secret and code patterns and report findings without exposing credentials.
argument-hint: "[path]"
---

# praxis-scan

Use a preinstalled Praxis CLI 1.2.4 or newer; check `praxis --version`.
Resolve the requested directory and pass arguments literally. `$ARGUMENTS`
below is a placeholder for user-selected arguments, not shell code to evaluate.
Keep stdout, stderr, and exit status separate. Never display credential values.

Use the pattern scanner, with the requested directory or `.`:

```bash
praxis scan secrets . --json
```

This command reports secret and code patterns without the full agent audit.
It exits 1 when it finds issues or encounters a failure. Parse its flat JSON
`findings` array and group it by file; distinguish operational errors using stderr and
whether a valid report was produced. Do not describe an error as a clean scan.

Report file, line, pattern type and severity without credential values. If a
complete scan finds no matches, state which directory/checks were scanned.
Preview authorized source changes, move secrets to environment variables, keep
real values out of `.env.example`, and rotate committed credentials. History
rewriting needs a separate coordinated plan; it does not revoke a credential.
