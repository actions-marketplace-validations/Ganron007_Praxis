---
name: praxis
description: Run and interpret a full Praxis security audit, including scan completion and skipped checks.
argument-hint: "[path] [--no-deps] [--baseline]"
---

# praxis

Use a preinstalled Praxis CLI 1.2.4 or newer; check `praxis --version`.
Resolve the requested directory and pass arguments literally. `$ARGUMENTS`
below is a placeholder for user-selected arguments, not shell code to evaluate.
Keep stdout, stderr, and exit status separate. Never display credential values.

Run the canonical full scan; default the directory to `.`:

```bash
praxis scan full . --json --no-ai
```

Replace `.` with the requested directory and append supported user options.
For an explicitly local-only audit add `--no-deps` and disclose that omission.
Do not silently retry an incomplete scan with checks disabled.

Require parseable JSON, `scanComplete === true`, and a successful exit status
before calling the assessment complete. Report `scanErrors` and
`dependencyAudit`; a full scan can succeed while containing findings.

Present completion/coverage first, then score, critical/high findings with file,
line, rule and evidence, dependency advisories, and medium/low totals. Describe
the score as a finding summary, not assurance. Review code before judging a
finding, including findings in tests and documentation.

Apply fixes within the user's authorized scope after presenting a concrete diff.
Re-scan and require completion before claiming a fix is verified. Rotate exposed
credentials; changing source does not revoke them. Use `praxis scan ci` for gates,
`praxis project baseline` for reviewed debt, and `praxis fix` for interactive fixes.
