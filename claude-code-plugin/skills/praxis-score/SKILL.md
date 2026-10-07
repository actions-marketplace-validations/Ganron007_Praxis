---
name: praxis-score
description: Summarize the Praxis score while explaining coverage and unresolved findings.
argument-hint: "[path] [--no-deps]"
---

# praxis-score

Use a preinstalled Praxis CLI 1.2.4 or newer; check `praxis --version`.
Resolve the requested directory and pass arguments literally. `$ARGUMENTS`
below is a placeholder for user-selected arguments, not shell code to evaluate.
Keep stdout, stderr, and exit status separate. Never display credential values.

Use a full report so completion and findings can be assessed alongside the score:

```bash
praxis scan full . --json --no-ai
```

Honor the requested directory and dependency options. Require
`scanComplete === true` and report skipped checks. Present the score and grade
with category deductions and the highest severity findings. An A/B grade is not
proof of security; a low score is not itself proof of exploitability. Describe
what was detected, review evidence, and suggest the relevant fixes and CI gate.
