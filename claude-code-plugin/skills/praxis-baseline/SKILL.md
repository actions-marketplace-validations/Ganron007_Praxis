---
name: praxis-baseline
description: Review and manage accepted findings without presenting suppression as remediation.
argument-hint: "[path] [--diff] [--clear]"
---

# praxis-baseline

Use a preinstalled Praxis CLI 1.2.4 or newer; check `praxis --version`.
Resolve the requested directory and pass arguments literally. `$ARGUMENTS`
below is a placeholder for user-selected arguments, not shell code to evaluate.
Keep stdout, stderr, and exit status separate. Never display credential values.

Run the requested baseline operation on the selected directory:

```bash
praxis project baseline .
praxis project baseline . --diff
praxis project baseline . --clear
```

Create/update only findings the user authorized accepting. Report what was
accepted and why. Review the resulting `.praxis/baseline.json` before selectively
versioning it; it may include source-derived fingerprints. Diff mode reports
new/resolved findings, and clear removes the baseline.

For a gate use `praxis scan ci . --baseline --fail-on high`. A normal full scan
does not fail merely because new findings exist. Accepted debt still needs review,
and incomplete scans or an Action's `always-fail-on` floor cannot be bypassed by
a baseline. Do not automatically re-baseline unresolved issues after a failed fix.
