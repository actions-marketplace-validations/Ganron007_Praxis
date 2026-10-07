---
name: praxis-fix
description: Preview deterministic Praxis fixes, apply authorized changes, and re-scan for verification.
argument-hint: "[path] [--all] [--dry-run]"
---

# praxis-fix

Use a preinstalled Praxis CLI 1.2.4 or newer; check `praxis --version`.
Resolve the requested directory and pass arguments literally. `$ARGUMENTS`
below is a placeholder for user-selected arguments, not shell code to evaluate.
Keep stdout, stderr, and exit status separate. Never display credential values.

Start with a preview for the requested project:

```bash
praxis fix quick . --all --dry-run
```

Show files, proposed changes, required dependencies and possible behavior changes.
Keep the same directory and options when applying. If the user already authorized
these reviewed changes, proceed; otherwise obtain approval for the concrete diff.

```bash
praxis fix quick . --all --yes
praxis scan full . --json --no-ai
```

Require a complete verification scan and relevant project tests before reporting
resolution. Disclose remaining findings and skipped checks. Deterministic quick
fixes have a different backup mechanism from the interactive fix ledger; do not
claim `fix undo` reverses every quick fix. Use `praxis fix .` for interactive
LLM plans, and `praxis fix rotate .` for credential rotation guidance.
