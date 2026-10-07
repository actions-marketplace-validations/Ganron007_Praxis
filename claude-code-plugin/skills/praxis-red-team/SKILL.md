---
name: praxis-red-team
description: Run the static adversarial scanner pack and review findings and agent coverage.
argument-hint: "[path] [--agents <list>]"
---

# praxis-red-team

Use a preinstalled Praxis CLI 1.2.4 or newer; check `praxis --version`.
Resolve the requested directory and pass arguments literally. `$ARGUMENTS`
below is a placeholder for user-selected arguments, not shell code to evaluate.
Keep stdout, stderr, and exit status separate. Never display credential values.

For a local codebase use the static command:

```bash
praxis scan redteam . --json --no-ai
praxis scan redteam . --agents injection,auth,ssrf --json --no-ai
```

Replace the directory and agent selection with the user's request. Preserve
agent failure/skipped information and disclose excluded checks. Do not label
failed or unexecuted agents clean. Execution time depends on the project.

Present critical/high findings with file, line, rule, evidence, confidence and
suggested remediation. Review source before making authorized changes and
re-run the selected checks afterward. `praxis redteam <endpoint>` is a separate
live probe command requiring an authorized target; it is not this static skill.
