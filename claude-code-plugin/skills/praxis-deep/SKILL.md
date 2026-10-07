---
name: praxis-deep
description: Run optional provider-backed analysis and distinguish model verdicts from verified results.
argument-hint: "[path] [--local] [--budget <cents>]"
---

# praxis-deep

Use a preinstalled Praxis CLI 1.2.4 or newer; check `praxis --version`.
Resolve the requested directory and pass arguments literally. `$ARGUMENTS`
below is a placeholder for user-selected arguments, not shell code to evaluate.
Keep stdout, stderr, and exit status separate. Never display credential values.

Check provider availability without printing keys. Cloud options include
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`/`GEMINI_API_KEY`, or
configured compatible providers. Local Ollama uses `--local`.

Explain that source context is sent to the configured provider, then run within
the user's authorized scope:

```bash
praxis scan full . --deep --json --no-ai --budget 100
praxis scan full . --deep --local --json --no-ai
```

`--no-ai` disables separate finding classification; deep analysis still uses
a provider. The budget is a configured control, not a guaranteed provider bill.
Require scan completion, disclose analysis errors/skips, and show actual
`deepAnalysis` fields and reasoning. Treat model verdicts, including
`confirmed` and `false_positive`, as advisory claims requiring source review.
Apply authorized fixes and verify through executable project checks and a
complete re-scan.
