# Security Policy

Praxis is a security tool; its own security matters. We take reports
seriously and ask that you do the same — **no public disclosure before a fix
is shipped**.

## Reporting a vulnerability

- **Preferred:** use GitHub private vulnerability reporting on the
  `Ganron007/Praxis` repository (Security tab → "Report a vulnerability").
- **If private reporting is unavailable:** open a general issue requesting a
  private contact channel. Do not include exploit details, affected secrets, or
  a proof of concept in that public issue.

## Scope

- Anything in this repository, including `cli/`, `action.yml`,
  `claude-code-plugin/`, and `vscode-extension/`.
- Out of scope: findings in scanned third-party projects (that is Praxis
  working as intended), and general dependency CVEs reported by the tool
  itself.

## Expectations

- We aim to acknowledge reports within 48 hours and ship a fix as soon as we
  can reproduce and validate the issue.
- Please include: affected version(s), reproduction steps, and — for
  exploitable issues — a minimal proof of concept without real secrets.

## Safe harbor

Research performed in good faith under this policy — reporting through
private channels, without exploiting data or harming others — will not be
reported to GitHub's abuse team.
