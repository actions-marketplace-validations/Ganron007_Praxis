# Contributing to Praxis

Thanks for considering a contribution. Praxis is a single-binary, AI-native
security CLI — ESM Node.js ≥18, no CLI build step, runs from source.

## Quick start

```bash
npm ci
npm test
npm run lint
node cli/bin/praxis.js scan .   # dogfood — CI runs this, keep it green
```

New test files under `cli/__tests__/` **must** be added to the `test` script in
`package.json`, or CI will never run them.

## Conventions

- ESM throughout, 2-space indent, single quotes. `npm run lint` is the source
  of truth (0 errors; warnings are reviewed case-by-case).
- Extend the registries instead of inlining code paths in commands:
  - `cli/agents/index.js` — add a scanner by extending `BaseAgent`
  - `cli/core/output/index.js` — add an output formatter
  - `cli/utils/intel/index.js` — add a threat-intel source
  - `cli/utils/standards/index.js` — add a standards mapper
- Use `cli/core/fs.js` (`validatePath` / `validateDir` / `ensureDir`) for path
  handling.
- One change per PR; explain the reasoning in the description, not just the
  diff.
- CLI commands are registered in `cli/bin/praxis.js`. Top-level legacy aliases
  live there too — keep them in sync with their grouped counterparts.

## Authoring a new agent

1. Create `cli/agents/<your-agent>.js` extending `BaseAgent` (see
   `cli/agents/base-agent.js` for the finding shape and `shouldRun` contract).
2. Register it in `BUILT_IN_AGENTS` (`cli/agents/index.js`).
3. Add a smoke test in `cli/__tests__/agents.test.js` (positive + negative
   case) and wire it into `package.json` if it is a new test file.
4. Update the agent table in `README.md` and the agent count everywhere it
   appears (`cli/core/branding.js`, `cli/utils/output.js`, `action.yml`,
   `claude-code-plugin/`, `vscode-extension/package.json`, `docs/USAGE.md`).

## Tests

```bash
npm test                                 # node --test
node cli/bin/praxis.js scan .            # dogfood self-scan (CI runs this)
node scripts/check-determinism.mjs .     # two scans must agree on file::rule
```

CI runs the test matrix on Node 18, 20, 22 and 24, plus a determinism gate and a package
build. A detection change is expected to alter results — the determinism gate exists so
that identical inputs produce stable finding identities. Intended rule changes
between commits do not excuse drift between two runs of the same checkout.

Before releasing, run `npm run release:check` and follow
[the release procedure](../docs/RELEASING.md). It also checks the editor build,
runtime tests, dependency audit, and an installed package.

Keep secret redaction, scan-completion status, and path boundaries intact. All
HTML output must escape interpolated values and use the shared theme/severity
sanitizer. Vendored data changes must update
[third-party notices](../docs/THIRD_PARTY_NOTICES.md).

CI requires a complete self-scan with zero critical findings; finding totals can
vary with repository history and local configuration. Review a finding before
using `.praxisignore` or an inline `praxis-ignore` annotation. The annotation must be a **trailing
comment on the matched line** — `base-agent.js` checks the finding's own line, so placing it
on the preceding line does nothing at all.

## Security

Found a vulnerability? See `.github/SECURITY.md` — do not open a public issue
for active exploits.
