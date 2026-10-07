# Praxis for VS Code

The extension runs the Praxis CLI and displays its findings as diagnostics.
Its version is independent of the CLI: this source release prepares extension
1.0.1 for use with CLI 1.2.4 or newer.

## Availability

The extension is not published to the Visual Studio Marketplace. This repository
contains source and build instructions; the GitHub CLI release does not publish
a VSIX. See [CLI installation](../README.md#install).

## Commands

- **Praxis: Scan Workspace** runs a full scan of the first workspace folder,
  including dependency auditing and configured LLM options.
- **Praxis: Scan Current File** scans the containing workspace with dependency
  auditing and AI classification disabled, then selects diagnostics for the file.
- **Praxis: Show Report** opens the most recent workspace report.
- **Auto-scan on save** uses the same workspace scan and file selection. It reads
  saved content on disk and can be costly for large projects; disable it if needed.

Scans require an open workspace and a preinstalled CLI. Commands run as executable
and argument arrays. The default `npx --no-install praxis-sec` launcher does not
download a package automatically. Configure `praxis.cliPath` if the CLI cannot be
resolved locally. Windows npm launchers resolve to the CLI's JavaScript entry point.

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `praxis.autoScanOnSave` | `true` | Scan saved files through their workspace |
| `praxis.severity` | `medium` | Minimum diagnostic severity |
| `praxis.showInlineHints` | `true` | Show inline hints |
| `praxis.deep` | `false` | Request provider-backed deep analysis for workspace scans |
| `praxis.cliPath` | empty | CLI executable or JavaScript entry point; empty uses npx without installation |

The report view escapes finding text and restricts remote content with a
Content-Security-Policy. A score is a summary of detected findings, not a security
certification. A failed scan must be investigated before relying on prior diagnostics.

## Build and check

From `vscode-extension/`:

```bash
npm ci
npm run compile
node --test tests/cli-runner.test.cjs
```

Packaging also requires the VS Code extension packaging tool (`vsce`) to be
installed separately; `npm run package` invokes it. Compilation and runtime
tests do not validate every interactive VS Code behavior.

## License

MIT. See [LICENSE](../LICENSE) and [third-party notices](../docs/THIRD_PARTY_NOTICES.md).
