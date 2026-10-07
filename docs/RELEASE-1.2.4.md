# Praxis 1.2.4

This patch corrects cases where a scan could report success without examining the
requested target, and fixes project targeting in the older annotation loop.

- Full, secret, and CI scans require a directory. A file supplied as a scan root
  now produces an error instead of a false empty result. The VS Code current-file
  action scans its workspace and selects diagnostics for the requested file.
- Full-scan JSON includes `scanComplete`, `scanErrors`, and `dependencyAudit`.
  Failed discovery, failed agents, unavailable dependency audits, or failed
  requested legal scans mark the result incomplete and exit unsuccessfully.
  Findings alone still do not fail a normal scan; use `scan ci` for severity gates.
- Incomplete scans do not update scan cache, score history, or the playbook, and
  cannot start the annotation loop or satisfy fix verification. HTML reports show
  an incomplete warning; the web runner refuses failed-agent results.
  A failed annotation-loop verification also overrides `--fail-below`; JSON
  reports the failure once without inner-scan progress text. Reports are generated
  after verification so HTML and machine-readable status agree.
- `scan full --timeout` now reaches the orchestrator.
- Annotation targets resolve inside the requested project, including symlink
  destinations. Protected scanner/Git paths and unsupported comment formats such
  as JSON are rejected. Writes are atomic, and unchanged annotations are not
  counted as applied. Multiple annotations in one file are inserted from the
  bottom to preserve finding line numbers; replaying the same report is safe.
- In-root directories beginning with two dots retain their full relative path.
  Foreign Windows backslash and UNC paths fall back to a safe basename.
- Memory-poisoning document discovery respects ignore rules and dependency
  directories instead of reading ignored nested artifacts as project context.
- File discovery uses `tinyglobby` in place of the vulnerable
  `fast-glob → micromatch → braces` chain. Directory expansion stays disabled,
  brace limits and symlink boundaries remain enforced, and discovery has tests
  for hidden files, exclusions, extglobs, literal directories, and async/sync parity.
- Exact provider-documented non-working credentials are recognized from an
  attributed data catalog. Unknown credentials on the same line still produce
  findings. History scans process all matches, distinguish credentials that share
  the same masked display, and report operational failures as incomplete.
- Upload rules require request/upload filename evidence instead of treating
  local package metadata or any variable named `filename` as a vulnerable upload.
- The independently versioned VS Code extension is prepared as 1.0.1. CLI calls
  use executable/argument arrays instead of shell text, and default npx execution
  forbids automatic package installation. Report fields are escaped, severity
  classes are sanitized, and a Content-Security-Policy blocks remote content.
  Windows npm launchers resolve to the CLI's JavaScript entry point, preserving
  literal arguments without invoking a command shell.

- MCP suppression now writes on the matched line, preserves line endings, rejects
  unsupported formats and non-integer lines, and writes atomically. MCP repository
  scans use the current scoring API, expose agent failures as incomplete, and
  reject file roots.
- Hermes handlers return structured audit/manifest results, read the explicit saved
  report path, apply severity filtering, and register against corrected integrity
  hashes. Default Hermes audits disclose skipped dependency checks.
- Documentation uses canonical commands, preserves errors, corrects CI examples,
  describes data egress and score limitations, and provides a release procedure.
  The Claude Code plugin instructions are independently versioned as 3.0.1.

## Validation and limitations

Release validation covers the CLI test suite on Node 18, 20, 22 and 24, lint,
extension compilation and runtime tests, scan determinism, a complete zero-critical
self-scan, local PR Action base/head comparison, and installed-package smoke tests.
The production dependency chain was removed rather than overridden; the reviewed
full dependency audit, including development dependencies, reports zero advisories.
Audit results reflect the advisory database at the time of verification.

AWS explicitly identifies the formerly reported fixture credential as
[non-working example data](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/RESTAuthentication.html).
Only that exact identifier in AWS credential rules is exempted; tests retain
unknown credentials on the same line. History and test files are not excluded.

Noncritical heuristic findings and existing lint warnings remain. A self-scan
score is not a measurement of scanner accuracy. Live LLM provider behavior and
interactive VS Code UI behavior were not validated by these release checks.

## Distribution

The GitHub release, immutable `v1.2.4` tag, and floating Marketplace Action `v1`
are prepared from the same commit after its hosted CI succeeds. The release
includes the npm package tarball and a SHA-256 checksum. **npm publication is a
separate maintainer step**; a GitHub release does not change npm latest.

Use `Ganron007/Praxis@v1.2.4` to pin the Action. For CLI use before npm publication,
install the attached tarball or run from a checkout of this tag. After publication,
install `praxis-sec@1.2.4` from npm. See [the release procedure](RELEASING.md) for
the checks and publishing handoff.
