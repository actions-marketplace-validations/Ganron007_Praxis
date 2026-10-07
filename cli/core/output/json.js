/**
 * JSON output formatter.
 *
 * Reports are emitted with `schemaVersion` so consumers can pin to a
 * version. Bump the version when the shape changes in a breaking way.
 *
 * Scanner hardening: secret-category findings never expose their raw
 * matched value — `matched` is redacted centrally so no consumer of the
 * JSON report can leak a credential. Finding paths are normalised against the scan
 * root by the orchestrator, so no consumer can receive an absolute path either.
 */

import path from 'path';

const SCHEMA_VERSION = 3;

function redactFinding(f) {
  if (!f || typeof f !== 'object') return f;
  const isSecret = f.category === 'secrets' || f.category === 'secret'
    || /secret|api[_-]?key|token|password|credential/i.test(String(f.rule || ''));
  const out = { ...f };
  if (f.matched) {
    out.matched = isSecret
      ? `${String(f.matched).slice(0, 3)}***`
      : String(f.matched).slice(0, 160);
  }
  if (out.file) {
    // Paths arrive already normalised against the scan root by the orchestrator,
    // so this only has to unify separators. The three strippers that used to live
    // here were wrong for everyone but this repository:
    //   `^[a-zA-Z]:\/+`  turned `C:\Users\alice\.cursor\mcp.json` into
    //                   `Users/alice/.cursor/mcp.json` — leaking the username and
    //                   naming a repo-relative file that does not exist;
    //   the two `/Praxis/` rules were dogfooding hacks that silently truncated any
    //                   real path merely containing a directory called `Praxis`.
    // See cli/core/paths.js for the replacement.
    out.file = String(out.file).split(path.sep).join('/').replace(/\\/g, '/');
  }
  return out;
}

export default function json(report, options = {}) {
  const { pretty = true } = options;
  const enriched = {
    schemaVersion: SCHEMA_VERSION,
    ...report,
  };
  if (Array.isArray(enriched.findings)) {
    enriched.findings = enriched.findings.map(redactFinding);
  }
  return pretty
    ? JSON.stringify(enriched, null, 2)
    : JSON.stringify(enriched);
}

export { redactFinding, SCHEMA_VERSION };
