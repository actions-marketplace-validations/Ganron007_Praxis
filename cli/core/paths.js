/**
 * Honest, publishable paths for findings.
 *
 * A finding is not always about a file inside the scanned tree.
 * `MCP_SHADOW_CONFIG` reports the developer's own `~/.cursor/mcp.json`, because a
 * shadow MCP server configured outside version control is precisely the finding
 * worth reporting. That file sits above the scan root, and neither obvious way of
 * rendering it is acceptable:
 *
 *   path.relative(root, file)  ->  '../../../Users/alice/.cursor/mcp.json'
 *                                  leaks the username and the directory depth into
 *                                  a report that gets pasted into a CI comment.
 *   strip the drive letter     ->  'Users/alice/.cursor/mcp.json'
 *                                  does not exist, and falsely reads as
 *                                  repo-relative, so the finding is unlocatable.
 *
 * The only honest rendering of a path above the root is `~/…`. It identifies the
 * file, leaks neither the username nor the directory layout, and — unlike either
 * alternative — is identical on every machine, so a self-scan's findings do not
 * change identity when a colleague runs it.
 *
 * Applied once by the orchestrator, before findings reach any renderer, because
 * the terminal table, the HTML and JSON reports, CI annotations and SARIF all read
 * the same `finding.file`. `fix` and `remediate` build their own absolute paths and
 * never read this field, so normalising it cannot redirect a write.
 */

import os from 'os';
import path from 'path';

const toSlash = (p) => String(p).split(path.sep).join('/').replace(/\\/g, '/');

// `path.isAbsolute` is platform-specific: on POSIX it reports false for
// `C:/work/src/a.js`, because that is a legal relative filename there. Findings
// normally come from the host's own glob, but a path read back from a report or
// a cache can carry the other platform's shape, and treating it as relative would
// print a drive letter straight into the output. Same guard sarif.js uses.
const isAbsoluteLike = (s) => path.isAbsolute(s) || /^[a-zA-Z]:[\\/]/.test(s);

/**
 * Render a finding's file for display.
 *
 * @param {string} file  Absolute or already-relative path.
 * @param {string} [root] Absolute scan root, when known.
 * @returns {string} Root-relative when inside `root`, `~/…` when inside the home
 *   directory, otherwise the bare filename — never an absolute path.
 */
export function displayPath(file, root) {
  if (file === undefined || file === null || file === '') return file;

  const s = String(file);
  // Already display-shaped. Passing a relative path back through
  // `path.relative(root, ...)` would resolve it against the cwd, escape the root
  // and collapse it to a bare filename — the trap that made Code Scanning alerts
  // unlocatable.
  if (!isAbsoluteLike(s)) return toSlash(s);

  if (root) {
    const rel = path.relative(root, s);
    // `rel` starting with '..' means the file is outside the scan root.
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return toSlash(rel);
  }

  const home = os.homedir();
  if (home && s !== home && s.startsWith(home + path.sep)) {
    return '~/' + toSlash(s.slice(home.length + 1));
  }

  // Outside the root and outside home: identify the file without publishing the
  // local directory layout.
  return path.basename(s);
}

/**
 * Apply {@link displayPath} to every finding that carries a path.
 *
 * The orchestrator calls this once, at the boundary where findings stop being
 * internal state and become report output.
 *
 * @param {Array<object>} findings Mutated in place and returned.
 * @param {string} [root] Absolute scan root.
 */
export function normalizeFindingPaths(findings, root) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (f && typeof f === 'object' && f.file) f.file = displayPath(f.file, root);
  }
  return findings;
}

export default displayPath;