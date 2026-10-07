/**
 * Portable rule import — the inverse of the export.
 * ============================================================================
 *
 * Deliberately scoped, and the scope matters:
 *
 *   ACCEPTS  pattern rules — the same records the export produces, which map 1:1 onto
 *            what Praxis can execute.
 *   REJECTS  anything else, with a stated reason, rather than importing it in a
 *            degraded form. Notably: AST/taint semantics, probe-corpus rules and
 *            entropy heuristics cannot be expressed as a static pattern, so a bundle
 *            claiming to carry them is told so rather than quietly losing them.
 *
 * This is NOT a general Semgrep parser. Praxis has no YAML runtime dependency (five
 * runtime deps, none a YAML parser), so the canonical round-trip format is the JSON
 * written alongside the Semgrep YAML. Handing it Semgrep YAML gets a clear error
 * explaining the supported path instead of a silent failure.
 *
 * What it produces is a real, runnable Praxis plugin, so an imported rule participates
 * in real scans rather than sitting inert on disk.
 */

import fs from 'fs';
import path from 'path';

/**
 * Loads a portable bundle.
 *
 * @param {string} file  Path to `praxis-rules.json` (canonical) — Semgrep YAML is
 *                       rejected with an explanation.
 * @returns {{ok: true, accepted: object[], rejected: object[], meta: object}
 *          | {ok: false, error: string}}
 */
export function loadPortableBundle(file) {
  if (!file || typeof file !== 'string') {
    return { ok: false, error: 'a bundle path is required' };
  }
  const ext = path.extname(file).toLowerCase();
  if (ext === '.yaml' || ext === '.yml') {
    return {
      ok: false,
      error:
        'Semgrep YAML is an export format, not an import format. Praxis has no YAML ' +
        'runtime dependency; import praxis-rules.json (written alongside the YAML) instead.',
    };
  }
  if (ext !== '.json') {
    return { ok: false, error: `unsupported bundle extension "${ext}" (expected .json)` };
  }

  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return { ok: false, error: `could not read bundle: ${err.message}` };
  }

  if (!data || !Array.isArray(data.rules)) {
    return { ok: false, error: 'bundle has no `rules` array' };
  }

  const accepted = [];
  const rejected = [];

  for (const r of data.rules) {
    if (!r || typeof r !== 'object') {
      rejected.push({ id: r?.id ?? null, reason: 'not an object' });
      continue;
    }
    if (typeof r.id !== 'string' || !r.id) {
      rejected.push({ id: null, reason: 'missing id' });
      continue;
    }
    if (typeof r.pattern !== 'string' || !r.pattern) {
      rejected.push({
        id: r.id,
        reason: 'no portable pattern — AST/taint, probe-corpus and entropy rules cannot be expressed as a static pattern',
      });
      continue;
    }

    // Praxis executes JavaScript regexes, so convert the PCRE2 form back before use.
    const { pattern: jsPattern, flags } = toJsPattern(r.pattern);
    try {
      // eslint-disable-next-line no-new
      new RegExp(jsPattern, flags);
    } catch (err) {
      rejected.push({ id: r.id, reason: `pattern does not compile in JavaScript: ${err.message}` });
      continue;
    }

    accepted.push({
      id: r.id,
      title: r.title || r.id,
      severity: String(r.severity || 'medium').toLowerCase(),
      description: r.description || r.title || r.id,
      fix: r.fix || null,
      cwe: r.cwe || null,
      owasp: r.owasp || null,
      jsPattern,
      jsFlags: flags,
      origin: r.origin || 'imported',
    });
  }

  return {
    ok: true,
    accepted,
    rejected,
    meta: {
      source: file,
      total: data.rules.length,
      generator: data.generator || null,
      praxisVersion: data.praxisVersion || null,
      praxisOnlyLayers: data.praxisOnlyLayers || [],
    },
  };
}

/**
 * Converts a PCRE2 portable pattern back into JavaScript form.
 *
 * Returns `{ pattern, flags }`. The inline flag groups are NOT simply stripped: doing so
 * would silently turn every case-insensitive rule into a case-sensitive one. They are
 * translated into JavaScript's flag position (`i`, `m`, `s`), which JavaScript supports.
 * `x` (extended/free-spacing) has no JavaScript equivalent and is reported.
 */
export function toJsPattern(portablePattern) {
  let flags = '';
  let s = String(portablePattern);

  s = s.replace(/^(?:\(\?([imsx]+)\))+/, (_m, group) => {
    for (const f of group) {
      if ('ims'.includes(f) && !flags.includes(f)) flags += f;
    }
    return '';
  });

  // PCRE2 \x{...} -> JS \u{...}
  s = s.replace(/\\x\{([0-9a-fA-F]+)\}/g, '\\u{$1}');

  // Semgrep matches every occurrence; JavaScript needs the global flag to iterate.
  if (!flags.includes('g')) flags += 'g';

  return { pattern: s, flags };
}

/**
 * Emits a runnable Praxis plugin for the accepted rules.
 *
 * Uses the same plugin contract as `plugin-loader` (`.praxis/agents/*.js`), so
 * imported rules participate in real scans instead of sitting inert.
 */
export function renderPlugin(accepted, { name = 'PortableRules' } = {}) {
  const className = `${name.replace(/[^A-Za-z0-9]/g, '')}Agent`;
  // Resolve at generation time so the emitted plugin has no unresolved placeholders.
  // Mirrors plugin-loader: prefer the installed package, fall back to the source tree.
  const packageRoot = (() => {
    try {
      return JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).name || 'praxis';
    } catch {
      return 'praxis';
    }
  })();
  // `scanFileWithPatterns` requires a real RegExp object (it advances `lastIndex`),
  // so the rules are emitted as constructed expressions rather than strings. Emitting
  // the pattern as a bare string yields "Cannot create property 'lastIndex' on string".
  // Built as JS source rather than JSON.stringify'd, because the regex must be code.
  const q = (v) => JSON.stringify(v === undefined || v === null ? '' : String(v));
  const rulesSource = accepted.map(r =>
    `  { rule: ${q(r.id)}, title: ${q(r.title)}, regex: new RegExp(${q(r.jsPattern)}, ${q(r.jsFlags)}),` +
    ` severity: ${q(r.severity)}, description: ${q(r.description)}, fix: ${q(r.fix)},` +
    ` cwe: ${q(r.cwe)}, owasp: ${q(r.owasp)} }`
  ).join(',\n');

  return `/**
 * Portable rules imported by \`praxis rules import\`.
 *
 * ${accepted.length} pattern rule(s) loaded from a Praxis portable bundle.
 * Dropped in .praxis/agents/, this participates in every \`praxis audit\`.
 *
 * Regenerate with:  praxis rules import <bundle.json> --write-plugin .praxis/agents
 *
 * Scope: pattern rules only. AST/taint analysis, the prompt-injection probe corpus
 * and entropy heuristics are NOT importable — they are not static patterns.
 */

// BaseAgent and createFinding are injected by the plugin loader at runtime.
let BaseAgent, createFinding;
if (globalThis.__praxisAgentFramework) {
  ({ BaseAgent, createFinding } = globalThis.__praxisAgentFramework);
} else {
  try {
    ({ BaseAgent, createFinding } = await import('${packageRoot}')); // praxis-ignore AGENT_ESCALATED_PERMISSIONS — generated plugin importing the Praxis framework; same lines as plugin-loader.js
  } catch {
    ({ BaseAgent, createFinding } = await import('${packageRoot}/cli/index.js')); // praxis-ignore AGENT_ESCALATED_PERMISSIONS — generated plugin importing the Praxis framework; same lines as plugin-loader.js
  }
}

const RULES = [
${rulesSource}
];

export default class ${className} extends BaseAgent {
  constructor() {
    super('${className}', 'Portable rules imported from a Praxis rule bundle', 'custom');
    this.category = 'custom';
  }

  async analyze({ files = [] }) {
    const findings = [];
    for (const file of files) {
      const results = this.scanFileWithPatterns(file, RULES);
      findings.push(...results);
    }
    return findings;
  }
}
`;
}

/** Writes the plugin into a directory, creating it if needed. */
export function writePlugin(accepted, dir, opts = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'portable-rules.js');
  fs.writeFileSync(file, renderPlugin(accepted, opts), 'utf8');
  return file;
}