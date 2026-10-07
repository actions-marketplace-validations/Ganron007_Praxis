/**
 * SARIF v2.1.0 output formatter.
 *
 * The single SARIF serializer for Praxis. Every emitting path must go
 * through here: `scan --sarif`, `scan ci --sarif`, `audit --sarif`, `redteam --sarif`,
 * `scan standard --sarif` and `--format sarif`. Four commands used to carry private
 * copies of this logic, which meant fixes applied here reached almost nobody — most
 * visibly `security-severity`, which the GitHub Action's `scan ci --sarif` call never
 * emitted. Do not reintroduce a local serializer.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import path from 'path';
import { toolVersion as toolVersion_ } from '../version.js';

const SARIF_VERSION = '2.1.0';

/**
 * Severity → SARIF `level` + GitHub `security-severity`.
 *
 * These are two different axes and both are needed:
 *   - `level` is the coarse SARIF gate (`error` / `warning` / `note`).
 *   - `security-severity` is the 0.0-10.0 number GitHub Code Scanning uses to rank,
 *     colour and filter alerts.
 *
 * Emitting `level` alone collapsed critical and high into the same bucket, so every
 * Code Scanning consumer saw compressed severity — the tiering the product is built on
 * was invisible exactly where people look for it. Both fields come from this one table
 * so they cannot drift apart.
 *
 * Emitted as a string because that is the form GitHub's own documentation uses.
 */
const SEVERITY = {
  critical: { level: 'error', securitySeverity: '9.5' },
  high: { level: 'error', securitySeverity: '7.5' },
  medium: { level: 'warning', securitySeverity: '5.0' },
  low: { level: 'note', securitySeverity: '2.5' },
  info: { level: 'note', securitySeverity: '0.0' },
};

/** Unknown or absent severity must not silently read as low-risk. */
const DEFAULT_SEVERITY = { level: 'warning', securitySeverity: '5.0' };

const forSeverity = (severity) => SEVERITY[severity] || DEFAULT_SEVERITY;

/**
 * Normalizes Praxis's internal finding shape and renders SARIF.
 *
 * Commands hold findings in two shapes: a flat list using `rule`/`title`/`file`, and
 * the per-file `[{ file, findings }]` shape the orchestrator returns. This accepts
 * either, so no command has to know the SARIF field names — which is what let four
 * private serializers drift apart in the first place.
 *
 * @param {object[]} findings
 * @param {object} [options]  forwarded to the serializer; pass `rootPath` or artifact
 *                            URIs will not be repo-relative.
 */
export function renderFindingsSARIF(findings, options = {}) {
  const flat = Array.isArray(findings) && findings.length > 0 && findings[0] && Array.isArray(findings[0].findings)
    ? findings.flatMap(({ file, findings: fileFindings }) =>
      (fileFindings || []).map((f) => ({ ...f, file: f.file || file })))
    : (findings || []);

  return renderSARIFDocument({
    findings: flat.map((f) => ({
      ruleId: f.ruleId || f.rule || f.patternName || f.pattern || f.type,
      title: f.title || f.patternName || f.rule,
      file: f.file,
      line: f.line,
      column: f.column,
      severity: f.severity,
      description: f.description,
      cwe: f.cwe,
      owasp: f.owasp,
      standards: f.standards,
      category: f.category,
    })),
  }, options);
}

function renderSARIFDocument(report, options = {}) {
  const {
    toolName = 'praxis',
    // Defaults to the real package version. This used to fall back to a hardcoded
    // '1.0.0', so any caller that forgot to pass `toolVersion` reported a confidently
    // wrong driver version in Code Scanning.
    toolVersion = report.version || toolVersion_(),
    informationUri = 'https://github.com/Ganron007/Praxis',
    rootPath = null,
  } = options;

  const findings = report.findings || [];
  const rules = collectRules(findings);
  const relativize = makeRelativizer(rootPath);

  const sarifReport = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            version: toolVersion,
            informationUri,
            rules,
          },
        },
        results: findings.map((f) => toResult(f, relativize)),
      },
    ],
  };

  return JSON.stringify(sarifReport, null, 2);
}

/**
 * Builds the artifact-URI normaliser.
 *
 * SARIF is uploaded to GitHub Code Scanning, so artifact URIs must be repo-relative.
 * When `rootPath` is supplied, findings are relativized against it. Without it we fall
 * back to stripping a leading drive letter or POSIX root and collapsing `..` segments.
 *
 * This fallback used to strip a hardcoded `/Praxis/` prefix. That was written for this
 * repository's own dogfooding and failed open for every real user: a Windows path
 * surfaced the username and the whole directory tree, and a POSIX path passed through
 * untouched — publishing the local filesystem layout into a target repository.
 */
function makeRelativizer(rootPath) {
  // A path that is already relative needs no relativizing. This matters: feeding
  // `src/nested/deep.js` to `path.relative(root, ...)` resolves it against the cwd,
  // escapes the root, and the fallback then reduces it to `deep.js` — losing the
  // directory and making the alert unlocatable in Code Scanning.
  const isAbsolute = (f) => path.isAbsolute(f) || /^[a-zA-Z]:[\\/]/.test(f);

  if (rootPath) {
    return (file) => {
      const s = String(file);
      if (!s) return s;
      if (!isAbsolute(s)) return s.split(path.sep).join('/');

      const rel = path.relative(rootPath, s);
      // A file outside the root still must not leak an absolute path; fall back to the
      // basename rather than emitting `../../..`.
      if (!rel || rel.startsWith('..')) return path.basename(s);
      return rel.split(path.sep).join('/');
    };
  }

  return (file) => {
    let s = String(file).split(path.sep).join('/');
    s = s.replace(/^[a-zA-Z]:\/*/, '').replace(/^\/+/, '');

    // Collapse `.`/`..` segments without escaping the repo.
    const out = [];
    for (const seg of s.split('/')) {
      if (seg === '' || seg === '.') continue;
      if (seg === '..') { out.pop(); continue; }
      out.push(seg);
    }
    return out.join('/') || path.basename(String(file));
  };
}

function collectRules(findings) {
  const seen = new Map();
  for (const f of findings) {
    const id = f.ruleId || f.pattern || f.type || 'finding';
    if (seen.has(id)) continue;
    // Collect tags for the rule definition so GitHub Security tab groups
    // Praxis findings by AI/LLM/MCP/supply-chain categories.
    const ruleTags = ['praxis'];
    if (f.category) ruleTags.push(f.category);
    if (f.owasp) ruleTags.push(f.owasp);
    if (f.standards) {
      for (const [, ids] of Object.entries(f.standards)) {
        for (const sid of ids) ruleTags.push(sid);
      }
    }
    const sev = forSeverity(f.severity);
    seen.set(id, {
      id,
      name: f.patternName || id,
      shortDescription: { text: f.patternName || id },
      fullDescription: { text: f.description || f.patternName || id },
      defaultConfiguration: {
        level: sev.level,
      },
      properties: {
        tags: [...new Set(ruleTags)], // dedup
        // GitHub Code Scanning ranks and filters on this numeric property.
        'security-severity': sev.securitySeverity,
      },
    });
  }
  return [...seen.values()];
}

function toResult(f, relativize) {
  const uri = relativize(f.file || f.path || '');

  const sev = forSeverity(f.severity);

  const result = {
    ruleId: f.ruleId || f.pattern || f.type || 'finding',
    level: sev.level,
    message: { text: f.description || f.message || f.patternName || 'finding' },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri, uriBaseId: '%SRCROOT%' },
          region: {
            startLine: f.line || 1,
            startColumn: f.column || 1,
          },
        },
      },
    ],
  };

  // Embed AI-security standard tags so SARIF consumers (GitHub Code Scanning,
  // SonarQube, etc.) can filter / display alignment per finding.
  const props = { 'security-severity': sev.securitySeverity };
  if (f.cwe) props.cwe = f.cwe;
  if (f.owasp) props.owasp = f.owasp;
  if (f.standards && Object.keys(f.standards).length > 0) {
    props.standards = f.standards;
    const tags = [];
    for (const [, ids] of Object.entries(f.standards)) {
      for (const id of ids) tags.push(id);
    }
    if (tags.length > 0) props.tags = tags;
  }
  result.properties = props;

  return result;
}

export default renderSARIFDocument;
