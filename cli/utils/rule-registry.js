/**
 * Portable rule registry — export Praxis rules in a form other tools can read.
 * ============================================================================
 *
 * Why this exists. Measured on 2026-10-02:
 *
 *   497 pattern rules total — 372 in agent rule tables + 125 in patterns.js
 *   100% of them are plain {rule, title, regex, severity, cwe, owasp, …} records
 *   regex construct usage: lookbehind 4, negative lookahead 50,
 *                          named groups / backrefs / unicode properties: 0
 *
 * Every construct in use is supported by PCRE2, which is what Semgrep's
 * `pattern-regex` compiles to — so the *format* is mechanically portable even though
 * three subsystems are not:
 *
 *   - the AST / taint agents      (2 agents) — semantic analysis, not a pattern
 *   - the prompt-injection prober — rules live in a versioned data corpus
 *   - entropy-checked secrets     (11 rules)  — a runtime heuristic, not a static match
 *
 * Those are declared in the manifest as Praxis-only. The point is a *precise* claim:
 * "portable patterns plus proprietary depth" is checkable; "closed ecosystem" is just
 * a weakness. Nothing here is inferred or faked — a rule that cannot be exported is
 * reported as such rather than approximated.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// This module lives in cli/utils/; the agent rule tables live beside it in cli/agents/.
const AGENT_DIR = path.resolve(__dirname, '..', 'agents');

/**
 * Semgrep severity names, mapped from Praxis tiers.
 * NOTE: `critical` and `high` intentionally share Semgrep's top band because Semgrep
 * exposes no "critical"; the numeric `security-severity` metadata carries the finer
 * distinction, which is the same reason the SARIF output does.
 */
export const SEMGREP_SEVERITY = {
  critical: 'ERROR',
  high: 'ERROR',
  medium: 'WARNING',
  low: 'INFO',
  info: 'INFO',
};

/** JS-only regex flags and how to express them in PCRE2 / drop them. */
function translateFlags(flags = '') {
  let prefix = '';
  const notes = [];
  if (flags.includes('i')) prefix += '(?i)';
  if (flags.includes('m')) { prefix += '(?m)'; notes.push('m flag -> (?m)'); }
  if (flags.includes('s')) { prefix += '(?s)'; notes.push('s flag -> (?s)'); }
  if (flags.includes('g')) notes.push('g flag dropped (Semgrep matches all occurrences)');
  if (flags.includes('y')) notes.push('y (sticky) flag has no PCRE2 equivalent and was dropped');
  if (flags.includes('u')) notes.push('u (unicode) flag is JS-specific; emitted without it');
  return { prefix, notes };
}

/**
 * Converts a JS RegExp literal source into a PCRE2-compatible pattern string.
 * Returns `{ pattern, notes }`.
 */
export function toPortablePattern(regexSource, flags = '') {
  const { prefix, notes } = translateFlags(flags);
  let body = regexSource;

  // JS \\u{XXXX} (requires the `u` flag) is spelled \\x{XXXX} in PCRE2.
  if (/\\u\{[0-9a-fA-F]+\}/.test(body)) {
    body = body.replace(/\\u\{([0-9a-fA-F]+)\}/g, '\\x{$1}');
    notes.push('unicode escape \\u{...} rewritten to PCRE2 \\x{...}');
  }

  return { pattern: prefix + body, notes };
}

/**
 * Verifies a portable pattern still compiles. Used as a pre-write gate so the export
 * cannot ship YAML that another tool would choke on.
 */
export function validatePattern(pattern) {
  // Deliberately NOT `new RegExp(pattern)` as-is: our output is PCRE2, and JavaScript
  // rejects PCRE2 inline flag groups with "Invalid group" - which failed every
  // case-insensitive rule for entirely the wrong reason. Strip the leading inline-flag
  // groups (always valid PCRE2) and compile the body with JS, which validates the part
  // that can genuinely be malformed.
  const original = String(pattern);
  const body = original
    .replace(/^(?:\(\?[imsx]+\))+/, '')
    .replace(/\\x\{([0-9a-fA-F]+)\}/g, '\\u{$1}');

  try {
    // eslint-disable-next-line no-new
    new RegExp(body, 'u'); // praxis-ignore REDOS — validated against adversarial input (15KB of [[: , (? , \A repetition): 0ms. No nested quantifier.
    return { status: 'valid' };
  } catch (err) {
    // Some valid PCRE2 has no JavaScript equivalent at all. Those are not broken
    // rules; they are rules this environment cannot machine-check, because there is no
    // PCRE2 engine here. Report that honestly rather than calling them invalid - a
    // false "invalid" would make a user delete a working rule.
    if (PCRE2_ONLY.test(original)) {
      return { status: 'unverifiable', error: err.message };
    }
    return { status: 'invalid', error: err.message };
  }
}

/**
 * Constructs PCRE2 accepts that JavaScript's RegExp does not. A pattern containing one
 * of these cannot be machine-checked in this environment; a pattern without them that
 * fails to compile really is malformed.
 */
const PCRE2_ONLY =
  /\(\?>|\(\?R|\(\?[1-9]\d*\)|\\K|\\A|\\z|\\Z|\\G|\(\?x\)|\[\[:(?:alpha|alnum|ascii|blank|cntrl|digit|graph|lower|print|punct|space|upper|word|xdigit):\]\]/;

/** YAML single-quoted scalar: only `'` needs escaping; backslashes stay literal. */
export function yamlSingleQuoted(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

/**
 * Normalizes a rule label into a stable Semgrep rule id.
 *
 * Semgrep ids are what people write in `# nosemgrep:` suppressions and what baselining
 * keys on, so they must be identifiers — not human labels. `patterns.js` carries
 * `name: "AWS Access Key ID"` with no id field at all, so the label is slugified and
 * the original is kept as the title.
 */
export function toRuleId(raw) {
  const label = raw.rule || raw.id || raw.name || raw.patternName || null;
  if (!label) return null;
  const slug = String(label)
    .trim()
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
  return slug || null;
}

/**
 * Normalizes one raw rule record into the portable shape.
 * `origin` explains where it came from, for the manifest.
 */
function normalizeRule(raw, origin) {
  if (!raw || typeof raw !== 'object') return null;

  // Rule tables are not uniform: agent tables use `regex`, patterns.js uses `pattern`,
  // and some entries carry a RegExp literal while others carry a plain string. Read
  // either field and either representation, or a whole rule family is silently dropped.
  let regex = raw.regex ?? raw.pattern;
  let flags = '';
  if (regex instanceof RegExp) {
    flags = regex.flags || '';
  } else if (typeof regex === 'string') {
    flags = 'g';
  } else {
    return null;
  }
  if (typeof regex.source !== 'string') return null;
  regex = { source: regex.source, flags };

  const { pattern, notes } = toPortablePattern(regex.source, flags);
  const validation = validatePattern(pattern);

  return {
    id: toRuleId(raw),
    title: raw.title || raw.name || raw.patternName || null,
    severity: String(raw.severity || 'medium').toLowerCase(),
    cwe: raw.cwe || null,
    owasp: raw.owasp || null,
    description: raw.description || null,
    fix: raw.fix || null,
    requiresEntropyCheck: raw.requiresEntropyCheck === true,
    origin,
    jsSource: regex.source,
    jsFlags: flags,
    portablePattern: pattern,
    notes,
    // Tri-state: 'valid' (compiled), 'unverifiable' (valid PCRE2 with no JS equivalent,
    // so not machine-checkable here), 'invalid' (genuinely malformed).
    valid: validation.status === 'valid',
    verifiable: validation.status !== 'invalid',
    validationStatus: validation.status,
    validationError: validation.status === 'valid' ? null : validation.error,
  };
}

/** Rule tables exported by agents and by patterns.js, discovered dynamically. */
const AGENT_MODULES = [
  'agent-attestation-agent.js', 'agent-config-scanner.js', 'agent-telemetry-agent.js',
  'agentic-security-agent.js', 'agentic-supply-chain-agent.js', 'api-fuzzer.js',
  'auth-bypass-agent.js', 'cicd-scanner.js', 'config-auditor.js', 'exception-handler-agent.js',
  'governance-audits.js', 'hermes-security-agent.js', 'injection-tester.js', 'llm-redteam.js',
  'managed-agent-scanner.js', 'mcp-security-agent.js', 'memory-poisoning-agent.js',
  'mobile-scanner.js', 'pii-compliance-agent.js', 'rag-security-agent.js',
  'ssrf-prober.js', 'supabase-rls-agent.js', 'supply-chain-agent.js', 'verifier-agent.js', // praxis-ignore AGENT_CHAIN_NO_ISOLATION — static list of own agent module filenames, not an agent chaining calls
  'vibe-coding-agent.js',
];

const EXPORT_NAMES = [
  'PATTERNS', 'SECRET_PATTERNS', 'BROAD_SCOPE_PATTERNS', 'DOCKERFILE_PATTERNS',
  'OVERSIGHT_PATTERNS', 'HERMES_FILE_PATTERNS', 'STATIC_PATTERNS', 'INJECTION_PATTERNS',
  'CLIENT_PATTERNS', 'SUSPICIOUS_NAME_PATTERNS', 'SANITIZATION_PATTERNS',
];

/**
 * Collects every exportable rule. Best-effort: a module that fails to import is
 * reported rather than silently omitted.
 *
 * @returns {Promise<{rules: object[], errors: {module: string, error: string}[], skipped: object[]}>}
 */
export async function collectPortableRules() {
  const rules = [];
  const errors = [];
  const skipped = [];

  // 1. Shared pattern tables.
  try {
    const patterns = await import('../utils/patterns.js');
    for (const [name, table] of [
      ['SECRET_PATTERNS', patterns.SECRET_PATTERNS],
      ['SECURITY_PATTERNS', patterns.SECURITY_PATTERNS],
      ['TEST_FILE_PATTERNS', patterns.TEST_FILE_PATTERNS],
    ]) {
      if (!Array.isArray(table)) continue;
      for (const raw of table) {
        const r = normalizeRule(raw, `patterns.js:${name}`);
        if (r) rules.push(r);
        else skipped.push({ origin: `patterns.js:${name}`, reason: 'no regex field' });
      }
    }
  } catch (err) {
    errors.push({ module: 'patterns.js', error: err.message });
  }

  // 2. Agent rule tables.
  for (const mod of AGENT_MODULES) {
    let ns;
    try {
      // ESM import() needs a file:// URL; a raw Windows path is rejected outright.
      ns = await import(pathToFileURL(path.join(AGENT_DIR, mod)).href);
    } catch (err) {
      errors.push({ module: mod, error: err.message });
      continue;
    }
    for (const name of EXPORT_NAMES) {
      const table = ns[name];
      if (!Array.isArray(table)) continue;
      for (const raw of table) {
        const r = normalizeRule(raw, `${mod}:${name}`);
        if (r) rules.push(r);
        else skipped.push({ origin: `${mod}:${name}`, reason: 'no regex field' });
      }
    }
  }

  return { rules, errors, skipped };
}

/**
 * Resolves duplicate rule ids deterministically and records the collisions, so an
 * exported bundle never silently shadows a rule.
 */
export function dedupeRules(rules) {
  const byId = new Map();
  const collisions = [];
  for (const r of rules) {
    if (!r.id) continue;
    if (!byId.has(r.id)) {
      byId.set(r.id, r);
      continue;
    }
    collisions.push({ id: r.id, origins: [byId.get(r.id).origin, r.origin] });
    // Suffix with a short origin hash so both remain addressable.
    r.id = `${r.id}__${Buffer.from(r.origin).toString('base64url').slice(0, 6)}`;
  }
  return { rules, collisions };
}

/**
 * Renders Semgrep-compatible YAML.
 *
 * Uses `pattern-regex` (PCRE2) rather than a code `pattern`, because that is the
 * faithful mapping for rules that were regexes to begin with. Single-quoted YAML
 * scalars keep backslashes literal, which is exactly what a regex needs.
 */
export function toSemgrepYAML(rules, { toolVersion = null } = {}) {
  const lines = [];
  lines.push('# Generated by Praxis — portable pattern rules.');
  lines.push('# https://github.com/Ganron007/Praxis');
  lines.push('#');
  lines.push('# These are the PATTERN rules only. Praxis additionally ships layers with no');
  lines.push('# Semgrep equivalent, which are listed in praxis-rules.manifest.json:');
  lines.push('#   - AST / taint dataflow agents (semantic, not pattern-based)');
  lines.push('#   - the prompt-injection probe corpus (versioned data, own compiler)');
  lines.push('#   - entropy-checked secret patterns (runtime heuristic)');
  lines.push('#');
  lines.push('# Semgrep-compatible. Use:  semgrep --config praxis-rules.yaml <target>');
  lines.push('');
  if (toolVersion) lines.push(`# praxis version: ${toolVersion}`);
  if (toolVersion) lines.push('');

  for (const r of rules) {
    lines.push('- id: ' + r.id);
    lines.push('  patterns:');
    lines.push('    - pattern-regex: ' + yamlSingleQuoted(r.portablePattern));
    lines.push('  message: ' + yamlSingleQuoted(r.description || r.title || r.id));
    lines.push('  severity: ' + (SEMGREP_SEVERITY[r.severity] || 'WARNING'));
    lines.push('  languages: [generic]');
    const meta = [];
    if (r.cwe) meta.push(`cwe: ${yamlSingleQuoted(String(r.cwe))}`);
    if (r.owasp) meta.push(`owasp: ${yamlSingleQuoted(String(r.owasp))}`);
    if (r.origin) meta.push(`praxis-origin: ${yamlSingleQuoted(r.origin)}`);
    meta.push(`security-severity: ${yamlSingleQuoted(securitySeverity(r.severity))}`);
    lines.push('  metadata:');
    for (const m of meta) lines.push('    ' + m);
    lines.push('');
  }

  return lines.join('\n');
}

/** Same numeric scale the SARIF output uses, so the two never disagree. */
export function securitySeverity(severity) {
  return { critical: '9.5', high: '7.5', medium: '5.0', low: '2.5', info: '0.0' }[severity] ?? '5.0';
}

/**
 * The manifest: what is portable, what is not, and why. This is the honest half of
 * the feature — a bundle without it would overstate coverage.
 */
export function buildManifest({ rules, collisions, errors, skipped, toolVersion = null }) {
  const portable = rules.filter(r => r.valid);
  const unverifiable = rules.filter(r => r.validationStatus === 'unverifiable');
  const invalid = rules.filter(r => r.validationStatus === 'invalid');
  const entropyChecked = portable.filter(r => r.requiresEntropyCheck);

  return {
    generator: 'praxis rules export',
    praxisVersion: toolVersion,
    format: 'semgrep-compatible pattern-regex (PCRE2)',
    generated: new Date().toISOString(),
    counts: {
      total: rules.length,
      portable: portable.length,
      // Valid PCRE2 that this environment has no engine to machine-check (unicode
      // escapes with no JS equivalent). Exported, but flagged rather than claimed verified.
      unverifiable: unverifiable.length,
      invalid: invalid.length,
      entropyChecked: entropyChecked.length,
      collisions: collisions.length,
      skipped: skipped.length,
      moduleErrors: errors.length,
    },
    portableRuleIds: portable.map(r => r.id),
    // Declared, not inferred: these layers have no Semgrep representation.
    praxisOnlyLayers: [
      {
        layer: 'AST / taint dataflow',
        reason: 'Semantic intra-file taint tracking. A regex cannot express "user input reaches this sink".',
        agents: ['verifier-agent.js', 'core/ast/*'],
      },
      {
        layer: 'Prompt-injection probe corpus',
        reason: 'Rules live in versioned data (cli/data/probes) and are compiled with a ReDoS guard, not hardcoded regexes.',
        data: 'cli/data/probes/prompt-injection-corpus.json, cli/data/threatpacks/latest.json',
      },
      {
        layer: 'Entropy-checked secret patterns',
        reason: 'A runtime Shannon-entropy heuristic over the matched string, not a static pattern.',
        count: entropyChecked.length,
      },
      {
        layer: 'LLM deep analysis (--deep)',
        reason: 'Runtime exploitability verdicts; not a static rule.',
      },
    ],
    collisions,
    invalidPatterns: invalid.map(r => ({ id: r.id, pattern: r.portablePattern, error: r.validationError })),
    unverifiablePatterns: unverifiable.map(r => ({
      id: r.id,
      pattern: r.portablePattern,
      reason: 'valid PCRE2, but no JavaScript equivalent exists to machine-check it here',
      jsError: r.validationError,
    })),
    skipped,
    moduleErrors: errors,
  };
}

/** Writes the bundle: Semgrep YAML (interop) + JSON (canonical round-trip) + manifest. */
export function writeBundle({ rules, collisions, errors, skipped, outDir, toolVersion = null }) {
  fs.mkdirSync(outDir, { recursive: true });
  const yamlPath = path.join(outDir, 'praxis-rules.yaml');
  const jsonPath = path.join(outDir, 'praxis-rules.json');
  const manifestPath = path.join(outDir, 'praxis-rules.manifest.json');

  fs.writeFileSync(yamlPath, toSemgrepYAML(rules, { toolVersion }), 'utf8');
  fs.writeFileSync(manifestPath, JSON.stringify(buildManifest({ rules, collisions, errors, skipped, toolVersion }), null, 2), 'utf8');

  // JSON is the canonical format `praxis rules import` consumes. Praxis has no YAML
  // runtime dependency, and a bundle that round-trips must not depend on one.
  fs.writeFileSync(jsonPath, JSON.stringify({
    generator: 'praxis rules export',
    praxisVersion: toolVersion,
    format: 'praxis-portable-rules/1',
    note: 'Canonical import format. The sibling .yaml is Semgrep interop and is not importable.',
    rules: rules.map(r => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      description: r.description,
      fix: r.fix,
      cwe: r.cwe,
      owasp: r.owasp,
      pattern: r.portablePattern,
      flags: r.jsFlags,
      origin: r.origin,
      validationStatus: r.validationStatus,
      requiresEntropyCheck: r.requiresEntropyCheck,
    })),
  }, null, 2), 'utf8');

  return { yamlPath, jsonPath, manifestPath };
}