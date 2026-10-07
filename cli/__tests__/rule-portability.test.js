/**
 * Tests for the portable rule export/import round-trip.
 *
 * The load-bearing properties here are honesty properties, not just "it runs":
 *   - every exported pattern is validated before it ships, and the export REFUSES to
 *     write a bundle containing a malformed one
 *   - rule ids are identifiers, because that is what suppressions and baselines key on
 *   - Semgrep severity and security-severity agree
 *   - the manifest declares the Praxis-only layers instead of implying full coverage
 *   - import rejects what it cannot execute, with a reason, never in degraded form
 *   - the round trip is lossless: export -> import -> run yields real findings
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const {
  toPortablePattern, validatePattern, yamlSingleQuoted, toRuleId,
  collectPortableRules, dedupeRules, toSemgrepYAML, securitySeverity, writeBundle,
} = await import('../utils/rule-registry.js');
const { loadPortableBundle, toJsPattern, renderPlugin } = await import('../utils/rule-import.js');

const temps = [];
const mkTmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-rules-'));
  temps.push(d);
  return d;
};
after(() => { for (const d of temps) fs.rmSync(d, { recursive: true, force: true }); });

// =============================================================================
// Pattern translation
// =============================================================================

describe('rule export — pattern translation', () => {
  it('turns the JS i flag into a PCRE2 inline group', () => {
    assert.equal(toPortablePattern('foo', 'gi').pattern, '(?i)foo');
    assert.equal(toPortablePattern('foo', 'g').pattern, 'foo');
    assert.equal(toPortablePattern('foo', 'gim').pattern, '(?i)(?m)foo');
  });

  it('records what happened to each flag rather than dropping it silently', () => {
    const notes = toPortablePattern('foo', 'gims').notes.join(' ');
    assert.match(notes, /g flag dropped/);
    assert.match(notes, /s flag/);
  });

  it('rewrites JS \\u{...} into PCRE2 \\x{...}', () => {
    const { pattern, notes } = toPortablePattern('[\\u{E0001}-\\u{E007F}]', 'u');
    assert.match(pattern, /\\x\{E0001\}/);
    assert.ok(notes.some(n => /x\{/.test(n)));
  });

  it('validates a PCRE2 inline-flag pattern that JavaScript itself rejects', () => {
    // `new RegExp('(?i)foo')` throws "Invalid group"; the export is PCRE2, so this
    // must still be reported valid.
    assert.equal(validatePattern('(?i)foo').status, 'valid');
    assert.equal(validatePattern('(?i)(?m)foo').status, 'valid', 'multiple flag groups');
    assert.equal(validatePattern('(?m)(?s)foo').status, 'valid', 'two distinct flags');
  });

  it('reports a genuinely malformed pattern as invalid', () => {
    assert.equal(validatePattern('(unclosed').status, 'invalid');
    assert.equal(validatePattern('[a-').status, 'invalid');
  });

  it('reports a PCRE2-only construct as unverifiable, not invalid', () => {
    // Valid PCRE2 that JavaScript cannot compile, with or without the `u` flag.
    // Calling these "invalid" would make a user delete a working rule.
    for (const pcre2 of ['(?>foo)', '(?R)', '[[:alpha:]]+', '\\Afoo']) {
      assert.equal(validatePattern(pcre2).status, 'unverifiable',
        `${pcre2} should be unverifiable, not invalid`);
    }
  });

  it('calls a construct valid when the validator can actually compile it', () => {
    // `(?x)` is stripped as a known inline flag, leaving a body JS compiles — so this
    // is genuinely verifiable and must not be downgraded to "unverifiable".
    assert.equal(validatePattern('(?x) foo').status, 'valid');
  });

  it('accepts the supplementary-plane unicode range, which JS can express after all', () => {
    // With the `u` flag JS compiles [\u{E0001}-\u{E007F}] fine, so this is `valid`.
    // An earlier expectation of `unverifiable` here was simply wrong.
    assert.equal(validatePattern('[\\x{E0001}-\\x{E007F}]').status, 'valid');
  });

  it('round-trips a pattern back to JavaScript with its flags intact', () => {
    const { pattern } = toPortablePattern('FOO', 'gi');
    const back = toJsPattern(pattern);
    assert.equal(back.pattern, 'FOO');
    assert.ok(back.flags.includes('i'), 'case-insensitivity must not be lost in the round trip');
    assert.ok(back.flags.includes('g'));
  });

  it('round-trips a case-insensitive rule behaviourally', () => {
    const { pattern } = toPortablePattern('secret_key', 'gi');
    const { pattern: jsPattern, flags } = toJsPattern(pattern);
    // `g` makes test() advance lastIndex, so compare with match() instead.
    assert.ok('AWS_SECRET_KEY = "x"'.match(new RegExp(jsPattern, flags)), 'uppercase must still match');
    assert.ok('secret_key'.match(new RegExp(jsPattern, flags)), 'lowercase must still match');
  });
});

// =============================================================================
// YAML + ids
// =============================================================================

describe('rule export — YAML and ids', () => {
  it('escapes single quotes in a single-quoted YAML scalar', () => {
    assert.equal(yamlSingleQuoted("it's"), "'it''s'");
    assert.equal(yamlSingleQuoted('back\\slash'), "'back\\slash'", 'backslashes stay literal');
  });

  it('slugifies a human label into an identifier', () => {
    assert.equal(toRuleId({ name: 'AWS Access Key ID' }), 'AWS_ACCESS_KEY_ID');
    assert.equal(toRuleId({ rule: 'CMD_INJECTION' }), 'CMD_INJECTION');
    assert.equal(toRuleId({}), null);
  });

  it('uses the same numeric severity scale as the SARIF output', () => {
    assert.equal(securitySeverity('critical'), '9.5');
    assert.equal(securitySeverity('high'), '7.5');
    assert.equal(securitySeverity('medium'), '5.0');
    assert.equal(securitySeverity('low'), '2.5');
    assert.equal(securitySeverity('nonsense'), '5.0', 'unknown must not read as low-risk');
  });
});

// =============================================================================
// Collection
// =============================================================================

describe('rule export — collection', () => {
  it('collects the real rule inventory with no module errors', async () => {
    const { rules, errors } = await collectPortableRules();
    assert.deepEqual(errors, [], 'every agent rule table must load');
    assert.ok(rules.length > 300, `expected the full inventory, got ${rules.length}`);
    assert.ok(rules.every(r => r.id), 'every rule needs an id');
    assert.ok(rules.every(r => r.origin), 'every rule must record where it came from');
  });

  it('validates every collected rule', async () => {
    const { rules } = await collectPortableRules();
    const bad = rules.filter(r => r.validationStatus === 'invalid');
    assert.deepEqual(bad.map(r => `${r.id}: ${r.validationError}`), [],
      'no shipped rule may export as malformed');
  });

  it('resolves duplicate ids instead of silently shadowing a rule', () => {
    const { rules, collisions } = dedupeRules([
      { id: 'A', origin: 'one.js' },
      { id: 'A', origin: 'two.js' },
    ]);
    assert.equal(collisions.length, 1);
    assert.equal(rules[0].id, 'A');
    assert.notEqual(rules[1].id, 'A', 'the second rule must be addressable');
  });
});

// =============================================================================
// Bundle output
// =============================================================================

describe('rule export — bundle', () => {
  const sample = [
    {
      id: 'R_CRIT', title: 'Critical', severity: 'critical', description: 'bad',
      cwe: 'CWE-94', owasp: 'A03:2021', origin: 'a.js:P', portablePattern: '(?i)bad',
      jsFlags: 'gi', requiresEntropyCheck: false, valid: true,
      verifiable: true, validationStatus: 'valid', validationError: null, notes: [],
    },
    {
      id: 'R_LOW', title: 'Low', severity: 'low', description: 'meh',
      cwe: null, owasp: null, origin: 'b.js:P', portablePattern: 'meh',
      jsFlags: 'g', requiresEntropyCheck: true, valid: true,
      verifiable: true, validationStatus: 'valid', validationError: null, notes: [],
    },
  ];

  it('emits Semgrep-shaped YAML', () => {
    const yaml = toSemgrepYAML(sample, { toolVersion: '1.2.3' });
    assert.match(yaml, /- id: R_CRIT/);
    assert.match(yaml, /pattern-regex: '\(\?i\)bad'/);
    assert.match(yaml, /severity: ERROR/);
    assert.match(yaml, /severity: INFO/);
    assert.match(yaml, /security-severity: '9\.5'/);
    assert.match(yaml, /cwe: 'CWE-94'/);
  });

  it('agrees on severity between the Semgrep field and security-severity', () => {
    const yaml = toSemgrepYAML(sample);
    const blocks = yaml.split('- id: ');
    const crit = blocks.find(b => b.startsWith('R_CRIT'));
    assert.match(crit, /severity: ERROR/);
    assert.match(crit, /security-severity: '9.5'/);
  });

  it('states in the file header that this is the pattern subset only', () => {
    const yaml = toSemgrepYAML(sample);
    assert.match(yaml, /pattern rules only/i);
    assert.match(yaml, /AST \/ taint/);
    assert.match(yaml, /probe corpus/);
  });

  it('writes yaml + json + manifest, and the json is re-importable', () => {
    const dir = mkTmp();
    const { yamlPath, jsonPath, manifestPath } = writeBundle({
      rules: sample, collisions: [], errors: [], skipped: [], outDir: dir, toolVersion: '1.2.3',
    });
    for (const p of [yamlPath, jsonPath, manifestPath]) assert.ok(fs.existsSync(p), `${p} missing`);

    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    assert.ok(manifest.praxisOnlyLayers.length >= 3);
    assert.ok(manifest.praxisOnlyLayers.some(l => /AST/.test(l.layer)));
    assert.ok(manifest.praxisOnlyLayers.some(l => /probe/.test(l.layer)));
    assert.ok(manifest.praxisOnlyLayers.some(l => /[Ee]ntropy/.test(l.layer)));
    assert.ok(manifest.praxisOnlyLayers.every(l => typeof l.reason === 'string' && l.reason.length > 10),
      'every declared layer needs a real reason');

    const loaded = loadPortableBundle(jsonPath);
    assert.equal(loaded.ok, true);
    assert.equal(loaded.accepted.length, 2);
  });
});

// =============================================================================
// Import
// =============================================================================

describe('rule import', () => {
  it('accepts pattern rules from the canonical JSON bundle', () => {
    const dir = mkTmp();
    const file = path.join(dir, 'b.json');
    fs.writeFileSync(file, JSON.stringify({
      generator: 'praxis rules export',
      rules: [{ id: 'R1', pattern: '(?i)foo', severity: 'high', description: 'd' }],
    }));
    const r = loadPortableBundle(file);
    assert.equal(r.ok, true);
    assert.equal(r.accepted.length, 1);
    assert.equal(r.accepted[0].id, 'R1');
    assert.ok(r.accepted[0].jsFlags.includes('i'), 'flags must survive');
  });

  it('rejects Semgrep YAML with an explanation, not a silent failure', () => {
    const dir = mkTmp();
    const file = path.join(dir, 'rules.yaml');
    fs.writeFileSync(file, '- id: R1\n');
    const r = loadPortableBundle(file);
    assert.equal(r.ok, false);
    assert.match(r.error, /YAML is an export format, not an import format/);
  });

  it('rejects rules it cannot execute, with a stated reason', () => {
    const dir = mkTmp();
    const file = path.join(dir, 'b.json');
    fs.writeFileSync(file, JSON.stringify({
      rules: [
        { id: 'OK', pattern: 'foo' },
        { id: 'NO_PATTERN', severity: 'high' },
        { id: 'BAD_PATTERN', pattern: '(unclosed' },
        { id: '', pattern: 'x' },
      ],
    }));
    const r = loadPortableBundle(file);
    assert.equal(r.ok, true);
    assert.equal(r.accepted.length, 1);
    assert.equal(r.accepted[0].id, 'OK');
    const reasons = Object.fromEntries(r.rejected.map(x => [x.id, x.reason]));
    assert.match(reasons.NO_PATTERN, /cannot be expressed as a static pattern/);
    assert.match(reasons.BAD_PATTERN, /does not compile/);
    assert.ok(r.rejected.some(x => x.reason === 'missing id'));
  });

  it('emits a plugin whose rules are real RegExp objects', () => {
    const plugin = renderPlugin([
      { id: 'R1', title: 'T', severity: 'high', description: 'd', fix: null, cwe: null, owasp: null, jsPattern: 'foo', jsFlags: 'gi' },
    ]);
    assert.match(plugin, /new RegExp\("foo", "gi"\)/, 'regex must be constructed, not a string');
    assert.match(plugin, /export default class/);
    // A bare string would satisfy scanFileWithPatterns until it set lastIndex.
    assert.ok(!/"regex":\s*"/.test(plugin), 'regex must not be a quoted string');
  });

  it('the generated plugin has no unresolved placeholders', () => {
    const plugin = renderPlugin([
      { id: 'R1', title: 'T', severity: 'low', description: 'd', fix: null, cwe: null, owasp: null, jsPattern: 'x', jsFlags: 'g' },
    ]);
    assert.ok(!/\$\{[A-Z_]+\}/.test(plugin), 'no template placeholders may survive');
  });
});