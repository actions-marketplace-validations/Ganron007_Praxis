/**
 * Tests for cli/core/ — the new shared utilities introduced in the
 * praxis rebrand. Covers:
 *   - cli/core/fs.js          (validatePath, validateDir, ensureDir)
 *   - cli/core/errors.js      (safeCatch, safeCatchAsync, toError)
 *   - cli/core/output/index.js (formatter registry: render, listFormats, registerFormat)
 *   - cli/core/output/json.js
 *   - cli/core/output/sarif.js
 *   - cli/core/branding.js    (PRODUCT_NAME constant + banner doesn't throw)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

// =============================================================================
// fs.js
// =============================================================================

describe('cli/core/fs', async () => {
  const { validatePath, validateDir, ensureDir } = await import('../core/fs.js');

  it('validatePath returns absolute path for existing dir', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-fs-test-'));
    try {
      const resolved = validatePath(tmp);
      assert.equal(resolved, path.resolve(tmp));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('validatePath returns null for missing path when exitOnMissing=false', () => {
    const missing = path.join(os.tmpdir(), 'praxis-does-not-exist-' + Date.now());
    const result = validatePath(missing, { exitOnMissing: false });
    assert.equal(result, null);
  });

  it('validateDir rejects a regular file when exitOnMissing=false', () => {
    const tmpFile = path.join(os.tmpdir(), 'praxis-fs-file-' + Date.now() + '.txt');
    fs.writeFileSync(tmpFile, 'hi');
    try {
      const result = validateDir(tmpFile, { exitOnMissing: false });
      assert.equal(result, null);
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  it('ensureDir creates a missing directory and is idempotent', () => {
    const tmp = path.join(os.tmpdir(), 'praxis-ensure-' + Date.now(), 'a', 'b');
    try {
      ensureDir(tmp);
      assert.ok(fs.existsSync(tmp));
      // Idempotent — second call must not throw.
      ensureDir(tmp);
      assert.ok(fs.existsSync(tmp));
    } finally {
      fs.rmSync(path.dirname(path.dirname(tmp)), { recursive: true, force: true });
    }
  });
});

// =============================================================================
// errors.js
// =============================================================================

describe('cli/core/errors', async () => {
  const { safeCatch, safeCatchAsync, toError } = await import('../core/errors.js');

  it('safeCatch returns the function value on success', () => {
    assert.equal(safeCatch(() => 42, 0), 42);
  });

  it('safeCatch returns fallback on throw', () => {
    const result = safeCatch(() => { throw new Error('boom'); }, 'fallback');
    assert.equal(result, 'fallback');
  });

  it('safeCatchAsync awaits and returns value', async () => {
    const result = await safeCatchAsync(async () => 'ok', 'fail');
    assert.equal(result, 'ok');
  });

  it('safeCatchAsync returns fallback on async throw', async () => {
    const result = await safeCatchAsync(async () => { throw new Error('nope'); }, 'fail');
    assert.equal(result, 'fail');
  });

  it('toError wraps non-Error values', () => {
    assert.ok(toError('a string') instanceof Error);
    assert.ok(toError({ code: 1 }) instanceof Error);
    assert.ok(toError(new Error('already')) instanceof Error);
    assert.equal(toError('msg').message, 'msg');
  });
});

// =============================================================================
// output/index.js — formatter registry
// =============================================================================

describe('cli/core/output registry', async () => {
  const { render, listFormats, hasFormat, registerFormat } = await import('../core/output/index.js');

  it('lists the built-in formats', () => {
    const formats = listFormats();
    assert.ok(formats.includes('json'));
    assert.ok(formats.includes('sarif'));
  });

  it('hasFormat returns true for known and false for unknown', () => {
    assert.equal(hasFormat('json'), true);
    assert.equal(hasFormat('does-not-exist'), false);
  });

  it('render() throws for unknown format with helpful message', () => {
    assert.throws(
      () => render('xml', {}),
      /unknown format 'xml'.*available:/
    );
  });

  it('registerFormat extends the registry', () => {
    registerFormat('plain', (report) => `findings=${(report.findings || []).length}`);
    assert.equal(render('plain', { findings: [1, 2, 3] }), 'findings=3');
  });
});

// =============================================================================
// output/json.js
// =============================================================================

describe('cli/core/output/json', async () => {
  const { render } = await import('../core/output/index.js');

  it('emits schemaVersion and pretty-prints by default', () => {
    const out = render('json', { findings: [{ severity: 'high' }] });
    const parsed = JSON.parse(out);
    assert.equal(parsed.schemaVersion, 3);
    assert.equal(parsed.findings.length, 1);
    // Pretty-print check — newlines present.
    assert.ok(out.includes('\n'));
  });

  it('compact mode strips whitespace', () => {
    const out = render('json', { findings: [] }, { pretty: false });
    assert.ok(!out.includes('\n'));
  });
});

// =============================================================================
// output/sarif.js
// =============================================================================

describe('cli/core/output/sarif', async () => {
  const { render } = await import('../core/output/index.js');

  it('produces a valid SARIF v2.1.0 envelope', () => {
    const out = render('sarif', {
      findings: [
        {
          ruleId: 'aws-key',
          patternName: 'AWS Access Key',
          severity: 'critical',
          file: 'src/leaked.js',
          line: 12,
          description: 'Hardcoded AWS access key',
        },
      ],
    });
    const parsed = JSON.parse(out);
    assert.equal(parsed.version, '2.1.0');
    assert.equal(parsed.runs.length, 1);
    assert.equal(parsed.runs[0].tool.driver.name, 'praxis');
    assert.equal(parsed.runs[0].results.length, 1);
    assert.equal(parsed.runs[0].results[0].level, 'error'); // critical → error
    assert.equal(parsed.runs[0].results[0].locations[0].physicalLocation.region.startLine, 12);
  });

  it('deduplicates rules across multiple findings sharing a ruleId', () => {
    const out = render('sarif', {
      findings: [
        { ruleId: 'r1', severity: 'high', file: 'a.js', line: 1 },
        { ruleId: 'r1', severity: 'high', file: 'b.js', line: 2 },
        { ruleId: 'r2', severity: 'low', file: 'c.js', line: 3 },
      ],
    });
    const parsed = JSON.parse(out);
    assert.equal(parsed.runs[0].tool.driver.rules.length, 2);
  });

  // ── GitHub `security-severity` (P-IMP-058) ─────────────────────────────────
  // `level` alone collapsed critical and high into the same bucket, so every Code
  // Scanning consumer saw compressed severity. `security-severity` is the numeric
  // property GitHub ranks and filters on.
  describe('security-severity', () => {
    const rulesOf = (findings) => JSON.parse(render('sarif', { findings })).runs[0].tool.driver.rules;
    const resultsOf = (findings) => JSON.parse(render('sarif', { findings })).runs[0].results;
    const sevOf = (rules, id) => Number(rules.find(r => r.id === id)?.properties['security-severity']);

    const TIERS = [
      ['critical', 'R_CRIT'],
      ['high', 'R_HIGH'],
      ['medium', 'R_MED'],
      ['low', 'R_LOW'],
    ];

    it('emits a numeric security-severity on every rule and result', () => {
      const findings = TIERS.map(([severity, ruleId]) => ({ ruleId, severity, file: 'a.js', line: 1 }));
      for (const r of rulesOf(findings)) {
        assert.ok(r.properties['security-severity'] !== undefined, `${r.id} has no security-severity`);
        assert.ok(Number.isFinite(Number(r.properties['security-severity'])), `${r.id} is not numeric`);
      }
      for (const r of resultsOf(findings)) {
        assert.ok(r.properties['security-severity'] !== undefined, `${r.ruleId} result has no security-severity`);
      }
    });

    it('orders severities so GitHub can rank them', () => {
      const findings = TIERS.map(([severity, ruleId]) => ({ ruleId, severity, file: 'a.js', line: 1 }));
      const rules = rulesOf(findings);
      const crit = sevOf(rules, 'R_CRIT');
      const high = sevOf(rules, 'R_HIGH');
      const med = sevOf(rules, 'R_MED');
      const low = sevOf(rules, 'R_LOW');
      assert.ok(crit > high, 'critical must outrank high');
      assert.ok(high > med, 'high must outrank medium');
      assert.ok(med > low, 'medium must outrank low');
      assert.ok(low >= 0 && crit <= 10, 'values must sit in the 0.0-10.0 range GitHub expects');
    });

    it('separates critical from high even though they share a SARIF level', () => {
      // The whole point of the fix: same coarse gate, different rank.
      const rules = rulesOf([
        { ruleId: 'R_CRIT', severity: 'critical', file: 'a.js', line: 1 },
        { ruleId: 'R_HIGH', severity: 'high', file: 'a.js', line: 1 },
      ]);
      const crit = rules.find(r => r.id === 'R_CRIT');
      const high = rules.find(r => r.id === 'R_HIGH');
      assert.equal(crit.defaultConfiguration.level, high.defaultConfiguration.level);
      assert.notEqual(crit.properties['security-severity'], high.properties['security-severity']);
    });

    it('does not let a missing or unknown severity read as low-risk', () => {
      const rules = rulesOf([
        { ruleId: 'R_MISSING', file: 'a.js', line: 1 },
        { ruleId: 'R_UNKNOWN', severity: 'catastrophic', file: 'a.js', line: 1 },
      ]);
      for (const r of rules) {
        assert.ok(Number(r.properties['security-severity']) >= 5, `${r.id} defaulted too low`);
        assert.equal(r.defaultConfiguration.level, 'warning');
      }
    });

    it('keeps a result level consistent with its rule definition', () => {
      const findings = TIERS.map(([severity, ruleId]) => ({ ruleId, severity, file: 'a.js', line: 1 }));
      const rules = rulesOf(findings);
      for (const result of resultsOf(findings)) {
        const rule = rules.find(r => r.id === result.ruleId);
        assert.equal(result.level, rule.defaultConfiguration.level, `${result.ruleId} level drifted`);
        assert.equal(
          result.properties['security-severity'],
          rule.properties['security-severity'],
          `${result.ruleId} severity drifted`
        );
      }
    });

    it('preserves the pre-existing properties', () => {
      const results = resultsOf([
        { ruleId: 'R1', severity: 'high', file: 'a.js', line: 1, cwe: 'CWE-918', owasp: 'A10:2021' },
      ]);
      assert.equal(results[0].properties.cwe, 'CWE-918');
      assert.equal(results[0].properties.owasp, 'A10:2021');
    });
  });
});

// =============================================================================
// P-IMP-062 / P-IMP-063 — one SARIF serializer, reachable from every command
// =============================================================================
//
// Four commands carried private SARIF serializers. The `security-severity` fix
// landed in the registry and reached almost nobody — including the GitHub Action's
// `scan ci --sarif` call, which emitted 0 of 12 rules with a severity. These tests
// pin both the behaviour and the structure that let it happen.

describe('sarif consolidation', async () => {
  const { renderFindingsSARIF } = await import('../core/output/sarif.js');
  const COMMANDS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'commands');

  const parse = (json) => JSON.parse(json);
  const uriOf = (doc, i = 0) =>
    doc.runs[0].results[i].locations[0].physicalLocation.artifactLocation.uri;

  it('no command may define a private SARIF serializer', () => {
    // Structural guard for the actual root cause: a duplicated `runs: [{ ... }]`
    // literal with a `tool.driver` is how the drift started.
    const dir = COMMANDS_DIR;
    const offenders = [];
    for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.js'))) {
      const src = fs.readFileSync(path.join(dir, file), 'utf8');
      if (/runs:\s*\[\s*\{/.test(src) && /tool:\s*\{/.test(src) && /driver:\s*\{/.test(src)) {
        offenders.push(file);
      }
    }
    assert.deepEqual(offenders, [],
      `these commands build SARIF by hand — use core/output/sarif.js: ${offenders.join(', ')}`);
  });

  it('no command may hardcode a SARIF driver version', () => {
    const dir = COMMANDS_DIR;
    const offenders = [];
    for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.js'))) {
      const src = fs.readFileSync(path.join(dir, file), 'utf8');
      const m = src.match(/driver:\s*\{[^}]*version:\s*'([^']+)'/);
      if (m) offenders.push(`${file} -> ${m[1]}`);
    }
    assert.deepEqual(offenders, [], `hardcoded driver versions: ${offenders.join(', ')}`);
  });

  it('renders the flat finding shape used by ci.js and audit.js', () => {
    const out = parse(renderFindingsSARIF(
      [{ rule: 'R1', title: 'T', file: '/proj/src/a.js', line: 3, severity: 'critical', description: 'd' }],
      { rootPath: '/proj' },
    ));
    assert.equal(out.runs[0].results[0].ruleId, 'R1');
    assert.equal(out.runs[0].tool.driver.rules[0].properties['security-severity'], '9.5');
    assert.equal(uriOf(out) , 'src/a.js');
  });

  it('renders the nested orchestrator shape used by scan.js', () => {
    const out = parse(renderFindingsSARIF(
      [{ file: '/proj/src/b.js', findings: [{ patternName: 'Nested', severity: 'low', description: 'n', line: 9 }] }],
      { rootPath: '/proj' },
    ));
    assert.equal(out.runs[0].results[0].ruleId, 'Nested');
    assert.equal(out.runs[0].tool.driver.rules[0].properties['security-severity'], '2.5');
    assert.equal(uriOf(out), 'src/b.js');
  });

  it('relativizes artifact URIs against rootPath so no local path leaks', () => {
    // Built with path.join so the fixture uses the host separator: on POSIX a
    // backslash-style path is just a filename, and path.relative cannot relativize it.
    const root = path.join('C:', 'Users', 'alice', 'projects', 'myapp');
    const file = path.join(root, 'src', 'db.js');
    const out = parse(renderFindingsSARIF(
      [{ rule: 'R', file, severity: 'high' }],
      { rootPath: root },
    ));
    const uri = out.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri, 'src/db.js');
    assert.ok(!uri.includes('alice'), 'must not leak the local username');
    assert.ok(!uri.startsWith('/') && !/^[A-Za-z]:/.test(uri), 'must be repo-relative');
  });

  it('never emits an escaping or absolute URI', () => {
    // A finding outside the root must still not become an absolute path.
    const root = path.join('C:', 'proj');
    const outside = path.join('C:', 'elsewhere', 'secret.js');
    const out = parse(renderFindingsSARIF(
      [{ rule: 'R', file: outside, severity: 'high' }],
      { rootPath: root },
    ));
    const uri = out.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    assert.ok(!uri.includes('..'), `must not escape the root: ${uri}`);
    assert.ok(!/^[A-Za-z]:/.test(uri) && !uri.startsWith('/'), `must not be absolute: ${uri}`);
  });

  it('leaves an already-relative path intact when rootPath is supplied', () => {
    // Regression: `path.relative(root, 'src/nested/deep.js')` resolves the input against
    // the cwd, escapes the root, and the outside-root fallback then reduced it to
    // `deep.js` — an alert Code Scanning cannot locate.
    const root = path.join('C:', 'proj');
    const out = parse(renderFindingsSARIF(
      [{ rule: 'R', file: path.join('src', 'nested', 'deep.js'), severity: 'high' }],
      { rootPath: root },
    ));
    assert.equal(uriOf(out), 'src/nested/deep.js');
  });

  it('does not hardcode a repository name when no rootPath is supplied', () => {
    // The old normalizer stripped a literal `/Praxis/`, written for this repo alone.
    const file = path.join('C:', 'a', 'Praxis', 'b.js');
    const out = parse(renderFindingsSARIF([{ rule: 'R', file, severity: 'high' }]));
    const uri = uriOf(out);
    assert.ok(uri.includes('Praxis'), `a user path containing "Praxis" must not be truncated: ${uri}`);
  });
});


// =============================================================================
// action.yml — Marketplace publication requirements
// =============================================================================
//
// GitHub refuses to publish a listing if action.yml fails its schema checks, and the
// only feedback is a generic "needs changes" banner. These pin the constraints that
// actually bit: `description` is capped at 124 characters, and `author` plus
// `branding` are required for a listing (though not for using `uses:` locally).

describe('action.yml Marketplace contract', async () => {
  const yaml = (await import('js-yaml')).default;
  const actionPath = path.join(
    path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'action.yml',
  );
  const action = yaml.load(fs.readFileSync(actionPath, 'utf8'));

  it('parses as valid YAML', () => {
    assert.equal(typeof action, 'object');
    assert.ok(action.name);
  });

  it('description is within the 124-character Marketplace limit', () => {
    assert.ok(action.description.length < 125,
      `description is ${action.description.length} chars; Marketplace rejects >= 125`);
  });

  it('declares the fields a Marketplace listing requires', () => {
    assert.ok(action.author, 'author is required to publish a listing');
    assert.ok(action.branding?.icon, 'branding.icon is required');
    assert.ok(action.branding?.color, 'branding.color is required');
  });

  it('uses a real Feather icon for branding', () => {
    // GitHub validates this against the Feather set and rejects unknown names.
    assert.ok(['shield', 'lock', 'eye', 'alert-triangle', 'check-circle', 'zap']
      .includes(action.branding.icon),
    `"${action.branding.icon}" is not a recognised Feather icon`);
  });

  it('is a composite action with steps', () => {
    assert.equal(action.runs.using, 'composite');
    assert.ok(Array.isArray(action.runs.steps) && action.runs.steps.length > 0);
  });

  it('every input and output is documented', () => {
    for (const [name, spec] of Object.entries(action.inputs || {})) {
      assert.ok(spec?.description, `input "${name}" has no description`);
    }
    for (const [name, spec] of Object.entries(action.outputs || {})) {
      assert.ok(spec?.description, `output "${name}" has no description`);
    }
  });

  it('every inline `run:` step declares a shell', () => {
    // Composite actions require an explicit shell; without it the runner cannot
    // interpret the script.
    for (const [i, step] of action.runs.steps.entries()) {
      if (typeof step.run === 'string' && !step.uses) {
        assert.ok(step.shell, `step ${i + 1} ("${step.name || 'unnamed'}") has no shell`);
      }
    }
  });

  it('installs the package this repo publishes, not a same-named stranger', () => {
    // `praxis` on npm belongs to an unrelated React framework. The action must install
    // the renamed package or users silently get the wrong tool.
    const pkg = JSON.parse(fs.readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'), 'utf8',
    ));
    const installSteps = action.runs.steps.filter(s => /npm ci --prefix/.test(s.run || ''));
    assert.ok(installSteps.length > 0, 'action must install the CLI');
    assert.equal(pkg.name, 'praxis-sec', 'this checkout must be the published Praxis CLI');
    for (const step of installSteps) {
      assert.equal(step.env.PRAXIS_ACTION_PATH, '${{ github.action_path }}');
      assert.match(step.run, /npm ci --prefix "\$PRAXIS_ACTION_PATH"/, 'install the Action checkout from its lockfile');
    }
  });
});

// =============================================================================
// Architecture diagram — claims must match the code
// =============================================================================
//
// The diagram drifted twice before (a rule count that appeared nowhere in the
// codebase, a stale report description) and briefly rendered text outside a card
// border. These pin the claims to measured reality and check the geometry.

describe('architecture diagram', async () => {
  const svgPath = path.join(
    path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'assets', 'praxis-architecture.svg',
  );
  const svg = fs.readFileSync(svgPath, 'utf8');
  const visible = [...svg.matchAll(/<text[^>]*>([\s\S]*?)<\/text>/g)]
    .map(m => m[1]
      .replace(/<[^>]+>/g, '')                                  // strip nested markup
      .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&middot;/g, '·').replace(/&ge;/g, '>=').replace(/&rarr;/g, '->')
      .replace(/\s+/g, ' ').trim())
    .filter(Boolean);

  it('is structurally valid', () => {
    const opens = (svg.match(/<[a-zA-Z]/g) || []).length;
    const closes = (svg.match(/<\//g) || []).length + (svg.match(/\/>/g) || []).length;
    assert.equal(opens, closes, 'unbalanced tags');
    assert.match(svg, /<svg[^>]*xmlns=/);
    // Every referenced paint server must be defined, or the browser renders nothing.
    const defined = new Set([...svg.matchAll(/<(?:linear|radial)Gradient id="([^"]+)"/g)].map(m => m[1]));
    for (const m of svg.matchAll(/url\(#([^)]+)\)/g)) {
      const id = m[1];
      if (id.endsWith('Grad') || id === 'shadow' || id.startsWith('arrDown') || id === 'topGlow') {
        assert.ok(defined.has(id) || svg.includes(`id="${id}"`), `undefined paint server: ${id}`);
      }
    }
  });

  it('canvas height matches the background rect', () => {
    const vb = svg.match(/viewBox="0 0 ([\d.]+) ([\d.]+)/);
    const bg = svg.match(/<rect width="(\d+)" height="(\d+)"/);
    assert.ok(vb && bg);
    assert.equal(bg[2], vb[2], 'background must cover the full canvas');
  });

  it('renders no text below a card border', () => {
    const DESCENDER = 5;
    const cards = [...svg.matchAll(/<g transform="translate\((\d+), (\d+)\)" filter="url\(#shadow\)"/g)];
    assert.ok(cards.length >= 6, 'expected the six-stage diagram');
    for (const c of cards) {
      const i = svg.indexOf(`translate(${c[1]}, ${c[2]})" filter`);
      const block = svg.slice(i, i + 2600);
      const h = +((block.match(/width="780" height="(\d+)"/) || [])[1]);
      const ys = [...block.matchAll(/<text x="0" y="(\d+)"/g)].map(m => +m[1]);
      const inner = +((block.match(/<g transform="translate\(24, (\d+)\)"/) || [])[1] || 0);
      if (!ys.length || !h) continue;
      const lowest = inner + Math.max(...ys);
      assert.ok(lowest + DESCENDER <= h,
        `card at y=${c[2]} overflows by ${lowest + DESCENDER - h}px (text bottom ${lowest + DESCENDER}, height ${h})`);
    }
  });

  it('states the real rule and feed counts', async () => {
    const patterns = await import('../utils/patterns.js');
    const shared = patterns.SECRET_PATTERNS.length + patterns.SECURITY_PATTERNS.length;
    assert.ok(visible.some(t => t.includes(`${shared} secret & code patterns`)),
      `diagram must state the real shared-pattern count (${shared})`);

    // svgPath is <repo>/assets/..., so one `..` reaches the repo root.
    const intelDir = path.join(path.dirname(svgPath), '..', 'cli', 'utils', 'intel', 'sources');
    const sources = fs.readdirSync(intelDir).filter(f => f.endsWith('.js'));
    const core = sources.filter(f => !/tier = 'optional'/.test(fs.readFileSync(path.join(intelDir, f), 'utf8'))).length;
    assert.ok(visible.some(t => t.includes(`${core} cached Threat Intel feeds`)),
      `diagram must state the real core-feed count (${core})`);
  });

  it('states the real exportable rule count', async () => {
    const { collectPortableRules } = await import('../utils/rule-registry.js');
    const { rules } = await collectPortableRules();
    assert.ok(visible.some(t => t.includes(`${rules.length} pattern rules`)),
      `diagram must state the real exportable rule count (${rules.length})`);
  });

  it('mentions the surfaces that were previously missing', () => {
    for (const needle of ['praxis web', 'praxis rules export', 'security-severity', 'fingerprint']) {
      assert.ok(visible.some(t => t.includes(needle)), `diagram omits "${needle}"`);
    }
  });

  it('no bullet is longer than one already known to fit the same 780px card', () => {
    // Absolute width estimation is unreliable; compare against known-good lines.
    const bullets = visible.filter(t => t.startsWith('•'));
    const longestKnown = bullets
      .filter(t => !/praxis web|rules export|security-severity|fingerprint|125 secret/.test(t))
      .reduce((a, b) => Math.max(a, b.length), 0);
    for (const b of bullets) {
      assert.ok(b.length <= longestKnown,
        `bullet may overflow: "${b.slice(0, 60)}" (${b.length} vs known-good ${longestKnown})`);
    }
  });
});

// =============================================================================
// P-IMP-065 — one source for the tool version
// =============================================================================
//
// Seven modules read `package.json` for the version independently, and one more
// (`core/output/sarif.js`) did not read it at all and fell back to a hardcoded
// `'1.0.0'`. Three different wrong values were in circulation: '1.0.0' in ci.js and
// sarif.js, '1.1.0' in html-reporter.js. At release time that is several chances to
// publish a wrong version — in SARIF provenance, in the cache key, in the report footer.

describe('tool version', async () => {
  const { toolVersion, isNewerVersion, UNKNOWN_VERSION } = await import('../core/version.js');

  it('resolves the real package version', () => {
    const pkg = JSON.parse(fs.readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'), 'utf8',
    ));
    assert.equal(toolVersion(), pkg.version);
  });

  it('never returns a placeholder that could pass for a version', () => {
    const v = toolVersion();
    assert.match(v, /^\d+\.\d+\.\d+/, `must be semver-shaped, got ${v}`);
    assert.notEqual(v, UNKNOWN_VERSION);
  });

  it('is stable across calls (cached, so it cannot change mid-run)', () => {
    assert.equal(toolVersion(), toolVersion());
  });

  it('is importable from every module that reports a version', async () => {
    // If a module kept its own lookup, these would disagree.
    const modules = [
      '../core/output/sarif.js',
      '../utils/scan-fingerprint.js',
      '../utils/cache-manager.js',
    ];
    for (const m of modules) {
      assert.doesNotThrow(() => fs.readFileSync(
        path.join(path.dirname(fileURLToPath(import.meta.url)), m), 'utf8',
      ), `${m} must remain readable`);
    }
  });

  it('no module outside core/version.js may resolve its own package.json version', () => {
    const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
    const offenders = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name !== '__tests__') walk(full);
          continue;
        }
        if (!entry.name.endsWith('.js')) continue;
        if (full.endsWith(path.join('core', 'version.js'))) continue;
        const src = fs.readFileSync(full, 'utf8');
        // Only a SELF-referential read counts. Reading a scanned target's package.json
        // (`path.join(rootPath, 'package.json')`) is legitimate and must not be flagged.
        const selfRead = /(?:__dirname|import\.meta\.url)[\s\S]{0,300}?package\.json/;
        const versionRead = /package\.json[\s\S]{0,200}?\.version|\.version[\s\S]{0,200}?package\.json/;
        if (selfRead.test(src) && versionRead.test(src)) {
          offenders.push(path.relative(root, full));
        }
      }
    };
    walk(root);
    assert.deepEqual(offenders, [],
      `these modules resolve their own version — import cli/core/version.js instead: ${offenders.join(', ')}`);
  });

  it('no module may hardcode a version literal as a fallback', () => {
    const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
    const offenders = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name !== '__tests__') walk(full);
          continue;
        }
        if (!entry.name.endsWith('.js')) continue;
        if (full.endsWith(path.join('core', 'version.js'))) continue;
        const src = fs.readFileSync(full, 'utf8');
        // A bare version literal used as a *fallback*, not a SARIF spec/schema version.
        const m = src.match(/toolVersion\s*=\s*[^,\n]*\|\|\s*'([\d.]+)'|PACKAGE_VERSION\s*=\s*[\s\S]{0,160}?\?\s*'([\d.]+)'|PKG_VERSION[\s\S]{0,200}?return\s+'([\d.]+)'/);
        if (m) offenders.push(`${path.relative(root, full)} -> ${m[1] || m[2] || m[3]}`);
      }
    };
    walk(root);
    assert.deepEqual(offenders, [],
      `hardcoded version fallbacks will drift at release time: ${offenders.join(', ')}`);
  });

  it('the tool version appears in SARIF and matches package.json', async () => {
    // Regression: the shared version helper was assigned to `toolVersion` without
    // being called, so the driver had a function where a version belonged and
    // JSON.stringify silently dropped the field entirely.
    const { render } = await import('../core/output/index.js');
    const pkg = JSON.parse(fs.readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'), 'utf8',
    ));
    const doc = JSON.parse(render('sarif', { findings: [{ ruleId: 'R', severity: 'high', file: 'a.js', line: 1 }] }));
    const version = doc.runs[0].tool.driver.version;
    assert.equal(version, pkg.version, 'SARIF driver version must be the real package version');
    assert.match(version, /^\d+\.\d+\.\d+$/, `must be a real version, got ${version}`);
  });

  it('every module reports the same version', async () => {
    // A wrong version in the cache key, the report footer or SARIF provenance is the
    // exact drift this consolidation exists to prevent.
    const pkg = JSON.parse(fs.readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'), 'utf8',
    ));
    const fingerprint = await import('../utils/scan-fingerprint.js');
    assert.equal(fingerprint.buildScanFingerprint({ filesScanned: 1 }).tool, pkg.version);
    assert.equal((await import('../core/version.js')).toolVersion(), pkg.version);
  });

  it('compares versions correctly for the update check', () => {
    assert.equal(isNewerVersion('1.0.1', '1.0.0'), true);
    assert.equal(isNewerVersion('1.1.0', '1.0.9'), true);
    assert.equal(isNewerVersion('2.0.0', '1.9.9'), true);
    assert.equal(isNewerVersion('1.0.0', '1.0.0'), false);
    assert.equal(isNewerVersion('0.9.0', '1.0.0'), false);
    assert.equal(isNewerVersion('1.0.0', '1.0.1'), false);
    assert.equal(isNewerVersion(UNKNOWN_VERSION, '1.0.0'), false, 'unknown must not claim an update exists');
    assert.equal(isNewerVersion('1.0.0', UNKNOWN_VERSION), true, 'a known current beats an unknown candidate');
  });
});

describe('cli/core/branding', async () => {
  const branding = await import('../core/branding.js');

  it('exports product name and tagline', () => {
    assert.equal(branding.PRODUCT_NAME, 'praxis');
    assert.equal(typeof branding.TAGLINE, 'string');
    assert.ok(branding.TAGLINE.length > 0);
  });

  it('printBanner does not throw with or without a version', () => {
    // Capture stdout to keep test output clean, but still assert no throw.
    const origLog = console.log;
    console.log = () => {};
    try {
      assert.doesNotThrow(() => branding.printBanner());
      assert.doesNotThrow(() => branding.printBanner('1.0.0'));
    } finally {
      console.log = origLog;
    }
  });
});

// =============================================================================
// policy-engine.js
// =============================================================================

describe('cli/agents/policy-engine', async () => {
  const { PolicyEngine } = await import('../agents/policy-engine.js');

  it('enforces minimumScore and failOn severity', () => {
    const policy = new PolicyEngine({
      minimumScore: 70,
      failOn: 'high',
    });

    const scoreResult = { score: 65, grade: 'C' };
    const findings = [
      { severity: 'high', title: 'High risk finding', file: 'app.js', line: 10, rule: 'r1' },
      { severity: 'low', title: 'Low risk finding', file: 'app.js', line: 12, rule: 'r2' },
    ];

    const violations = policy.evaluate(scoreResult, findings);
    assert.equal(violations.length, 2);
    assert.equal(violations[0].type, 'minimum_score');
    assert.equal(violations[1].type, 'severity_threshold');
  });

  it('enforces requiredScans list', () => {
    const policy = new PolicyEngine({
      requiredScans: ['secrets', 'injection', 'deps'],
    });

    const scoreResult = { score: 90, grade: 'A' };
    
    // Test: missing 'injection' scan
    const violations = policy.evaluate(scoreResult, [], {
      agentResults: [{ agent: 'secrets-scanner', category: 'secrets', success: true }],
      depsRun: true,
      secretsRun: true,
    });
    
    assert.equal(violations.length, 1);
    assert.equal(violations[0].type, 'missing_scan');
    assert.ok(violations[0].message.includes('injection'));
  });

  it('enforces maxAge for dependency CVEs', () => {
    const policy = new PolicyEngine({
      maxAge: {
        criticalCVE: '7d',
        highCVE: '30d',
      },
    });

    const scoreResult = { score: 90, grade: 'A' };

    // Test: a critical CVE that is 10 days old (violates 7d SLA)
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const depVulns = [
      { name: 'old-package', severity: 'critical', cve: 'CVE-2026-1000', published: tenDaysAgo },
      { name: 'safe-package', severity: 'high', cve: 'CVE-2026-2000', published: new Date().toISOString() },
    ];

    const violations = policy.evaluate(scoreResult, [], { depVulns });
    assert.equal(violations.length, 1);
    assert.equal(violations[0].type, 'cve_sla_breach');
    assert.ok(violations[0].message.includes('old-package'));
  });
});

