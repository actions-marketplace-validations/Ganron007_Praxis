/**
 * Tests for cli/agents/html-reporter.js — the user-facing HTML report generator.
 *
 * The reporter had no test coverage at all before this work, despite being ~600 lines
 * of string-building that ends up in front of users. These tests focus on the parts
 * that can silently produce a wrong or unsafe report:
 *   - HTML escaping (untrusted finding text flows into the document)
 *   - path normalization (must not leak absolute host paths)
 *   - the new agent-coverage / ASI / severity-bar surfaces, including empty-input
 *     degradation for callers that don't pass telemetry
 *   - the multi-page suite file set
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const { HTMLReporter } = await import('../agents/html-reporter.js');

const SCORE_RESULT = {
  score: 62,
  grade: { letter: 'D' },
  categories: {
    secrets: { label: 'Secrets', deduction: 12, counts: { critical: 2 } },
    injection: { label: 'Injection', deduction: 4, counts: { high: 1 } },
  },
};

const FINDINGS = [
  {
    file: 'src/server.js',
    line: 10,
    severity: 'critical',
    category: 'secrets',
    rule: 'AWS_KEY_HARDCODED',
    title: 'AWS Access Key ID in source',
    description: 'A live-looking AWS key is committed.',
    fix: 'Rotate the key and load it from the environment.',
  },
  {
    file: 'src/api.js',
    line: 22,
    severity: 'high',
    category: 'injection',
    rule: 'CMD_INJECTION',
    title: 'Command injection via concatenation',
    description: 'User input flows into exec().',
    fix: 'Use execFile with an argument array.',
  },
  {
    file: 'src/llm.js',
    line: 5,
    severity: 'medium',
    category: 'injection',
    rule: 'LLM_NO_INPUT_GUARD',
    title: 'Unvalidated prompt interpolation',
    description: 'User text is interpolated into a prompt.',
    fix: 'Delimit and validate untrusted input.',
  },
];

const AGENT_RESULTS = [
  { agent: 'AgentConfigScanner', category: 'agent-config', findingCount: 6, success: true },
  { agent: 'MCPSecurityAgent', category: 'mcp', findingCount: 4, success: true },
  { agent: 'SecretScanner', category: 'secrets', findingCount: 0, success: true },
  { agent: 'BrokenAgent', category: 'broken', findingCount: 0, success: false },
];

const SCORE_WITH_ASI = {
  ...SCORE_RESULT,
  agenticSummary: {
    risks: [
      {
        id: 'ASI01',
        title: 'Agent Goal Hijacking',
        description: 'Manipulation of agent objectives.',
        findingCount: 4,
        status: 'flagged',
      },
      {
        id: 'ASI02',
        title: 'Tool Misuse',
        description: 'Agent uses tools beyond scope.',
        findingCount: 0,
        status: 'clear',
      },
    ],
    flagged: 1,
    total: 2,
    coverage: 50,
  },
};

// =============================================================================
// Escaping & path normalization
// =============================================================================

describe('HTMLReporter — escaping and path normalization', () => {
  const reporter = new HTMLReporter();

  it('escapes HTML-significant characters', () => {
    assert.equal(reporter.esc('<script>alert("x")</script>'), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
    assert.equal(reporter.esc("it's & more"), 'it&#039;s &amp; more');
  });

  it('esc tolerates null/undefined', () => {
    assert.equal(reporter.esc(null), '');
    assert.equal(reporter.esc(undefined), '');
  });

  it('strips the project root prefix from absolute paths', () => {
    const out = reporter.normalizePath(path.join('/tmp/proj', 'src', 'a.js'), '/tmp/proj');
    assert.equal(out, 'src/a.js');
  });

  it('reduces an absolute path to its filename when no root is supplied', () => {
    // With no root there is no way to know what is in-tree, so the old behaviour
    // — strip the drive letter and keep `work/src/a.js` — published the local
    // directory layout, and `C:\Users\alice\.cursor\mcp.json` became
    // `Users/alice/.cursor/mcp.json`, leaking the username into every HTML
    // report. Reducing to the filename is strictly safer and matches the
    // fallback sarif.js already used. A home-directory path still becomes `~/…`.
    //
    // Built with path.join so the fixture is absolute on the host: on POSIX a
    // `C:/…` string is just a relative filename, so `path.isAbsolute` is false
    // and displayPath correctly passes it through untouched. Hardcoding the
    // Windows form made this test pass on Windows and fail on every CI runner.
    assert.equal(reporter.normalizePath(path.join(path.sep, 'work', 'src', 'a.js')), 'a.js');
    assert.equal(
      reporter.normalizePath(path.join(os.homedir(), '.cursor', 'mcp.json')),
      '~/.cursor/mcp.json',
    );
  });

  it('never leaks an absolute path into the document', () => {
    const html = reporter.generate(SCORE_RESULT, FINDINGS, {}, '/private/secret-project');
    assert.ok(!html.includes('/private/secret-project'), 'absolute root path must not appear in output');
  });
});

// =============================================================================
// Severity distribution
// =============================================================================

describe('HTMLReporter — severity distribution', () => {
  it('renders a segment and percentage for each severity present', () => {
    const reporter = new HTMLReporter();
    const html = reporter.renderOverviewSection(SCORE_RESULT, FINDINGS, {}, '/proj');
    assert.ok(html.includes('class="sev-bar"'));
    // 1 critical of 3 findings = 33.33%
    assert.ok(html.includes('33%'), 'expected rounded critical share');
    assert.ok(html.includes('critical'), 'legend labels severities');
  });

  it('degrades to an empty state when there are no findings', () => {
    const reporter = new HTMLReporter();
    const html = reporter.renderOverviewSection(SCORE_RESULT, [], {}, '/proj');
    assert.ok(html.includes('No findings recorded'));
    assert.ok(!html.includes('class="sev-bar"'), 'must not render an empty bar');
  });

  it('segments sum to 100% even when info findings are present', () => {
    const reporter = new HTMLReporter();
    const withInfo = [
      ...FINDINGS,
      { file: 'a.js', line: 1, severity: 'info', category: 'misc', rule: 'R', title: 'info finding', description: '', fix: '' },
    ];
    const html = reporter.renderOverviewSection(SCORE_RESULT, withInfo, {}, '/proj');

    // Every rendered segment width, summed, must fill the bar.
    const widths = [...html.matchAll(/class="sev-seg" style="width:([\d.]+)%/g)].map(m => parseFloat(m[1]));
    const total = widths.reduce((a, b) => a + b, 0);
    assert.ok(widths.length >= 4, 'info should be rendered as its own segment');
    assert.ok(Math.abs(total - 100) < 0.1, `bar segments should sum to 100%, got ${total}`);
  });
});

// =============================================================================
// Agent coverage
// =============================================================================

describe('HTMLReporter — agent coverage', () => {
  it('reports executed/completed/errored counts and attributes findings', () => {
    const reporter = new HTMLReporter();
    const html = reporter.renderAgentCoverageSection(AGENT_RESULTS, SCORE_RESULT);
    assert.ok(html.includes('4'), 'should count all four agents');
    assert.ok(html.includes('>3<'), 'three agents completed');
    assert.ok(html.includes('AgentConfigScanner'));
    assert.ok(html.includes('BrokenAgent'));
    assert.ok(html.includes('10'), 'attributed finding count (6+4+0+0)');
  });

  it('marks errored agents as a coverage gap', () => {
    const reporter = new HTMLReporter();
    const html = reporter.renderAgentCoverageSection(AGENT_RESULTS, SCORE_RESULT);
    assert.ok(html.includes('ERROR'), 'errored agent should be badged');
    assert.ok(html.includes('coverage gap'), 'an errored agent is a gap, not a clean result');
  });

  it('degrades gracefully when no telemetry is supplied', () => {
    const reporter = new HTMLReporter();
    for (const input of [undefined, [], null, 'not-an-array']) {
      const html = reporter.renderAgentCoverageSection(input, SCORE_RESULT);
      assert.ok(html.includes('not captured'), 'should explain the missing telemetry');
      assert.ok(!html.includes('class="sev-bar"'));
    }
  });

  it('defaults the parameter so callers can omit it', () => {
    const reporter = new HTMLReporter();
    assert.ok(reporter.renderAgentCoverageSection().includes('not captured'));
  });
});

// =============================================================================
// ASI agentic risk coverage
// =============================================================================

describe('HTMLReporter — OWASP ASI coverage', () => {
  it('renders flagged and clear risk classes with the tally', () => {
    const reporter = new HTMLReporter();
    const html = reporter.renderAsiSection(SCORE_WITH_ASI);
    assert.ok(html.includes('ASI01'));
    assert.ok(html.includes('Agent Goal Hijacking'));
    assert.ok(html.includes('REVIEW'), 'flagged class marked for review');
    assert.ok(html.includes('CLEAR'), 'clear class marked clear');
    assert.ok(html.includes('1/2'), 'flagged/total tally');
  });

  it('returns an empty string when no summary is present', () => {
    const reporter = new HTMLReporter();
    assert.equal(reporter.renderAsiSection(SCORE_RESULT), '');
    assert.equal(reporter.renderAsiSection({}), '');
  });

  it('is included in the overview when the score result carries a summary', () => {
    const reporter = new HTMLReporter();
    const html = reporter.renderOverviewSection(SCORE_WITH_ASI, FINDINGS, {}, '/proj');
    assert.ok(html.includes('Agentic Risk Coverage'), 'ASI panel should appear in the overview');
  });
});

// =============================================================================
// Recon signal rendering
// =============================================================================
// Note: `recon.envFiles` is intentionally NOT rendered. recon honours .gitignore, and
// `.env` is gitignored in nearly every real project, so that field is systematically
// empty — rendering it would assert a false negative in a security report.

describe('HTMLReporter — recon signal lists', () => {
  const reporter = new HTMLReporter();

  it('renders values as code chips', () => {
    const html = reporter.renderSignalList(['vercel.json']);
    assert.ok(html.includes('vercel.json'));
  });

  it('says "none detected" for an empty list', () => {
    assert.ok(reporter.renderSignalList([]).includes('none detected'));
    assert.ok(reporter.renderSignalList(undefined).includes('none detected'));
  });

  it('distinguishes "present but not enumerated" from absent', () => {
    const html = reporter.renderSignalList([], true);
    assert.ok(html.includes('detected (not enumerated)'));
  });

  it('renders the extended AI-surface rows', () => {
    const html = reporter.renderOverviewSection(
      SCORE_RESULT,
      FINDINGS,
      {
        frontendExposure: ['next.js'],
        modelFiles: ['model/fraud.pkl'],
        hasModelFiles: true,
        hasDockerfile: true,
        configFiles: ['vercel.json'],
        cicd: [{ platform: 'github-actions', file: '.github/workflows/ci.yml' }],
      },
      '/proj'
    );
    assert.ok(html.includes('Frontend Exposure'));
    assert.ok(html.includes('Model / AI Artifacts'));
    assert.ok(html.includes('fraud.pkl'));
    assert.ok(html.includes('Containers'));
    assert.ok(html.includes('Dockerfile'));
  });
});

// =============================================================================
// Full document
// =============================================================================

describe('HTMLReporter — full document', () => {
  const reporter = new HTMLReporter();

  it('produces a well-formed single-file document with all six tabs', () => {
    const html = reporter.generate(SCORE_RESULT, FINDINGS, {}, '/proj', AGENT_RESULTS);
    assert.ok(html.startsWith('<!DOCTYPE html>'));
    assert.ok(html.trimEnd().endsWith('</html>'));
    for (const tab of ['overview', 'agents', 'findings', 'standards', 'abom', 'remediation']) {
      assert.ok(html.includes(`id="section-${tab}"`), `missing section-${tab}`);
      assert.ok(html.includes(`id="tab-btn-${tab}"`), `missing tab-btn-${tab}`);
    }
  });

  it('includes agent telemetry when supplied, and stays valid without it', () => {
    const withAgents = reporter.generate(SCORE_RESULT, FINDINGS, {}, '/proj', AGENT_RESULTS);
    assert.ok(withAgents.includes('AgentConfigScanner'));
    const without = reporter.generate(SCORE_RESULT, FINDINGS, {}, '/proj');
    assert.ok(without.startsWith('<!DOCTYPE html>'));
    assert.ok(without.includes('not captured'));
  });

  // Tab navigation must not rely on inline javascript: URLs.
  it('uses no javascript: URLs and switches tabs via a delegated handler', () => {
    const html = reporter.generate(SCORE_RESULT, FINDINGS, {}, '/proj', AGENT_RESULTS);
    assert.ok(!html.includes('javascript:'), 'inline javascript: URLs break a strict CSP');
    assert.ok(html.includes("closest('[data-tab]')"), 'tab switching should use one delegated listener');
    for (const tab of ['overview', 'agents', 'findings', 'standards', 'abom', 'remediation']) {
      assert.ok(html.includes(`data-tab="${tab}"`), `missing data-tab for ${tab}`);
      assert.ok(html.includes(`href="#${tab}"`), `tab ${tab} should be a real, shareable hash href`);
    }
  });

  it('deep-links the active tab and restores it on load', () => {
    const html = reporter.generate(SCORE_RESULT, FINDINGS, {}, '/proj', AGENT_RESULTS);
    assert.ok(html.includes('location.hash'), 'should read the tab from the URL');
    assert.ok(html.includes('replaceState'), 'should keep the address bar in sync');
    assert.ok(html.includes('DOMContentLoaded'), 'should restore the tab on load');
  });

  it('ignores an unknown tab instead of blanking the page', () => {
    const html = reporter.generate(SCORE_RESULT, FINDINGS, {}, '/proj', AGENT_RESULTS);
    assert.ok(html.includes('TABS.includes(tabId)'), 'switchTab should validate the tab id');
    assert.ok(html.includes("if (!tabId) tabId = 'overview'") || html.includes('TABS.includes(fromHash) ? fromHash'),
      'an unknown hash should fall back to the overview');
  });

  it('lists every finding rule in the findings table', () => {
    const html = reporter.generate(SCORE_RESULT, FINDINGS, {}, '/proj', AGENT_RESULTS);
    for (const f of FINDINGS) assert.ok(html.includes(f.rule), `missing rule ${f.rule}`);
  });

  it('escapes hostile finding text rather than emitting live markup', () => {
    const hostile = [
      {
        ...FINDINGS[0],
        title: '<img src=x onerror=alert(1)>',
        description: '</script><script>alert(2)</script>',
      },
    ];
    const html = reporter.generate(SCORE_RESULT, hostile, {}, '/proj', AGENT_RESULTS);
    assert.ok(!html.includes('<img src=x'), 'raw img tag must not survive into the document');
    assert.ok(html.includes('&lt;img'), 'hostile title should be escaped');
  });

  it('sanitises a hostile severity in the row badge and the filter key', () => {
    // `severity` reaches the report from scan data and previously went straight into
    // both a class attribute and the data-sev filter key.
    const hostile = [{ ...FINDINGS[0], severity: 'critical" onmouseover="alert(1)' }];
    const html = reporter.generate(SCORE_RESULT, hostile, {}, '/proj', AGENT_RESULTS);

    assert.ok(!html.includes('onmouseover="alert(1)"'), 'severity broke out of an attribute');
    assert.ok(html.includes('data-sev=""'), 'unrecognised severity must not become a filter class');
  });

  it('lowercases the filter key so an uppercase severity still filters', () => {
    const shouty = [{ ...FINDINGS[0], severity: 'CRITICAL' }];
    const html = reporter.generate(SCORE_RESULT, shouty, {}, '/proj', AGENT_RESULTS);
    // The client-side filter compares dataset.sev against lowercase keys.
    assert.ok(html.includes('data-sev="critical"'), 'filter key must be normalised to lowercase');
  });
});

// =============================================================================
// Shared theme — single source of truth for every HTML surface
// =============================================================================

describe('html-theme — shared primitives', async () => {
  const theme = await import('../core/output/html-theme.js');

  it('esc escapes markup-significant characters', () => {
    assert.equal(theme.esc('<b>&"\'</b>'), '&lt;b&gt;&amp;&quot;&#039;&lt;/b&gt;');
    assert.equal(theme.esc(null), '');
    assert.equal(theme.esc(undefined), '');
  });

  it('severityBadgeClass only ever returns a known-safe class', () => {
    for (const sev of ['critical', 'high', 'medium', 'low', 'info', 'CRITICAL']) {
      assert.match(theme.severityBadgeClass(sev), /^[a-z]*$/, `"${sev}" must be a bare token`);
    }
    // Attribute-injection attempts must not survive into the class attribute.
    for (const hostile of ['x" onclick="alert(1)', 'a b', '<script>', '', null, undefined, 'nope']) {
      const cls = theme.severityBadgeClass(hostile);
      assert.doesNotMatch(cls, /["'<>\s]/, `unsafe class from ${JSON.stringify(hostile)}`);
    }
  });

  it('severityBadge escapes the label and sanitises the class', () => {
    const html = theme.severityBadge('critical');
    assert.ok(html.includes('class="sev-badge sev-critical"'));
    assert.ok(html.includes('critical'));

    const hostile = theme.severityBadge('bad" onmouseover="alert(1)', '<img src=x>');
    assert.ok(!hostile.includes('onmouseover="alert(1)"'), 'attribute break-out must be neutralised');
    assert.ok(hostile.includes('&lt;img'), 'label must be escaped');
  });

  it('countBySeverity always returns a fully-populated record', () => {
    const counts = theme.countBySeverity([
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'bogus' },
      {},
    ]);
    assert.deepEqual(counts, { critical: 2, high: 1, medium: 0, low: 0, info: 0 });
    assert.deepEqual(theme.countBySeverity(), { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    assert.deepEqual(theme.countBySeverity(null), { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it('baseStyles defines the canonical severity palette once', () => {
    const css = theme.baseStyles();
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      assert.ok(css.includes(`.sev-${sev}{`), `missing .sev-${sev}`);
    }
  });

  it('documentShell escapes the title and emits a valid document', () => {
    const doc = theme.documentShell({
      title: '<script>alert(1)</script>',
      styles: theme.baseStyles(),
      body: '<p>body</p>',
    });
    assert.ok(doc.startsWith('<!DOCTYPE html>'));
    assert.ok(!doc.includes('<script>alert(1)</script>'), 'title must be escaped');
    assert.ok(doc.includes('&lt;script&gt;'));
    assert.ok(doc.includes('<p>body</p>'));
  });
});

// =============================================================================
// De-duplication guard
// =============================================================================
// Splitting the theme out is what puts the severity palette and escaping in ONE
// place. These are deliberately *behavioural* rather than source-scanning: they
// assert both reports emit the theme's canonical rules, so an intentional
// re-theme (which changes the theme) keeps passing, while a report that
// re-introduces its own copy of a rule fails.

describe('report surfaces share one theme', async () => {
  const theme = await import('../core/output/html-theme.js');

  /** Renders a team report through the real command and returns the HTML. */
  const renderTeamReport = async () => {
    const { teamReportCommand } = await import('../commands/team-report.js');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-theme-'));
    try {
      const input = path.join(tmp, 'in.txt');
      const out = path.join(tmp, 'out.html');
      fs.writeFileSync(
        input,
        [
          'FINDING: {"severity":"critical","title":"Command injection","location":"src/a.js:1"}',
          'FINDING: {"severity":"low","title":"Verbose logging","location":"src/b.js:2"}',
        ].join('\n'),
        'utf8'
      );
      await teamReportCommand(input, { html: out });
      return fs.readFileSync(out, 'utf8');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  };

  it('both reports emit the theme severity rules verbatim', async () => {
    const css = theme.baseStyles();
    const rules = ['critical', 'high', 'medium', 'low'].map(sev => {
      const m = css.match(new RegExp(`\\.sev-${sev}\\{[^}]*\\}`));
      assert.ok(m, `theme is missing .sev-${sev}`);
      return m[0];
    });

    const forensic = new HTMLReporter().generate(SCORE_RESULT, FINDINGS, {}, '/proj', AGENT_RESULTS);
    const team = await renderTeamReport();

    for (const rule of rules) {
      assert.ok(forensic.includes(rule), 'forensic report is missing the shared rule');
      assert.ok(team.includes(rule), 'team report is missing the shared rule');
    }
  });

  it('neither report carries a competing .sev-critical definition', async () => {
    const forensic = new HTMLReporter().generate(SCORE_RESULT, FINDINGS, {}, '/proj', AGENT_RESULTS);
    const team = await renderTeamReport();
    for (const [name, html] of [['forensic', forensic], ['team', team]]) {
      const definitions = html.match(/\.sev-critical\{/g) || [];
      assert.equal(definitions.length, 1, `${name} report defines .sev-critical ${definitions.length} times`);
    }
  });
});

// =============================================================================
// team-report escaping (the injection sink this de-dup closed)
// =============================================================================

describe('team-report — escapes untrusted report input', async () => {
  const { teamReportCommand } = await import('../commands/team-report.js');

  it('escapes finding text and neutralises class-attribute injection', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-team-'));
    try {
      const input = path.join(tmp, 'hermes.txt');
      const out = path.join(tmp, 'team.html');

      // The parser reads FINDING: <json> lines, so the payload arrives as JSON.
      const hostile = {
        severity: 'critical" onmouseover="alert(1)',
        title: '<img src=x onerror=alert(2)>',
        location: '</td><td><script>alert(3)</script>',
        remediation: '<svg onload=alert(4)>',
      };
      const target = '<script>alert("target")</script>';

      fs.writeFileSync(
        input,
        [
          `TARGET: ${target}`,
          `FINDING: ${JSON.stringify(hostile)}`,
          `FINDING: ${JSON.stringify({ severity: 'high', title: 'Plain finding', location: 'src/a.js' })}`,
        ].join('\n'),
        'utf8'
      );

      await teamReportCommand(input, { html: out });
      const html = fs.readFileSync(out, 'utf8');

      // No live markup from any injected field. The payload text may still appear
      // *escaped* (e.g. `&lt;img src=x onerror=…&gt;`) — that is inert visible text,
      // which is the correct outcome. What must not exist is an unescaped tag.
      for (const marker of ['<img src=x', '<script>alert(2)', '<script>alert(3)', '<svg onload']) {
        assert.ok(!html.includes(marker), `unescaped payload survived: ${marker}`);
      }
      assert.ok(!html.includes('onmouseover="alert(1)"'), 'severity broke out of the class attribute');

      // Escaped forms are present instead, and legitimate content still renders.
      assert.ok(html.includes('&lt;img src=x'), 'img tag should appear escaped');
      assert.ok(html.includes('&lt;script&gt;'), 'script tag should appear escaped');
      assert.ok(html.includes('Plain finding'), 'legitimate content must still render');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('HTMLReporter — file output', () => {
  it('generateToFile writes the document and returns the path', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-html-'));
    try {
      const out = path.join(tmp, 'report.html');
      const reporter = new HTMLReporter();
      const returned = reporter.generateToFile(SCORE_RESULT, FINDINGS, {}, '/proj', out, AGENT_RESULTS);
      assert.equal(returned, out);
      const written = fs.readFileSync(out, 'utf8');
      assert.ok(written.startsWith('<!DOCTYPE html>'));
      assert.ok(written.includes('AgentConfigScanner'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('generateReportSuite writes one page per tab', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-suite-'));
    try {
      const outDir = path.join(tmp, 'report');
      const reporter = new HTMLReporter();
      reporter.generateReportSuite(
        SCORE_RESULT,
        FINDINGS,
        [],
        {},
        [],
        '/proj',
        outDir,
        AGENT_RESULTS
      );
      const written = fs.readdirSync(outDir).sort();
      assert.deepEqual(written, [
        'abom.html',
        'agents.html',
        'findings.html',
        'index.html',
        'remediation.html',
        'standards.html',
      ]);
      const agentsPage = fs.readFileSync(path.join(outDir, 'agents.html'), 'utf8');
      assert.ok(agentsPage.includes('AgentConfigScanner'), 'agents page should carry telemetry');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
