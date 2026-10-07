/**
 * Tests for cli/utils/fix-ledger.js and the Remediation Ledger panel.
 *
 * The ledger exists so the report can show the applied half of the find→fix→verify
 * loop rather than only the findings. The tests pin the semantics that are easy to
 * get wrong and expensive to misreport:
 *   - `.praxis/fixes.jsonl` means *currently applied* (undo removes entries rather
 *     than annotating them), so no "undone" total may be invented
 *   - reversibility depends on the plan still carrying create/append/edits
 *   - a missing ledger and a malformed ledger both degrade without throwing
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const { readFixLedger, summarizeFixLedger, isReversible } = await import('../utils/fix-ledger.js');
const { HTMLReporter } = await import('../agents/html-reporter.js');

let tmp;

const APPLIED = {
  timestamp: '2026-08-20T10:15:30.000Z',
  file: 'src/server.js',
  findings: [
    { title: 'Command injection', line: 22, severity: 'critical', rule: 'CMD_INJECTION' },
    { title: 'Hardcoded key', line: 10, severity: 'critical', rule: 'AWS_KEY_HARDCODED' },
  ],
  plan: { summary: 'sanitise input', files: [{ path: 'src/server.js', edits: [{ line: 22, original: 'a', replacement: 'b' }] }] },
  verified: true,
  verificationClass: 'pass',
  branch: 'praxis/fix-1',
  commitHash: 'abc1234',
};

const APPLIED_UNVERIFIED = {
  timestamp: '2026-08-20T11:00:00.000Z',
  file: 'src/api.js',
  findings: [{ title: 'Missing rate limit', line: 88, severity: 'medium', rule: 'NO_RATE_LIMIT' }],
  plan: { summary: 'add limit', files: [{ path: 'src/api.js', append: '\n// rate limit\n' }] },
  verified: false,
};

const APPLIED_NO_PLAN = {
  timestamp: '2026-08-20T12:00:00.000Z',
  file: 'src/legacy.js',
  findings: [{ title: 'Legacy issue', line: 3, severity: 'low', rule: 'LEGACY' }],
  verified: true,
};

const REJECTED = [
  { timestamp: '2026-08-20T09:00:00.000Z', file: 'a.js', reason: 'verification-failed', detail: 'tests still fail' },
  { timestamp: '2026-08-20T09:30:00.000Z', file: 'b.js', reason: 'verification-failed', detail: 'tests still fail' },
  { timestamp: '2026-08-20T09:45:00.000Z', file: 'c.js', reason: 'validation-rejected', detail: 'unsafe patch' },
];

const writeLog = (name, lines) => {
  fs.mkdirSync(path.join(tmp, '.praxis'), { recursive: true });
  fs.writeFileSync(path.join(tmp, '.praxis', name), lines.map(l => JSON.stringify(l)).join('\n') + '\n', 'utf8');
};

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-ledger-'));
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

// =============================================================================
// isReversible
// =============================================================================

describe('fix-ledger — reversibility', () => {
  it('is reversible when the plan records line edits', () => {
    assert.equal(isReversible({ files: [{ path: 'a.js', edits: [{ line: 1, original: 'x', replacement: 'y' }] }] }), true);
  });

  it('is reversible for a created file or an append', () => {
    assert.equal(isReversible({ files: [{ path: 'a.js', create: true }] }), true);
    assert.equal(isReversible({ files: [{ path: 'a.js', append: 'text' }] }), true);
  });

  it('is not reversible without a usable plan', () => {
    assert.equal(isReversible(undefined), false);
    assert.equal(isReversible({}), false);
    assert.equal(isReversible({ files: [] }), false);
    assert.equal(isReversible({ files: [{ path: 'a.js' }] }), false, 'a bare path carries no undo information');
    assert.equal(isReversible({ files: [{ path: 'a.js', edits: [] }] }), false);
  });
});

// =============================================================================
// readFixLedger
// =============================================================================

describe('fix-ledger — reading', () => {
  it('returns empty and does not throw when no ledger exists', () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-noledger-'));
    try {
      const ledger = readFixLedger(empty);
      assert.deepEqual(ledger.applied, []);
      assert.deepEqual(ledger.rejected, []);
      assert.equal(ledger.error, null);
      assert.equal(ledger.hasLog, false);
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });

  it('summarizes applied and declined fixes', () => {
    writeLog('fixes.jsonl', [APPLIED, APPLIED_UNVERIFIED, APPLIED_NO_PLAN]);
    writeLog('failures.jsonl', REJECTED);

    const ledger = readFixLedger(tmp);
    const s = summarizeFixLedger(ledger);

    assert.equal(s.appliedCount, 3);
    assert.equal(s.verified, 2);
    assert.equal(s.unverified, 1);
    assert.equal(s.findingsFixed, 4, '2 + 1 + 1 findings across the three entries');
    // edits and append are reversible; the entry with no recorded plan is not.
    assert.equal(s.reversible, 2);
    assert.equal(s.irreversible, 1);
    assert.equal(s.rejectedCount, 3);
    assert.deepEqual(s.rejectedByReason, { 'verification-failed': 2, 'validation-rejected': 1 });
  });

  it('skips malformed lines but counts them', () => {
    fs.mkdirSync(path.join(tmp, '.praxis'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, '.praxis', 'fixes.jsonl'),
      JSON.stringify(APPLIED) + '\n{ not json\n\n' + JSON.stringify(APPLIED_UNVERIFIED) + '\n',
      'utf8'
    );
    const ledger = readFixLedger(tmp);
    assert.equal(ledger.applied.length, 2);
    assert.equal(ledger.appliedUnreadable, 1, 'a corrupt line must be counted, not silently dropped');

    // Restore a clean log for subsequent assertions.
    writeLog('fixes.jsonl', [APPLIED, APPLIED_UNVERIFIED, APPLIED_NO_PLAN]);
  });

  it('tolerates a null or missing project path', () => {
    assert.doesNotThrow(() => readFixLedger(null));
    assert.doesNotThrow(() => summarizeFixLedger(null));
    const s = summarizeFixLedger(null);
    assert.equal(s.appliedCount, 0);
    assert.equal(s.rejectedCount, 0);
  });
});

// =============================================================================
// Remediation Ledger panel
// =============================================================================

describe('Remediation Ledger panel', () => {
  const panel = (root) => new HTMLReporter().renderFixLedger(root);

  it('states the loop outcome when fixes were applied', () => {
    const html = panel(tmp);
    assert.ok(html.includes('Remediation Ledger'));
    assert.ok(html.includes('Changes Applied'));
    assert.ok(html.includes('VERIFIED'));
    assert.ok(html.includes('UNVERIFIED'));
    assert.ok(html.includes('src/server.js'));
    assert.ok(html.includes('reversible'), 'entries with an undoable plan should be marked reversible');
    assert.ok(html.includes('no plan recorded'), 'an entry without a plan must say so plainly');
  });

  it('reports declined fixes grouped by reason', () => {
    const html = panel(tmp);
    assert.ok(html.includes('Declined Fixes by Reason'));
    assert.ok(html.includes('verification-failed'));
    assert.ok(html.includes('validation-rejected'));
  });

  it('does NOT invent an undone total', () => {
    // `praxis undo` removes entries from the log instead of annotating them, so an
    // "undone" figure would always be 0 and would read as "nothing was ever reverted".
    // The word may legitimately appear in the explanatory note, but never as a count.
    const html = panel(tmp);
    assert.ok(!/kpi-label">\s*Undone/i.test(html), 'report must not present an undone KPI');
    assert.ok(!/\b\d+\s+undone\b/i.test(html), 'report must not present an undone count');
    assert.ok(html.includes('currently applied'), 'the log semantics must be stated');
    assert.ok(html.includes('removes reverted entries'), 'the reader should be told why');
  });

  it('shows an explicit empty state rather than a blank panel', () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-ledger-empty-'));
    try {
      const html = panel(empty);
      assert.ok(html.includes('Remediation Ledger'));
      assert.ok(html.includes('No fixes have been applied'), 'must explain the empty state, not render nothing');
      assert.ok(html.includes('praxis fix'), 'should point at the command that changes this');
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });

  it('escapes log content and normalizes paths', () => {
    const hostile = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-ledger-xss-'));
    try {
      fs.mkdirSync(path.join(hostile, '.praxis'), { recursive: true });
      fs.writeFileSync(
        path.join(hostile, '.praxis', 'fixes.jsonl'),
        JSON.stringify({ ...APPLIED, file: '<img src=x onerror=alert(1)>.js', plan: undefined }) + '\n',
        'utf8'
      );
      const html = panel(hostile);
      assert.ok(!html.includes('<img src=x'), 'file path from the log must be escaped');
      assert.ok(html.includes('&lt;img'));
    } finally {
      fs.rmSync(hostile, { recursive: true, force: true });
    }
  });

  it('appears on the remediation tab of a full report', () => {
    const html = new HTMLReporter().generate(
      { score: 70, grade: { letter: 'C' }, categories: {} },
      [],
      {},
      tmp
    );
    assert.ok(html.includes('Remediation Ledger'), 'ledger should be part of the remediation section');
  });
});