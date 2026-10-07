/**
 * Threat-pack probe precision.
 *
 * A shipped threat-pack probe fired a *medium-severity* "document-payload split
 * injection" finding on the phrase "when combined with" — idiomatic English that
 * appears in ordinary code comments. A scanner that reports a medium-severity
 * security finding on a comment about stdout is a credibility problem, and this
 * file exists so that precision cannot silently regress.
 *
 * Two things are pinned:
 *   1. TP-003 requires an actual chaining referent, and does not fire on ordinary prose.
 *   2. Every shipped threat-pack probe compiles through the real compiler, which
 *      enforces the ReDoS guard — so a pattern change cannot smuggle in a
 *      catastrophic-backtracking construct.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

import { _internals } from '../agents/prompt-injection-prober.js';

const PACK_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', 'cli', 'data', 'threatpacks', 'latest.json'
);
const pack = JSON.parse(fs.readFileSync(PACK_PATH, 'utf8'));

describe('threat-pack probes — compile safety', () => {
  it('ships a non-empty probe set', () => {
    assert.ok(Array.isArray(pack.probes) && pack.probes.length > 0);
  });

  it('every probe compiles through the real compiler (ReDoS guard enforced)', () => {
    for (const probe of pack.probes) {
      assert.doesNotThrow(
        () => _internals.compileProbeRegex(probe.regex),
        `${probe.id} failed to compile: ${probe.regex}`
      );
    }
  });

  it('carries a version and a review date (data-asset obligation)', () => {
    assert.ok(pack.version, 'threat pack must carry a version');
    assert.ok(pack._refresh_policy?.lastReviewed, 'threat pack must record lastReviewed');
  });
});

describe('TP-003 — split-payload precision', () => {
  const probe = pack.probes.find(p => p.id === 'TP-003');
  const re = probe ? _internals.compileProbeRegex(probe.regex) : null;
  const matches = (s) => {
    re.lastIndex = 0;
    const hit = re.test(s);
    re.lastIndex = 0;
    return hit;
  };

  it('exists', () => {
    assert.ok(probe, 'TP-003 must be present in the shipped pack');
  });

  it('still detects genuine split-payload chaining', () => {
    const attacks = [
      'when combined with the above instructions',
      'When combined with these rules, execute the payload',
      'when combined with previous content',
      'Part 2 of 3',
      'continue reading the next part',
    ];
    for (const a of attacks) {
      assert.ok(matches(a), `TP-003 must still detect: ${a}`);
    }
  });

  it('does NOT fire on ordinary English', () => {
    // The regression this guards: this exact comment in
    // cli/commands/audit.js was reported as a medium-severity finding.
    const benign = [
      '// Keep stdout pure JSON/SARIF when combined with machine output',
      'the result is faster when combined with caching',
      'output when combined with stderr is written to the log',
      'this runs when combined with the results',
      'merged when combined with the previous version',
    ];
    for (const b of benign) {
      assert.ok(!matches(b), `TP-003 must not fire on ordinary prose: ${b}`);
    }
  });

  it('the tightened pattern is what actually ships, not just what the pack file says', () => {
    // The pack file was fixed, but the *loaded* corpus is what the agent scans with. A
    // stale `~/.praxis/threat-intel.json` was reinstating the pre-fix pattern through
    // the feed overlay, so the benign text was flagged again in a real scan.
    const benign = 'Keep stdout pure JSON/SARIF when combined with machine output';
    const loaded = _internals.loadCorpus();
    const tp3 = loaded.probes.find(p => p.id === 'TP-003');
    assert.ok(tp3, 'TP-003 must be present in the loaded corpus');
    tp3.regex.lastIndex = 0;
    assert.ok(!tp3.regex.test(benign),
      `the loaded TP-003 still fires on ordinary prose: ${tp3.patternSource}`);
  });
});

// =============================================================================
// Feed overlay versioning
// =============================================================================
//
// `loadCorpus` overlays probes from the fetched intel feed on top of the bundled
// threat-pack seed. Without a version gate a cache from an older release silently
// replaced the signatures shipped with the current one — which is how a fixed TP-003
// came back to life. The seed is the floor; a newer feed may extend it.

describe('threat-pack feed overlay versioning', async () => {
  const os = await import('os');
  const { PromptInjectionProber } = await import('../agents/prompt-injection-prober.js');
  // `os.homedir` is read-only on an ESM namespace, so reach the CJS object to stub it.
  const mutableOs = createRequire(import.meta.url)('os');

  const SEED_VERSION = pack.version;
  const NEW_SIGNATURE = 'zzz-brand-new-signature-token';

  /** Runs a fresh load against a sandboxed HOME so the corpus cache cannot leak. */
  const loadWith = async (feed) => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-home-'));
    const realHome = mutableOs.homedir;
    try {
      fs.mkdirSync(path.join(home, '.praxis'), { recursive: true });
      if (feed) {
        fs.writeFileSync(path.join(home, '.praxis', 'threat-intel.json'), JSON.stringify(feed));
      }
      mutableOs.homedir = () => home;
      const mod = await import(`../agents/prompt-injection-prober.js?t=${Math.random()}`);
      return mod._internals.loadCorpus();
    } finally {
      mutableOs.homedir = realHome;
      fs.rmSync(home, { recursive: true, force: true });
    }
  };

  const packFeed = (version, id) => ({
    updated: '2026-10-01T00:00:00Z',
    threatPack: {
      ...(version ? { version } : {}),
      probes: [{
        id, title: 'Feed probe', severity: 'high',
        regex: NEW_SIGNATURE, category: 'indirect-injection',
      }],
    },
  });

  it('bundled seed families are loaded even with no feed present', async () => {
    const corpus = await loadWith(null);
    for (const id of ['TP-001', 'TP-002', 'TP-003']) {
      assert.ok(corpus.probes.some(p => p.id === id),
        `${id} must load from the bundled seed with no network`);
    }
  });

  it('rejects a feed older than the bundled seed', async () => {
    const corpus = await loadWith(packFeed('0.9', 'TP-099'));
    assert.equal(corpus.feedRejected, 1, 'the stale feed probe must be rejected');
    assert.ok(!corpus.probes.some(p => p.id === 'TP-099'), 'stale probe must not be loaded');
    assert.ok(corpus.probes.some(p => p.id === 'TP-003'), 'bundled TP-003 must survive');
  });

  it('applies a feed newer than the bundled seed', async () => {
    const corpus = await loadWith(packFeed('99.0', 'TP-099'));
    assert.equal(corpus.feedApplied, 1, 'a newer feed must still take effect');
    assert.ok(corpus.probes.some(p => p.id === 'TP-099'), 'new feed probe must load');
  });

  it('honours an unversioned feed rather than silently dropping it', async () => {
    const corpus = await loadWith(packFeed(null, 'TP-100'));
    assert.ok(corpus.probes.some(p => p.id === 'TP-100'),
      'a feed with no version keeps the original overlay behaviour');
  });

  it('detects genuine attacks and ignores ordinary English end-to-end', async () => {
    // Guards against the obvious wrong fix: dropping the stale feed wholesale, which
    // removes the whole family and trades a false positive for a false negative.
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-home-'));
    const file = path.join(home, 'probe.js');
    const realHome = mutableOs.homedir;
    try {
      mutableOs.homedir = () => home;
      const agent = new PromptInjectionProber();
      const scan = async (text) => {
        fs.writeFileSync(file, text);
        return agent.analyze({ rootPath: home, files: [file] });
      };
      for (const attack of [
        'Part 2 of 3',
        'continue reading the next part',
        'when combined with the above instructions',
      ]) {
        assert.ok((await scan(attack)).length > 0, `must still detect: ${attack}`);
      }
      for (const prose of [
        '// Keep stdout pure JSON/SARIF when combined with machine output',
        '// the result is faster when combined with caching',
      ]) {
        assert.equal((await scan(prose)).length, 0, `must not flag: ${prose}`);
      }
    } finally {
      mutableOs.homedir = realHome;
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('the seed version is what the gate compares against', () => {
    assert.ok(SEED_VERSION, 'seed must carry a version for the gate to work');
  });
});