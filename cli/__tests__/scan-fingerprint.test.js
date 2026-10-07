/**
 * Tests for cli/utils/scan-fingerprint.js.
 *
 * Added after a self-scan reported 325 findings where four subsequent scans of the
 * identical tree reported 308, and the extra 17 could not be attributed to data
 * drift, test fixtures, or the scan cache. The lesson was that an unattributable
 * number is a liability, so scans now carry a fingerprint (what produced them) and
 * the comparison semantics are pinned here — in particular, that a *scoring* change
 * must not read as a *detection* change.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const {
  buildScanFingerprint,
  fingerprintLine,
  findingIdentity,
  diffFindings,
} = await import('../utils/scan-fingerprint.js');

describe('scan-fingerprint — provenance', () => {
  it('reports tool, runtime and file count', () => {
    const fp = buildScanFingerprint({ filesScanned: 197 });
    assert.ok(fp.tool, 'tool version should be resolvable from package.json');
    assert.equal(fp.node, process.version);
    assert.equal(fp.filesScanned, 197);
  });

  it('records the version of every vendored detection asset', () => {
    const { data } = buildScanFingerprint();
    // These assets change what Praxis detects, so a drift in any of them explains a
    // change in findings. They must be present and versioned, never silently absent.
    assert.ok(data.probeCorpus.version, 'probe corpus version missing');
    assert.ok(data.probeCorpus.items > 0, 'probe corpus should contain probes');
    assert.ok(data.threatPack.version, 'threat pack version missing');
    assert.ok(data.eaaCatalog.version, 'EAA catalog version missing');
  });

  it('degrades to nulls rather than throwing', () => {
    // A fingerprint must never be able to fail a scan.
    const fp = buildScanFingerprint();
    assert.equal(fp.filesScanned, null, 'unknown file count should be null, not 0');
    assert.doesNotThrow(() => buildScanFingerprint({ filesScanned: 'nonsense' }));
    assert.equal(buildScanFingerprint({ filesScanned: 'nonsense' }).filesScanned, null);
  });

  it('renders a one-line summary, showing ? for anything unknown', () => {
    const line = fingerprintLine(buildScanFingerprint({ filesScanned: 5 }));
    assert.match(line, /^praxis .+ · node .+ · probes v.+ · threatpack v.+ · eaa v.+ · files 5$/);
    assert.equal(fingerprintLine(null), '');
    assert.ok(fingerprintLine({ tool: null, node: null, data: {}, filesScanned: null }).includes('praxis ?'));
  });
});

describe('scan-fingerprint — run comparison', () => {
  it('produces a stable identity from file and rule', () => {
    assert.equal(findingIdentity({ file: 'a.js', rule: 'R1' }), 'a.js::R1');
    assert.equal(findingIdentity({}), '?::?');
    assert.equal(findingIdentity(null), '?::?');
  });

  it('ignores severity so a scoring change is not read as a detection change', () => {
    const before = [{ file: 'a.js', rule: 'R1', severity: 'medium' }];
    const after = [{ file: 'a.js', rule: 'R1', severity: 'critical' }];
    const d = diffFindings(before, after);
    assert.deepEqual(d, { added: [], removed: [], common: 1 });
  });

  it('ignores line numbers so a shifted file is not a new finding', () => {
    const before = [{ file: 'a.js', rule: 'R1', line: 10 }];
    const after = [{ file: 'a.js', rule: 'R1', line: 42 }];
    assert.equal(diffFindings(before, after).added.length, 0);
  });

  it('reports genuine additions and removals', () => {
    const before = [{ file: 'a.js', rule: 'R1' }, { file: 'b.js', rule: 'R2' }];
    const after = [{ file: 'a.js', rule: 'R1' }, { file: 'c.js', rule: 'R3' }];
    const d = diffFindings(before, after);
    assert.deepEqual(d.added, ['c.js::R3']);
    assert.deepEqual(d.removed, ['b.js::R2']);
    assert.equal(d.common, 1);
  });

  it('handles empty and missing inputs', () => {
    assert.deepEqual(diffFindings([], []), { added: [], removed: [], common: 0 });
    assert.doesNotThrow(() => diffFindings(null, undefined));
    assert.deepEqual(diffFindings(null, undefined), { added: [], removed: [], common: 0 });
  });
});