/**
 * Tests for cli/utils/score-history.js and the trend panel.
 *
 * The rule these pin is "do not overstate the data". An empty chart reads as
 * "flat, no change", which is a different claim from "we have no data" — so the
 * panel must distinguish a baseline, a too-few-samples series, and a real trend,
 * and must never fabricate points to fill a graph.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const { readScoreHistory, summarizeHistory } = await import('../utils/score-history.js');
const { HTMLReporter } = await import('../agents/html-reporter.js');

const temps = [];
const mkProject = (history) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-hist-'));
  temps.push(dir);
  if (history !== undefined) {
    fs.mkdirSync(path.join(dir, '.praxis'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, '.praxis', 'history.json'),
      typeof history === 'string' ? history : JSON.stringify(history),
      'utf8'
    );
  }
  return dir;
};

after(() => {
  for (const dir of temps) fs.rmSync(dir, { recursive: true, force: true });
});

const entry = (score, day, grade = 'C') => ({
  timestamp: `2026-10-0${day}T10:00:00.000Z`,
  score,
  grade,
  totalFindings: 10,
});

// =============================================================================
// readScoreHistory
// =============================================================================

describe('score-history — reading', () => {
  it('returns an empty series when there is no history file', () => {
    const h = readScoreHistory(mkProject());
    assert.deepEqual(h.points, []);
    assert.equal(h.error, null, 'a missing file is not an error');
  });

  it('sorts points oldest first', () => {
    const h = readScoreHistory(mkProject([entry(10, 3), entry(30, 1), entry(20, 2)]));
    assert.deepEqual(h.points.map(p => p.score), [30, 20, 10]);
  });

  it('reports corrupt JSON instead of throwing or inventing points', () => {
    const h = readScoreHistory(mkProject('{ not json'));
    assert.deepEqual(h.points, []);
    assert.ok(h.error, 'a corrupt history must be reported, not swallowed');
  });

  it('rejects a non-array history', () => {
    const h = readScoreHistory(mkProject('{"score":50}'));
    assert.deepEqual(h.points, []);
    assert.ok(h.error);
  });

  it('counts unreadable entries but keeps the good ones', () => {
    const h = readScoreHistory(mkProject('[{"score":50,"timestamp":"2026-10-01T00:00:00Z"},"junk",{"nope":1}]'));
    assert.equal(h.points.length, 1);
    assert.equal(h.unreadable, 2);
  });

  it('tolerates a null root path by falling back to the cwd', () => {
    // Documented behaviour: a missing root resolves to process.cwd(), so this reads
    // whatever history the current project has. The contract under test is "does not
    // throw and returns a well-formed result", not "returns empty".
    assert.doesNotThrow(() => readScoreHistory(null));
    const h = readScoreHistory(null);
    assert.ok(Array.isArray(h.points), 'must always return an array');
    assert.equal(h.error, null);
  });
});

// =============================================================================
// summarizeHistory
// =============================================================================

describe('score-history — summarising without overstating', () => {
  it('appends the in-flight scan so the chart shows the current score', () => {
    const h = readScoreHistory(mkProject([entry(40, 1)]));
    const s = summarizeHistory(h.points, { score: 70, grade: 'C' });
    assert.equal(s.measurementCount, 2);
    assert.equal(s.latest, 70, 'latest must be the scan being reported, not the previous one');
    assert.equal(s.previous, 40);
    assert.equal(s.delta, 30);
    assert.equal(s.priorCount, 1);
  });

  it('does not double-append when history already ends with this score', () => {
    const h = readScoreHistory(mkProject([entry(40, 1), entry(70, 2)]));
    const s = summarizeHistory(h.points, { score: 70, grade: 'C' });
    assert.equal(s.measurementCount, 2, 'the current scan must not be counted twice');
  });

  it('flags a series with too few points to call a trend', () => {
    const h = readScoreHistory(mkProject([entry(40, 1)]));
    assert.equal(summarizeHistory(h.points, { score: 70 }).needsMoreData, true);
    assert.equal(summarizeHistory(readScoreHistory(mkProject([entry(40, 1), entry(50, 2)])).points, { score: 60 }).needsMoreData, false);
  });

  it('reports a baseline when there is nothing to compare against', () => {
    const s = summarizeHistory([], null);
    assert.equal(s.measurementCount, 0);
    assert.equal(s.delta, null);
    assert.equal(s.isBaseline, true);
    assert.equal(s.spanDays, null);
  });

  it('computes best, worst and time span', () => {
    const h = readScoreHistory(mkProject([entry(30, 1), entry(90, 5), entry(60, 9)]));
    const s = summarizeHistory(h.points, { score: 60 });
    assert.equal(s.best, 90);
    assert.equal(s.worst, 30);
    assert.equal(s.spanDays, 8);
  });

  it('never throws on empty or missing input', () => {
    assert.doesNotThrow(() => summarizeHistory(null, null));
    assert.equal(summarizeHistory(null, null).measurementCount, 0);
  });
});

// =============================================================================
// Trend panel
// =============================================================================

describe('trend panel — honest states', () => {
  const panel = (root, score = 70) =>
    new HTMLReporter().renderTrendSection({ score, grade: { letter: 'C' } }, root);
  const strip = (h) => h.replace(/<title>[\s\S]*?<\/title>/g, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

  it('says "baseline" instead of drawing an empty chart', () => {
    const html = panel(mkProject());
    assert.ok(html.includes('baseline'), 'must state the project is at its baseline');
    assert.ok(!html.includes('<svg'), 'must NOT render an empty graph — that reads as "flat, no change"');
    assert.ok(strip(html).includes('at least two measurements'), 'must say what a trend requires');
  });

  it('never fabricates points to fill the graph', () => {
    const html = panel(mkProject());
    assert.ok(!html.includes('sev-bar'), 'no chart chrome without data');
    assert.ok(!html.includes('<circle'), 'no data points without data');
  });

  it('warns when there are too few measurements to call a trend', () => {
    const html = panel(mkProject([entry(40, 1)]));
    assert.ok(html.includes('too few to call a trend'));
    assert.ok(html.includes('not a trajectory'));
    assert.ok(html.includes('<svg'), 'a chart is still drawn, just labelled honestly');
  });

  it('shows the sample size and time span beside the chart', () => {
    // The last history entry already carries this run's score, so it is not
    // double-counted: 3 recorded scans, not 4.
    const html = panel(mkProject([entry(30, 1), entry(60, 5), entry(70, 9)]));
    assert.ok(html.includes('3 measurements'), 'sample size must be visible');
    assert.ok(html.includes('over 8 days'), 'time span must be visible');
    assert.ok(!html.includes('too few to call a trend'), '3 points clears the warning');
  });

  it('counts the in-flight scan when history does not already contain it', () => {
    const html = panel(mkProject([entry(30, 1), entry(60, 5), entry(70, 9)]), 99);
    assert.ok(html.includes('4 measurements'), 'a new score must be added as a point');
  });

  it('surfaces a corrupt history without failing the report', () => {
    const html = panel(mkProject('{ not json'));
    assert.ok(html.includes('could not be read'));
    assert.ok(html.includes('current score is still accurate'), 'must reassure that the score itself is fine');
    assert.ok(!html.includes('<svg'));
  });

  it('is included in the overview of a full report', () => {
    const html = new HTMLReporter().generate(
      { score: 70, grade: { letter: 'C' }, categories: {} },
      [],
      {},
      mkProject()
    );
    assert.ok(html.includes('Score Trend'));
  });
});