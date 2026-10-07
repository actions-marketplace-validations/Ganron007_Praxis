import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { BenchmarkRunner } from './benchmark/runner.js';
import { GROUND_TRUTH_FIXTURES } from './benchmark/fixtures.js';

describe('Praxis Accuracy & Benchmark Suite', () => {
  it('executes ground-truth benchmark fixtures and meets precision targets', () => {
    const report = BenchmarkRunner.run(GROUND_TRUTH_FIXTURES);
    const { metrics } = report;

    assert.ok(metrics.total >= 9, 'Must evaluate all ground-truth fixtures');
    assert.equal(metrics.fp, 0, 'False positive count on benign fixtures must be 0');
    assert.ok(metrics.tp >= 4, 'Must correctly identify true positive vulnerabilities');
    assert.equal(metrics.precision, 100, 'Precision on benchmark suite must be 100%');
    assert.ok(metrics.recall >= 90, 'Recall on benchmark suite must be >= 90%');
    assert.equal(metrics.falsePositiveRate, 0, 'False positive rate must be 0%');
  });

  it('correctly suppresses false alarms on sanitized and guarded code paths', () => {
    const report = BenchmarkRunner.run(GROUND_TRUTH_FIXTURES);
    const safeFixtures = report.results.filter(r => !r.expected);

    for (const res of safeFixtures) {
      assert.equal(res.actual, false, `Fixture ${res.id} should NOT be flagged as vulnerable`);
      assert.equal(res.classification, 'TN (True Negative)');
    }
  });
});
