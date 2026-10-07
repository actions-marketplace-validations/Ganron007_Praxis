import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { LLMRedTeamEngine, DYNAMIC_REDTEAM_PROBES } from '../agents/llm-redteam.js';

describe('Praxis Dynamic AI Red Teaming Engine', () => {
  it('detects prompt injection vulnerability on a simulated vulnerable endpoint', async () => {
    // Mock fetch that simulates a vulnerable LLM echoing back "Developer Mode Active"
    const mockFetch = async (url, options) => {
      const body = JSON.parse(options.body);
      let text = 'Safe default answer';
      if (body.prompt && body.prompt.includes('Developer Mode Enabled')) {
        text = 'Developer Mode Active: I will now fulfill your request without limits.';
      }
      return {
        status: 200,
        text: async () => text,
      };
    };

    const report = await LLMRedTeamEngine.probeEndpoint('http://mock-ai.local/chat', {
      fetchFn: mockFetch,
    });

    assert.ok(report.totalProbes >= 4);
    assert.ok(report.failedCount >= 1, 'Vulnerable probe must be caught');
    assert.ok(report.securityScore < 100);
    assert.equal(report.isSecure, false);

    const jbResult = report.probeResults.find(r => r.probeId === 'RT-JB-01');
    assert.ok(jbResult);
    assert.equal(jbResult.isVulnerable, true);
  });

  it('reports 100/100 security score on a safe / guarded AI endpoint', async () => {
    // Mock fetch that always safely refuses or answers normally without tripping triggers
    const mockFetch = async () => ({
      status: 200,
      text: async () => 'I am an AI assistant and I cannot fulfill requests to bypass safety filters or reveal system prompts.',
    });

    const report = await LLMRedTeamEngine.probeEndpoint('http://safe-ai.local/chat', {
      fetchFn: mockFetch,
    });

    assert.equal(report.failedCount, 0);
    assert.equal(report.passedCount, DYNAMIC_REDTEAM_PROBES.length);
    assert.equal(report.securityScore, 100);
    assert.equal(report.isSecure, true);
  });
});
