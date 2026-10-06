/** Marketplace runner: argv-only execution, release-pinned CLI, and one gate decision. */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync, execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

const cli = fileURLToPath(new URL('../bin/praxis.js', import.meta.url));
const severities = ['critical', 'high', 'medium', 'low'];

export function buildScanArgs(inputs, { base = false, sarif = null } = {}) {
  const args = ['scan', 'ci', inputs.path || '.', '--json', '--threshold', base ? '0' : (inputs.threshold || '75')];
  if (inputs.deps === 'false') args.push('--no-deps');
  if (inputs.deep === 'true') args.push('--deep');
  if (!base && inputs.baseline === 'true') args.push('--baseline');
  if (!base && inputs.failOn) args.push('--fail-on', inputs.failOn);
  if (!base && inputs.alwaysFailOn) args.push('--always-fail-on', inputs.alwaysFailOn);
  if (inputs.netNew === 'true') args.push('--include-findings');
  if (sarif) args.push('--sarif', sarif);
  return args;
}

export function parseScanResult(result) {
  if (result.error) throw result.error;
  if (![0, 1].includes(result.status)) throw new Error(`Praxis scan failed (exit ${result.status})`);
  let report;
  try { report = JSON.parse(result.stdout); } catch { throw new Error('Praxis scan did not produce valid JSON'); } // praxis-ignore AGENT_NO_OUTPUT_SCHEMA — subprocess stdout, not LLM output; fields are checked on the next line
  if (!report || typeof report.pass !== 'boolean' || !Number.isFinite(report.score)) {
    throw new Error('Praxis scan produced an invalid report');
  }
  if (result.status === 1 && report.pass) throw new Error('Praxis scan exit status disagrees with report');
  return report;
}

export function introducedFindings(base, head, floor = 'high') {
  const limit = severities.indexOf(floor);
  if (limit < 0) throw new Error(`Invalid fail-on-new severity: ${floor}`);
  if (!Array.isArray(base.findings) || !Array.isArray(head.findings)) throw new Error('Net-new gate requires finding lists from both scans');
  const identity = finding => `${finding.file}:${finding.rule}`;
  const existing = new Set(base.findings.map(identity));
  const introduced = head.findings.filter(finding => !existing.has(identity(finding)));
  return {
    total: introduced.length,
    blocking: introduced.filter(finding => {
      const severity = severities.indexOf(finding.severity);
      return severity >= 0 && severity <= limit;
    }).length,
  };
}

export function evaluateGate(head, base, inputs) {
  if (!base) return { pass: head.pass, introduced: null };
  if (base.scanComplete === false) throw new Error('Base scan is incomplete; refusing to pass the net-new gate');
  const introduced = introducedFindings(base, head, inputs.failOnNew || 'high');
  return { pass: head.scanComplete !== false && head.floorPass !== false && introduced.blocking === 0, introduced };
}

function scan(inputs, cwd, options = {}) {
  const result = spawnSync(process.execPath, [cli, ...buildScanArgs(inputs, options)], {
    cwd, env: process.env, encoding: 'utf8', timeout: 20 * 60 * 1000, maxBuffer: 32 * 1024 * 1024,
  });
  // GitHub annotations go to stderr, keeping the JSON channel valid.
  if (result.stderr) process.stderr.write(result.stderr);
  return parseScanResult(result);
}

export async function runAction(env = process.env) {
  const inputs = {
    path: env.PRAXIS_INPUT_PATH, threshold: env.PRAXIS_INPUT_THRESHOLD,
    failOn: env.PRAXIS_INPUT_FAIL_ON, alwaysFailOn: env.PRAXIS_INPUT_ALWAYS_FAIL_ON,
    deps: env.PRAXIS_INPUT_DEPS, deep: env.PRAXIS_INPUT_DEEP, baseline: env.PRAXIS_INPUT_BASELINE,
    netNew: env.PRAXIS_INPUT_NET_NEW, failOnNew: env.PRAXIS_INPUT_FAIL_ON_NEW,
  };
  const temp = fs.mkdtempSync(path.join(env.RUNNER_TEMP || os.tmpdir(), 'praxis-action-'));
  const sarif = env.PRAXIS_INPUT_SARIF === 'true' ? path.join(temp, 'results.sarif') : null;
  const root = env.GITHUB_WORKSPACE || process.cwd();
  const head = scan(inputs, root, { sarif });
  let base = null;
  if (inputs.netNew === 'true') {
    if (env.GITHUB_EVENT_NAME !== 'pull_request') throw new Error('net-new requires a pull_request event');
    const sha = env.PRAXIS_BASE_SHA || '';
    if (!/^[a-f0-9]{40,64}$/i.test(sha)) throw new Error('Invalid or missing pull request base SHA');
    const worktree = path.join(temp, 'base');
    let added = false;
    try {
      execFileSync('git', ['fetch', '--depth', '1', 'origin', sha], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
      execFileSync('git', ['worktree', 'add', '--detach', worktree, sha], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
      added = true;
      base = scan(inputs, worktree, { base: true });
    } finally {
      if (added) execFileSync('git', ['worktree', 'remove', '--force', worktree], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
    }
  }
  const gate = evaluateGate(head, base, inputs);
  const count = category => head.categories?.[category]?.findingCount || 0;
  const outputs = {
    score: head.score, grade: head.grade, findings: head.totalFindings, secrets: count('secrets'),
    vulns: count('injection') + count('auth'), cves: head.totalDepVulns,
    'sarif-file': sarif && fs.existsSync(sarif) ? sarif : '',
    'report-url': `${env.GITHUB_SERVER_URL || 'https://github.com'}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`,
    fail: gate.pass ? '0' : '1',
  };
  if (env.GITHUB_OUTPUT) {
    fs.appendFileSync(env.GITHUB_OUTPUT, Object.entries(outputs).map(([key, value]) => `${key}=${value ?? ''}`).join('\n') + '\n');
  }
  let summary = `## Praxis Security Report\n\nScore: **${head.score}/100 (${head.grade})** · Findings: **${head.totalFindings}** · CVEs: **${head.totalDepVulns}**\n\n`;
  if (gate.introduced) summary += `Net-new gate: **${gate.introduced.total}** introduced finding(s), **${gate.introduced.blocking}** at or above ${inputs.failOnNew || 'high'}.\n\n`;
  summary += gate.pass ? '**Passed** the configured security gate.\n' : '**Failed** the configured security gate.\n';
  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, summary);
  console.log(summary);
  if (env.PRAXIS_INPUT_COMMENT === 'true' && env.GITHUB_EVENT_NAME === 'pull_request') {
    const pr = env.PRAXIS_PR_NUMBER;
    const repository = env.GITHUB_REPOSITORY;
    if (!/^\d+$/.test(pr || '') || !/^[\w.-]+\/[\w.-]+$/.test(repository || '')) throw new Error('Invalid PR context');
    const marker = '<!-- praxis-security-report -->';
    const body = `${marker}\n${summary}\n[Scanned by Praxis](https://github.com/Ganron007/Praxis)`;
    const bodyPath = path.join(temp, 'comment.json');
    fs.writeFileSync(bodyPath, JSON.stringify({ body }));
    try {
      const comments = JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp', `repos/${repository}/issues/${pr}/comments`], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })).flat();
      const existing = comments.find(comment => comment.user?.type === 'Bot' && comment.body?.includes(marker));
      const endpoint = existing ? `repos/${repository}/issues/comments/${existing.id}` : `repos/${repository}/issues/${pr}/comments`;
      execFileSync('gh', ['api', endpoint, '-X', existing ? 'PATCH' : 'POST', '--input', bodyPath], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch {
      console.error('::warning::Could not post Praxis PR comment. Check pull-requests: write permissions.');
    }
  }
  return gate;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runAction().catch(error => {
    console.error(`::error::${String(error.message).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')}`);
    process.exitCode = 1;
  });
}
