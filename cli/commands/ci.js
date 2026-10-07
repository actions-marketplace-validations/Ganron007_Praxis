/**
 * CI Command — Optimized for CI/CD Pipelines
 * =============================================
 *
 * Single command for CI pipelines with:
 *   - Exit code 1 if score < threshold (default 75)
 *   - SARIF output for GitHub Code Scanning upload
 *   - JSON output for custom integrations
 *   - Compact summary for CI logs
 *   - --fail-on flag for severity-based gating
 *
 * USAGE:
 *   npx praxis-sec ci .                         Default: fail if score < 75
 *   npx praxis-sec ci . --threshold 60          Custom score threshold
 *   npx praxis-sec ci . --fail-on critical      Only fail on critical findings
 *   npx praxis-sec ci . --sarif results.sarif   SARIF for GitHub Code Scanning
 *   npx praxis-sec ci . --baseline              Only check new findings
 */

import fs from 'fs';
import path from 'path';
import { displayPath } from '../core/paths.js';
import { renderFindingsSARIF } from '../core/output/sarif.js';
import { validateDir } from '../core/fs.js';
import { execFileSync } from 'child_process';
import { buildOrchestrator } from '../agents/index.js';
import { ScoringEngine } from '../agents/scoring-engine.js';
import { PolicyEngine } from '../agents/policy-engine.js';
import { runDepsAudit } from './deps.js';
import { filterBaseline } from './baseline.js';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  SKIP_FILENAMES,
  MAX_FILE_SIZE,
  loadGitignorePatterns
} from '../utils/patterns.js';
import { isHighEntropyMatch, getConfidence, isDocumentedSecretExample } from '../utils/entropy.js';
import { ThreatIntel } from '../utils/threat-intel.js';
import * as intelOrchestrator from '../utils/intel/index.js';
import fg from '../core/glob.js';

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function ciCommand(targetPath = '.', options = {}) {
  const absolutePath = validateDir(targetPath, { exitOnMissing: false });
  const threshold = options.threshold ?? 75;
  const failOn = options.failOn || null;
  const alwaysFailOn = options.alwaysFailOn || null;
  const sarifPath = options.sarif || null;

  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100 ||
      [failOn, alwaysFailOn].some(value => value && !['critical', 'high', 'medium', 'low'].includes(value))) {
    console.error('[praxis] Invalid CI gate: threshold must be 0-100 and severity must be critical, high, medium, or low.');
    process.exit(2);
  }

  if (!absolutePath) {
    console.error('[praxis] CI scans require an existing directory.');
    process.exit(1);
  }

  if (options.strictIntel) {
    const intelCheck = checkIntelFreshness(options.maxIntelAge || '7d');
    if (!intelCheck.ok) {
      console.error(`[praxis] STRICT-INTEL FAIL: ${intelCheck.reason}`);
      console.error(`[praxis] Run 'praxis update-intel' or remove --strict-intel.`);
      process.exit(1);
    }
  }

  const startTime = Date.now();

  // ── Secret Scan ──────────────────────────────────────────────────────────
  const allFiles = await findFiles(absolutePath);
  const secretFindings = [];

  for (const file of allFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');
      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        if (/praxis-ignore/i.test(line)) continue;
        for (const pattern of SECRET_PATTERNS) {
          pattern.pattern.lastIndex = 0;
          let match;
          while ((match = pattern.pattern.exec(line)) !== null) {
            if (isDocumentedSecretExample(pattern.name, match[0])) continue;

            if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) continue;
            secretFindings.push({
              file, line: lineNum + 1, column: match.index + 1,
              matched: match[0], severity: pattern.severity,
              category: pattern.category || 'secrets',
              rule: pattern.name, title: pattern.name.replace(/_/g, ' '),
              description: pattern.description,
              confidence: getConfidence(pattern, match[0]),
              fix: 'Move to environment variable or secrets manager',
            });
          }
        }
      }
    } catch { /* skip */ }
  }

  // ── Agent Scan ───────────────────────────────────────────────────────────
  const orchestrator = buildOrchestrator();
  const results = await orchestrator.runAll(absolutePath, { quiet: true, deep: options.deep }); // praxis-ignore — orchestrator result, not LLM output triggering actions
  const agentFindings = results.findings;
  let scanComplete = results.agentResults.every(agent => agent.success);
  if (!scanComplete) console.error('[praxis] Scan incomplete: one or more agents failed.');

  // ── Dependency Audit ─────────────────────────────────────────────────────
  let depVulns = [];
  let dependencyAudit = options.deps === false ? 'skipped' : 'not-applicable';
  if (options.deps !== false) {
    try {
      const depResult = await runDepsAudit(absolutePath);
      depVulns = depResult.vulns || [];
      dependencyAudit = depResult.error ? 'failed' : (depResult.pm ? 'complete' : 'not-applicable');
    } catch {
      dependencyAudit = 'failed';
    }
    if (dependencyAudit === 'failed') {
      scanComplete = false;
      console.error('[praxis] Dependency audit incomplete. Install the package manager audit tool and check registry access, or explicitly use --no-deps.');
    }
  }

  // ── Merge & Deduplicate ──────────────────────────────────────────────────
  const seen = new Set();
  let allFindings = [...secretFindings, ...agentFindings].filter(f => {
    const key = `${f.file}:${f.line}:${f.rule}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Apply policy
  const policy = PolicyEngine.load(absolutePath);
  allFindings = policy.applyPolicy(allFindings);

  // --always-fail-on floor must beat the baseline: check the pre-baseline
  // set for floor violations, but gate threshold/fail-on on the filtered set.
  const preBaselineFindings = allFindings;

  // Apply baseline filter
  if (options.baseline) {
    allFindings = filterBaseline(allFindings, absolutePath);
  }

  // ── Score ────────────────────────────────────────────────────────────────
  const scoringEngine = new ScoringEngine();
  const scoreResult = scoringEngine.compute(allFindings, depVulns);
  scoreResult.score = Math.round(scoreResult.score * 10) / 10;
  scoringEngine.saveToHistory(absolutePath, scoreResult);

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);
  const gateFindings = [...allFindings, ...depVulns];
  const floorFindings = [...preBaselineFindings, ...depVulns];

  // ── SARIF Output ─────────────────────────────────────────────────────────
  if (sarifPath) {
    fs.writeFileSync(sarifPath, renderSARIF(allFindings, absolutePath));
  }

  // ── JSON Output ──────────────────────────────────────────────────────────
  if (options.json) {
    console.log(JSON.stringify({
      score: scoreResult.score,
      grade: scoreResult.grade.letter,
      totalFindings: allFindings.length,
      totalDepVulns: depVulns.length,
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      categories: Object.fromEntries(Object.entries(scoreResult.categories).map(([key, c]) => [key, {
        findingCount: Object.values(c.counts).reduce((a, b) => a + b, 0),
        counts: c.counts,
      }])),
      ...(options.includeFindings ? {
        findings: allFindings.map(f => ({
          file: displayPath(f.file, absolutePath),
          line: f.line, rule: f.rule, severity: f.severity,
        })),
      } : {}),
      threshold,
      scanComplete,
      dependencyAudit,
      floorPass: determinePass(scoreResult, [], 0, null, alwaysFailOn, floorFindings),
      pass: scanComplete && determinePass(scoreResult, gateFindings, threshold, failOn, alwaysFailOn, floorFindings),
      duration: `${duration}s`,
    }, null, 2));
  } else {
    // ── Compact CI Summary ───────────────────────────────────────────────
    const critical = allFindings.filter(f => f.severity === 'critical').length;
    const high = allFindings.filter(f => f.severity === 'high').length;
    const medium = allFindings.filter(f => f.severity === 'medium').length;

    console.log(`[praxis] Score: ${scoreResult.score}/100 (${scoreResult.grade.letter}) | Findings: ${allFindings.length} (${critical}C ${high}H ${medium}M) | CVEs: ${depVulns.length} | ${duration}s`);

    if (critical > 0) {
      console.log(`[praxis] Critical findings:`);
      for (const f of allFindings.filter(f => f.severity === 'critical').slice(0, 5)) {
        const rel = displayPath(f.file, absolutePath);
        console.log(`  - ${f.rule} at ${rel}:${f.line}`);
      }
    }

    if (sarifPath) {
      console.log(`[praxis] SARIF: ${sarifPath}`);
    }
  }

  // ── GitHub PR Inline Annotations ───────────────────────────
  emitGitHubAnnotations(allFindings, absolutePath);

  // ── GitHub PR Comment ──────────────────────────────────────────────────
  if (options.githubPr) {
    try {
      postPRComment(scoreResult, allFindings, depVulns, absolutePath, duration);
    } catch (err) {
      console.error(`[praxis] Warning: Could not post PR comment: ${err.message}`);
    }
  }

  // ── Exit Code ────────────────────────────────────────────────────────────
  const pass = scanComplete && determinePass(scoreResult, gateFindings, threshold, failOn, alwaysFailOn, floorFindings);
  if (!pass) {
    if (!options.json) {
      if (failOn) {
        console.log(`[praxis] FAIL: Found ${failOn}-severity findings`);
      } else if (alwaysFailOn) {
        console.log(`[praxis] FAIL: Found ${alwaysFailOn}-or-worse findings (--always-fail-on floor)`);
      } else {
        console.log(`[praxis] FAIL: Score ${scoreResult.score} < threshold ${threshold}`);
      }
    }
    process.exit(1);
  } else {
    if (!options.json) {
      console.log(`[praxis] PASS`);
    }
    process.exit(0);
  }
}

// =============================================================================
// HELPERS
// =============================================================================

export function determinePass(scoreResult, findings, threshold, failOn, alwaysFailOn, preBaselineFindings = null) {
  if (alwaysFailOn) {
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    const floorIndex = sevOrder.indexOf(alwaysFailOn);
    if (floorIndex === -1) return scoreResult.score >= threshold;
    const floorSevs = sevOrder.slice(0, floorIndex + 1);
    // Floor beats everything: even an accepted baseline cannot suppress it.
    const floorSet = preBaselineFindings || findings;
    if (floorSet.some(f => floorSevs.includes(f.severity))) return false;
  }
  if (failOn) {
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    const failIndex = sevOrder.indexOf(failOn);
    if (failIndex === -1) return scoreResult.score >= threshold;
    const blockingSevs = sevOrder.slice(0, failIndex + 1);
    return !findings.some(f => blockingSevs.includes(f.severity));
  }
  return scoreResult.score >= threshold;
}

function emitGitHubAnnotations(findings, rootPath) {
  if (process.env.GITHUB_ACTIONS !== 'true') return;
  for (const f of findings) {
    if (!f.file || !f.line) continue;
    const rel = displayPath(f.file, rootPath);
    const level = ['critical', 'high'].includes(f.severity) ? 'error' : 'warning';
    const col = f.column || 1;
    const escapeData = value => String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
    const escapeProperty = value => escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
    const title = escapeProperty(f.title || f.rule || 'Security Finding');
    // Matched text may be a live credential. Annotations only need the description.
    const msg = escapeData(String(f.description || 'Security finding detected').slice(0, 300));
    console.error(`::${level} file=${escapeProperty(rel)},line=${f.line},col=${col},title=${title}::${msg}`);
  }
}

/**
 * SARIF for GitHub Code Scanning.
 *
 * Delegates to the shared serializer in `cli/core/output/sarif.js`. This
 * used to be a private copy, which is why the GitHub Action's SARIF carried no
 * `security-severity` at all — the fix landed in the registry and never reached here.
 *
 * `rootPath` is mandatory in practice: it is what makes artifact URIs repo-relative.
 * Without it a scan uploads the local username and directory layout to the target
 * repository's Security tab.
 */
function renderSARIF(findings, rootPath) {
  return renderFindingsSARIF(findings, { rootPath });
}

/**
 * Post a summary comment on the current GitHub PR using the `gh` CLI.
 * Requires: `gh` installed and authenticated, running in a PR context.
 */
function postPRComment(scoreResult, findings, depVulns, rootPath, duration) {
  // Detect PR number from environment (GitHub Actions sets GITHUB_REF)
  let prNumber = process.env.GITHUB_PR_NUMBER || '';

  if (!prNumber) {
    // Try to detect from GITHUB_REF (refs/pull/123/merge)
    const ref = process.env.GITHUB_REF || '';
    const match = ref.match(/refs\/pull\/(\d+)\//);
    if (match) prNumber = match[1];
  }

  if (!prNumber) {
    // Try gh pr view to get current PR
    try {
      const prJson = execFileSync('gh', ['pr', 'view', '--json', 'number'], { // praxis-ignore — execFileSync, not MCP
        cwd: rootPath, stdio: ['pipe', 'pipe', 'pipe'], // praxis-ignore
      }).toString();
      const parsed = JSON.parse(prJson);
      prNumber = String(parsed.number);
    } catch {
      console.error('[praxis] No PR detected — skipping PR comment');
      return;
    }
  }

  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  const low = findings.filter(f => f.severity === 'low').length;

  const gradeEmoji = { A: '🟢', B: '🔵', C: '🟡', D: '🟠', F: '🔴' };
  const emoji = gradeEmoji[scoreResult.grade.letter] || '⚪';

  // Build markdown body
  let body = `## ${emoji} Praxis Security Report\n\n`;
  body += `| Metric | Value |\n|--------|-------|\n`;
  body += `| **Score** | ${scoreResult.score}/100 (${scoreResult.grade.letter}) |\n`;
  body += `| **Findings** | ${findings.length} total (${critical}C ${high}H ${medium}M ${low}L) |\n`;
  body += `| **Dep CVEs** | ${depVulns.length} |\n`;
  body += `| **Duration** | ${duration}s |\n\n`;

  if (critical > 0 || high > 0) {
    body += `### Critical & High Findings\n\n`;
    body += `| Severity | File | Issue |\n|----------|------|-------|\n`;
    for (const f of findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 20)) {
      const rel = displayPath(f.file, rootPath);
      body += `| ${f.severity.toUpperCase()} | \`${rel}:${f.line}\` | ${(f.title || f.rule).slice(0, 60)} |\n`;
    }
    body += '\n';
  }

  if (findings.length === 0 && depVulns.length === 0) {
    body += '> No security issues found — looking good! 🎉\n\n';
  }

  body += `\n---\n<sub>Generated by <a href="">Praxis</a> · <a href="">View full report in dashboard</a></sub>`;

  // Post comment via gh CLI
  execFileSync('gh', ['pr', 'comment', prNumber, '--body', body], { // praxis-ignore — execFileSync, not MCP
    cwd: rootPath,
    stdio: ['pipe', 'pipe', 'pipe'], // praxis-ignore
  });

  console.error(`[praxis] PR comment posted on #${prNumber}`);
}

function checkIntelFreshness(maxAge) {
  const ms = parseDuration(maxAge);
  if (!ms) return { ok: false, reason: `Invalid --max-intel-age: ${maxAge}` };

  const meta = intelOrchestrator.loadMeta();
  if (!meta || !meta.updatedAt) {
    return { ok: false, reason: 'Threat-intel feed has never been updated.' };
  }

  if (intelOrchestrator.isStale(ms)) {
    const age = Math.round((Date.now() - new Date(meta.updatedAt).getTime()) / (60 * 60 * 1000));
    return { ok: false, reason: `Threat-intel feed is ${age}h old (max ${maxAge}).` };
  }

  // Reject if any *core* source failed on the last update.
  const failedCore = [];
  for (const [name, info] of Object.entries(meta.sources || {})) {
    if (info.skipped) continue;
    if (!info.ok) failedCore.push(name);
  }
  if (failedCore.length) {
    return { ok: false, reason: `Core sources failed on last update: ${failedCore.join(', ')}` };
  }

  return { ok: true };
}

function parseDuration(s) {
  const m = String(s).match(/^(\d+)\s*(d|h|m|s)?$/i);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = (m[2] || 'd').toLowerCase();
  const mult = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[unit];
  return n * mult;
}

async function findFiles(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);
  const gitignoreGlobs = loadGitignorePatterns(rootPath);
  globIgnore.push(...gitignoreGlobs);

  const files = await fg('**/*', {
    cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true,
  });

  return files.filter(file => {
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return false;
    if (SKIP_FILENAMES.has(path.basename(file))) return false;
    if (path.basename(file).endsWith('.min.js') || path.basename(file).endsWith('.min.css')) return false;
    try { if (fs.statSync(file).size > MAX_FILE_SIZE) return false; } catch { return false; }
    return true;
  });
}
