/**
 * Praxis Security Agent — Interactive Fix Loop
 * ================================================
 *
 * Scans your codebase, then for each affected file:
 *   1. Generates a precise multi-edit fix plan via LLM (one plan per file,
 *      addressing every finding in that file at once)
 *   2. Shows you exactly what it will change (unified diff with line numbers)
 *   3. Asks you to accept, skip, or quit
 *   4. Applies the changes atomically
 *   5. Re-scans to verify the findings are resolved
 *   6. Logs every change to .praxis/fixes.jsonl
 *
 * USAGE:
 *   praxis agent [path]              Interactive fix loop
 *   praxis agent . --plan-only       Generate plans, never write
 *   praxis agent . --severity high   Only fix high+ severity
 *   praxis agent . --branch fixes    Create a branch, commit per file
 *   praxis agent . --pr              After fixing, push and open a PR
 *   praxis agent . --provider deepseek-flash
 *
 * SAFETY:
 *   - Refuses to operate on a dirty git tree (use --allow-dirty to override)
 *   - Always shows a diff before any write
 *   - Re-scans after each batch to verify the fix
 *   - Plans may create new files (e.g., .env.example) but cannot edit
 *     .env, secrets, lockfiles, or build artifacts
 *   - Every applied change is logged for audit & undo (`praxis undo`)
 */

import fs from 'fs';
import { fileURLToPath } from 'url';
import path, { dirname } from 'path';
import { createInterface } from 'readline';

const __filename = fileURLToPath(import.meta.url); // praxis-ignore — module's own path via import.meta.url, not user input
const __dirname = dirname(__filename);
const praxisDir = path.resolve(__dirname, '../..');
import { execFileSync } from 'child_process';
import chalk from 'chalk';
import ora from 'ora';
import { autoDetectProvider } from '../providers/llm-provider.js';
import { auditCommand } from './audit.js';
import { ASTParser } from '../core/ast/index.js';
import * as output from '../utils/output.js';
import { validatePlan, applyPlan, restoreSnapshots, isProtectedFixPath } from '../core/fix-plan.js';

const SEV_RANK   = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const FIX_LOG_DIR  = '.praxis';
const FIX_LOG_FILE = 'fixes.jsonl';

// =============================================================================
// MAIN
// =============================================================================

export async function agentFixCommand(targetPath = '.', options = {}) {
  const root = path.resolve(targetPath);

  if (!fs.existsSync(root)) {
    output.error(`Path does not exist: ${root}`);
    process.exit(1);
  }

  console.log();
  output.header('Praxis — Security Agent');
  console.log(chalk.gray('  I will scan, plan each fix, ask before changing anything,'));
  console.log(chalk.gray('  and verify the fix worked. You stay in control.'));
  console.log();

  // ── Git safety check ─────────────────────────────────────────────────────
  const initialBranch = getCurrentBranch(root);
  if (!options.allowDirty) {
    const state = checkGitState(root);
    if (state === 'not-a-repo') {
      console.log(chalk.yellow('  Note: this is not a git repository.'));
      console.log(chalk.gray('  Changes cannot be reverted automatically.'));
      if (options.ci) {
        console.log(chalk.gray('  CI mode active: automatically continuing.'));
      } else {
        const ok = await confirm('  Continue anyway?');
        if (!ok) { console.log(chalk.gray('  Aborted.\n')); return; }
      }
    } else if (state === 'dirty') {
      output.error('Working tree has uncommitted changes.');
      console.log(chalk.gray('  Commit or stash first, or pass --allow-dirty.'));
      process.exit(1);
    }
  }

  // ── Optional branch isolation ────────────────────────────────────────────
  let branchCreated = null;
  if (options.branch) {
    if (!initialBranch) {
      console.log(chalk.yellow('  --branch requires a git repository. Skipping branch creation.'));
    } else {
      const stamp      = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 16);
      const branchName = options.branch === true
        ? `praxis/fixes-${stamp}`
        : String(options.branch);
      try {
        execFileSync('git', ['checkout', '-b', branchName], { cwd: root, stdio: 'pipe' });
        branchCreated = branchName;
        console.log(chalk.gray(`  Branch: ${chalk.cyan(branchName)}`));
      } catch (err) {
        output.error(`Could not create branch ${branchName}: ${err.message}`);
        process.exit(1);
      }
    }
  }

  // ── Load LLM provider ────────────────────────────────────────────────────
  const provider = autoDetectProvider(root, {
    provider: options.provider,
    model:    options.model,
    think:    options.think || false,
  });
  if (!provider) {
    output.error('No LLM provider available.');
    console.log(chalk.gray('  Set one of: DEEPSEEK_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, MOONSHOT_API_KEY, XAI_API_KEY'));
    process.exit(1);
  }
  console.log(chalk.gray(`  Provider: ${chalk.cyan(provider.name)}`));

  if (options.sandbox) {
    console.log(chalk.gray('  Sandbox:  ' + chalk.green('active') + ' (verifying fixes in Docker container)'));
  }

  // ── Run the scan ─────────────────────────────────────────────────────────
  const scanSpinner = ora({ text: 'Scanning for issues...', color: 'cyan' }).start();
  let scanResult;
  try {
    scanResult = await auditCommand(root, { _agenticInner: true, deep: false, deps: false, noAi: true });
    if (!scanResult || scanResult.scanComplete !== true) throw new Error('Initial scan incomplete; refusing to generate fixes');
  } catch (err) {
    scanSpinner.fail('Scan failed');
    output.error(err.message);
    process.exit(1);
  }
  scanSpinner.stop();

  // ── Filter findings ──────────────────────────────────────────────────────
  const minSev  = options.severity || 'low';
  const minRank = SEV_RANK[minSev] ?? 1;

  const findings = (scanResult.findings ?? []).filter(f => {
    if (!f.file) return false;
    if ((SEV_RANK[f.severity] ?? 0) < minRank) return false;
    const rel = f.file.replace(/\\/g, '/');
    if (isProtectedFixPath(rel)) return false;
    const abs = path.resolve(root, f.file);
    return fs.existsSync(abs);
  });

  if (findings.length === 0) {
    output.success('No fixable findings at the requested severity.');
    console.log();
    return;
  }

  // ── Group by file ────────────────────────────────────────────────────────
  const byFile = new Map();
  for (const f of findings) {
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }

  console.log(chalk.cyan(`  Found ${findings.length} fixable finding(s) across ${byFile.size} file(s)`));
  console.log();

  // ── Fix loop ─────────────────────────────────────────────────────────────
  const applied = []; // { file, plan, verified }
  const skipped = []; // { file, findings, reason }
  let stopped   = false;
  let i         = 0;

  for (const [filePath, fileFindings] of byFile) {
    i++;
    if (stopped) break;

    const idx = `[${i}/${byFile.size}]`;
    console.log();
    console.log(chalk.bold(`  ${idx} ${chalk.cyan(filePath)} ${chalk.gray(`— ${fileFindings.length} finding(s)`)}`));
    for (const f of fileFindings) {
      console.log(`      ${severityLabel(f.severity)} ${f.title}${f.line ? chalk.gray(` (line ${f.line})`) : ''}`);
    }

    // ── Plan → apply → verify ladder, with one evidence-fed retry ──────────
    const maxAttempts = options.maxAttempts || 2;
    let retryEvidence = '';
    let decision = null;
    let finalPlan = null;
    let finalVerified = null;
    let snapshots = []; // files touched by the currently applied attempt
    let ladderFailed = false; // verification failed with nothing resolved

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      if (retryEvidence) {
        console.log(chalk.yellow(`      Verification failed — retrying plan with failure evidence (attempt ${attempt}/${maxAttempts})`));
      }

      // Generate plan
      const planSpinner = ora({ text: retryEvidence ? 'Regenerating fix plan...' : 'Generating fix plan...', color: 'cyan', indent: 6 }).start();
      const planResult = await generateBatchPlan(provider, root, filePath, fileFindings, retryEvidence);
      planSpinner.stop();

      if (!planResult.ok) {
        const detail = describePlanFailure(planResult);
        console.log(chalk.yellow(`      ${detail.message}`));
        logFailure(root, { timestamp: new Date().toISOString(), file: filePath, findings: fileFindings.map(f => ({ title: f.title, line: f.line, rule: f.rule })), ...planResult });
        skipped.push({ file: filePath, findings: fileFindings, reason: detail.reason });
        finalPlan = null;
        break;
      }
      const plan = planResult.plan;

      // Validate (allows new safe files like .env.example)
      const validation = validatePlan(root, plan);
      if (!validation.ok) {
        console.log(chalk.yellow(`      Plan invalid: ${validation.reason}`));
        logFailure(root, { timestamp: new Date().toISOString(), file: filePath, findings: fileFindings.map(f => ({ title: f.title, line: f.line, rule: f.rule })), reason: 'validation-rejected', detail: validation.reason, plan });
        skipped.push({ file: filePath, findings: fileFindings, reason: `plan-invalid: ${validation.reason}` });
        finalPlan = null;
        break;
      }

      // Show plan
      printPlan(plan, root);

      if (options.planOnly) {
        console.log(chalk.gray('      (plan-only mode — not applying)'));
        finalPlan = null;
        break;
      }

      // Each distinct plan needs approval, unless an explicit auto mode is enabled.
      if (decision === null) {
        const risk = (plan.risk || 'medium').toLowerCase();
        if (options.yolo || options.ci) {
          decision = 'a';
          console.log(chalk.gray(`      (${options.ci ? 'ci' : 'yolo'}: auto-accepting)`));
        } else if (options.autoLow && risk === 'low') {
          decision = 'a';
          console.log(chalk.gray('      (auto-low: low-risk, auto-accepting)'));
        } else {
          decision = await promptDecision(plan, root);
        }
      }

      if (decision === 'q' || decision === 'quit') {
        console.log(chalk.gray('      Stopping.'));
        stopped = true;
        finalPlan = null;
        break;
      }
      if (!['a', 'accept', 'y', 'yes'].includes(decision)) {
        skipped.push({ file: filePath, findings: fileFindings, reason: 'user-skipped' });
        finalPlan = null;
        break;
      }

      // Revalidate after approval and roll back a partially applied plan on error.
      let applyErr = null;
      try {
        snapshots = applyPlan(root, plan);
      } catch (err) {
        applyErr = err.message;
      }

      if (applyErr) {
        console.log(chalk.red(`      Apply failed: ${applyErr}`));
        skipped.push({ file: filePath, findings: fileFindings, reason: `apply-failed: ${applyErr}` });
        finalPlan = null;
        break;
      }

      // Verify — tiered ladder (build → tests → re-scan)
      const verifySpinner = ora({ text: 'Verifying (build → tests → re-scan)...', color: 'cyan', indent: 6 }).start();
      const verified = await verifyFile(root, filePath, fileFindings, options);
      finalPlan = plan;
      finalVerified = verified;

      if (verified.allResolved) {
        const ranTiers = (verified.tiers || []).map(t => t.tier);
        verifySpinner.succeed(chalk.green(`Fix verified — ${fileFindings.length} finding(s) resolved (${[...ranTiers, 're-scan'].join(' → ')})`));
        ladderFailed = false;
        break;
      }

      if (verified.someResolved) {
        verifySpinner.warn(chalk.yellow(`Partial: ${verified.resolvedCount}/${fileFindings.length} resolved`));
        ladderFailed = false;
      } else {
        verifySpinner.warn(chalk.yellow(`Verification failed at tier "${verified.failedTier}"`));
        ladderFailed = true;
      }

      // Evidence-fed retry
      if (attempt < maxAttempts && verified.evidence) {
        restoreSnapshots(snapshots);
        snapshots = [];
        finalPlan = null;
        finalVerified = null;
        ladderFailed = false;
        decision = null; // a regenerated plan needs its own approval
        retryEvidence = verified.evidence;
        continue;
      }
      break;
    }

    // Revert failed fixes (nothing resolved) so the repo stays consistent —
    // even when the retry plan itself failed to generate.
    if (ladderFailed && snapshots.length > 0) {
      restoreSnapshots(snapshots);
      console.log(chalk.yellow('      Reverted failed fix — file(s) restored to pre-fix state.'));
      logFailure(root, {
        timestamp: new Date().toISOString(),
        file: filePath,
        findings: fileFindings.map(f => ({ title: f.title, line: f.line, rule: f.rule })),
        reason: 'verification-failed',
        detail: finalVerified?.evidence || 'verification failed',
        plan: finalPlan,
      });
      skipped.push({ file: filePath, findings: fileFindings, reason: `verification-failed: ${finalVerified?.failedTier || 'unknown'}` });
      continue;
    }

    if (!finalPlan || !finalVerified) continue;

    // Per-fix commit (if branch isolation in use)
    const written = finalPlan.files.map(fc => path.resolve(root, fc.path));
    let commitHash = null;
    if (branchCreated) {
      try {
        execFileSync('git', ['add', '--', ...written], { cwd: root, stdio: 'pipe' });
        const titles = fileFindings.slice(0, 3).map(f => f.title).join(', ');
        const more   = fileFindings.length > 3 ? ` (+${fileFindings.length - 3} more)` : '';
        const msg    = `fix(security): ${filePath} — ${titles}${more}`;
        execFileSync('git', ['commit', '-m', msg], { cwd: root, stdio: 'pipe' });
        commitHash = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf-8' }).trim();
      } catch {
        // commit failed — most likely nothing staged because edits were no-ops
      }
    }

    // Log
    logFix(root, {
      timestamp: new Date().toISOString(),
      file:      filePath,
      findings:  fileFindings.map(f => ({ title: f.title, line: f.line, severity: f.severity, rule: f.rule })),
      plan:      finalPlan,
      verified:  finalVerified.allResolved,
      verificationClass: finalVerified.verification,
      verificationTiers: (finalVerified.tiers || []).map(t => ({ tier: t.tier, command: t.command, ok: t.ok })),
      branch:    branchCreated,
      commitHash,
    });

    applied.push({ file: filePath, plan: finalPlan, verified: finalVerified });
  }

  // ── Final report ─────────────────────────────────────────────────────────
  console.log();
  console.log();
  output.header('Summary');
  console.log();
  console.log(`  ${chalk.green('Applied:')} ${applied.length} file(s)`);
  console.log(`  ${chalk.gray('Skipped:')} ${skipped.length} file(s)`);

  if (applied.length > 0) {
    console.log();
    console.log(chalk.gray('  Applied:'));
    for (const a of applied) {
      const mark = a.verified.allResolved ? chalk.green('✓') : chalk.yellow('?');
      console.log(`    ${mark} ${a.file}`);
    }
    console.log();
    console.log(chalk.gray(`  Audit log: ${path.join(FIX_LOG_DIR, FIX_LOG_FILE)}`));
    if (branchCreated) {
      console.log(chalk.gray(`  Branch:    ${chalk.cyan(branchCreated)}`));
      console.log(chalk.gray(`  Switch back: git checkout ${initialBranch}`));
    } else {
      console.log(chalk.gray('  Review:    git diff'));
      console.log(chalk.gray('  Undo last: praxis undo'));
    }
  }

  // ── PR autopilot ─────────────────────────────────────────────────────────
  if (options.pr && applied.length > 0 && branchCreated) {
    console.log();
    await openPullRequest(root, branchCreated, applied);
  } else if (options.pr && !branchCreated) {
    console.log();
    console.log(chalk.yellow('  --pr requires --branch. Skipping PR creation.'));
  }

  if (skipped.length > 0 && applied.length === 0) {
    console.log();
    console.log(chalk.gray('  Tip: try a different provider with --provider, or run with --plan-only'));
    console.log(chalk.gray('  to inspect what would change.'));
  }

  console.log();
}

// =============================================================================
// PLAN GENERATION
// =============================================================================

// Generate a fix plan for a file. Returns either:
//   { ok: true, plan }                       — plan generated successfully
//   { ok: false, reason, raw, error }        — failed; reason is one of:
//       'file-read-failed' | 'provider-error' | 'parse-error' |
//       'llm-declined' | 'empty-response'
// Caller decides what to do with the failure (log, persist, skip).
async function generateBatchPlan(provider, root, filePath, fileFindings, retryEvidence = '') {
  const abs = path.resolve(root, filePath);
  let content;
  try {
    content = fs.readFileSync(abs, 'utf8');
  } catch (err) {
    return { ok: false, reason: 'file-read-failed', error: err.message };
  }

  const fileForPrompt = windowFileContent(content, fileFindings);

  const findingsBlock = fileFindings.map((f, i) => `
${i + 1}. [${f.severity.toUpperCase()}] ${f.title}${f.line ? ` (line ${f.line})` : ''}
   Rule: ${f.rule ?? 'N/A'}
   Description: ${f.description ?? 'N/A'}${f.fix ? `\n   Suggested fix: ${f.fix}` : ''}
`).join('');

  const systemPrompt = 'You are a security engineer. Produce precise code edits as structured JSON only. Never include prose, markdown, or code fences. Output a single JSON object.';

  const userPrompt = `Fix all of these security findings in a single file by producing one coordinated plan.

FILE: ${filePath}

FINDINGS (${fileFindings.length}):
${findingsBlock}

CURRENT FILE CONTENT:
\`\`\`
${fileForPrompt}
\`\`\`

OUTPUT this exact JSON shape:
{
  "summary": "one short sentence describing what you'll do across all findings",
  "files": [
    {
      "path": "${filePath}",
      "edits": [
        { "find": "EXACT verbatim substring", "replace": "new string", "reason": "addresses finding N" }
      ]
    }
  ],
  "risk": "low"
}

You MAY also include companion file changes (only these are allowed):
  - .env.example  — add placeholders for any secrets you moved to env vars
  - .gitignore    — add patterns for files that should not be committed

For companion files, use this shape (no "find" needed):
  { "path": ".env.example", "create": true, "content": "FULL FILE CONTENT" }
or to append:
  { "path": ".gitignore", "append": "PATTERN_TO_ADD\\n" }

RULES:
- Each "find" string must appear EXACTLY ONCE in the file. Include enough context (3+ lines) for uniqueness.
- "replace" must be the corrected code. Preserve indentation and surrounding style.
- Address each finding listed above with at least one edit (or explain in summary why a finding can't be mechanically fixed).
- GREP FOR SIBLING CALL SITES: search the file (and clearly-related helper files) for every other instance of the same dangerous pattern and fix all of them, not just the flagged line. A fix that leaves variant call sites behind fails verification.
- REGRESSION TEST: if this project has a test suite, include a test in your edits that fails before your fix and passes after it.
- Risk: "low" = mechanical, "medium" = behavior change, "high" = architectural. Use "high" sparingly.
- If you cannot produce a precise mechanical plan, return {"summary":"requires manual review","files":[],"risk":"high"}
- JSON only. No prose. No code fences.${retryEvidence ? `

PREVIOUS ATTEMPT FEEDBACK — your earlier plan was applied but automated verification failed:

${retryEvidence}

Produce a corrected plan against the CURRENT file content below. Diagnose the root cause of the
verification failure (build break, failing test, or finding still present) and fix it.` : ''}`;

  let response;
  try {
    response = await provider.complete(systemPrompt, userPrompt, {
      maxTokens: 3000,
      jsonMode:  true,
    });
  } catch (err) {
    return { ok: false, reason: 'provider-error', error: err.message };
  }

  if (!response || !response.trim()) {
    return { ok: false, reason: 'empty-response', raw: response ?? '' };
  }

  const plan = parseJsonLoose(response);
  if (!plan) {
    return { ok: false, reason: 'parse-error', raw: response };
  }
  if (!Array.isArray(plan.files) || plan.files.length === 0) {
    // The LLM returned valid JSON but explicitly declined to produce edits
    // (typically with summary like "requires manual review"). This is a
    // legitimate "I don't know" — not a bug.
    return { ok: false, reason: 'llm-declined', raw: response, plan };
  }

  return { ok: true, plan };
}

function parseJsonLoose(response) {
  if (!response) return null;
  const cleaned = response.trim()
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/```\s*$/i, '')
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const m = cleaned.match(/\{[\s\S]*\}/);
    if (m) {
      try { return JSON.parse(m[0]); } catch { return null; }
    }
    return null;
  }
}

function windowFileContent(content, fileFindings) {
  if (content.length <= 8000) return content;
  if (!Array.isArray(fileFindings) || fileFindings.length === 0) {
    return content.slice(0, 8000);
  }
  
  const lines = content.split('\n');
  const RADIUS = 40;
  
  const targetLines = [...new Set(fileFindings.map(f => f.line).filter(Boolean))].sort((a, b) => a - b);
  if (targetLines.length === 0) return content.slice(0, 8000);
  
  const ranges = [];
  for (const line of targetLines) {
    const start = Math.max(0, line - 1 - RADIUS);
    const end = Math.min(lines.length - 1, line - 1 + RADIUS);
    if (ranges.length === 0) {
      ranges.push({ start, end });
    } else {
      const last = ranges[ranges.length - 1];
      if (start <= last.end + 5) {
        last.end = Math.max(last.end, end);
      } else {
        ranges.push({ start, end });
      }
    }
  }
  
  const result = [];
  let lastEnd = 0;
  for (const r of ranges) {
    if (r.start > lastEnd) {
      result.push(`// ... [lines ${lastEnd + 1}-${r.start} truncated] ...`);
    }
    result.push(lines.slice(r.start, r.end + 1).join('\n'));
    lastEnd = r.end + 1;
  }
  if (lastEnd < lines.length) {
    result.push(`// ... [lines ${lastEnd + 1}-${lines.length} truncated] ...`);
  }
  return result.join('\n');
}

// =============================================================================
// PLAN VALIDATION
// =============================================================================

// =============================================================================
// PRINTING
// =============================================================================

function printPlan(plan, _root) {
  console.log();
  console.log(chalk.bold('      Plan:'));
  console.log(chalk.white(`        ${plan.summary || '(no summary)'}`));
  if (plan.risk) {
    const riskColor = plan.risk === 'low' ? chalk.green : plan.risk === 'medium' ? chalk.yellow : chalk.red;
    console.log(`        Risk: ${riskColor(plan.risk)}`);
  }
  console.log();

  for (const f of plan.files) {
    if (f.create) {
      console.log(chalk.bold(`      ${chalk.green('+ ')}${f.path} ${chalk.gray('(new file)')}`));
      printNewFilePreview(f.content);
      continue;
    }
    if (f.append !== undefined) {
      console.log(chalk.bold(`      ${f.path} ${chalk.gray('(append)')}`));
      for (const l of f.append.split('\n')) {
        if (l) console.log(chalk.green(`        + ${l}`));
      }
      continue;
    }
    console.log(chalk.bold(`      ${f.path}`));
    for (const e of f.edits) {
      console.log(chalk.gray(`        — ${e.reason || 'edit'}`));
      printDiff(e._resolvedFind || e.find, e.replace);
    }
  }
  console.log();
}

function printNewFilePreview(content) {
  const lines = content.split('\n');
  const max = 6;
  const shown = lines.slice(0, max);
  for (const l of shown) console.log(chalk.green(`        + ${l}`));
  if (lines.length > max) {
    console.log(chalk.gray(`        … +${lines.length - max} more line(s)`));
  }
}

function printDiff(oldStr, newStr) {
  const oldLines = oldStr.split('\n');
  const newLines = newStr.split('\n');
  for (const l of oldLines) console.log(chalk.red(`        - ${l}`));
  for (const l of newLines) console.log(chalk.green(`        + ${l}`));
}

function severityLabel(sev) {
  switch (sev) {
    case 'critical': return chalk.red.bold('[CRITICAL]');
    case 'high':     return chalk.red('[HIGH]');
    case 'medium':   return chalk.yellow('[MEDIUM]');
    case 'low':      return chalk.blue('[LOW]');
    default:         return chalk.gray(`[${(sev || 'INFO').toUpperCase()}]`);
  }
}

// =============================================================================
// APPLY
// =============================================================================

// =============================================================================
// VERIFY — tiered ladder
// =============================================================================
// Executable oracles only; no tier is decided by model judgment:
//   Tier 1  build/lint   — the project's own build (or lint) must still pass
//   Tier 2  test suite   — the project's test command must still pass
//   Tier 3  re-scan      — original findings must be gone from the fixed file
// Failing tier evidence is returned so the caller can feed it into a retry.

function isDockerAvailable() {
  try {
    execFileSync('docker', ['info'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function detectBuildCommand(root) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    if (typeof pkg.scripts?.build === 'string') return { label: 'build', command: ['npm', 'run', 'build'] };
    if (typeof pkg.scripts?.lint === 'string') return { label: 'lint', command: ['npm', 'run', 'lint'] };
  } catch { /* no package.json */ }
  if (fs.existsSync(path.join(root, 'Cargo.toml'))) return { label: 'build', command: ['cargo', 'build'] };
  if (fs.existsSync(path.join(root, 'go.mod'))) return { label: 'build', command: ['go', 'build', './...'] };
  if (fs.existsSync(path.join(root, 'Makefile'))) return { label: 'build', command: ['make'] };
  return null;
}

function detectTestCommand(root) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    if (typeof pkg.scripts?.test === 'string') return { label: 'test', command: ['npm', 'test'] };
  } catch { /* no package.json */ }
  if (fs.existsSync(path.join(root, 'Cargo.toml'))) return { label: 'test', command: ['cargo', 'test'] };
  if (fs.existsSync(path.join(root, 'go.mod'))) return { label: 'test', command: ['go', 'test', './...'] };
  if (fs.existsSync(path.join(root, 'pyproject.toml')) || fs.existsSync(path.join(root, 'pytest.ini'))) return { label: 'test', command: ['pytest'] };
  return null;
}

function runProjectCommand(root, command, timeoutMs = 300000) {
  const [cmd0, ...args] = command;
  try {
    let stdout;
    if (process.platform === 'win32' && /^npm$/.test(cmd0)) {
      // npm is a .cmd shim on Windows — spawnSync of .cmd files returns EINVAL
      // without a shell. Commands are fixed internal strings (no user input).
      const line = `npm.cmd ${args.map(a => `"${a}"`).join(' ')}`;
      stdout = execFileSync(line, {
        cwd: root,
        shell: true,
        encoding: 'utf-8',
        timeout: timeoutMs,
        maxBuffer: 10 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } else {
      stdout = execFileSync(cmd0, args, {
        cwd: root,
        encoding: 'utf-8',
        timeout: timeoutMs,
        maxBuffer: 10 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    }
    return { ok: true, exitCode: 0, output: String(stdout).slice(-800) };
  } catch (err) {
    const output = String((err.stdout || '') + '\n' + (err.stderr || '')).slice(-800);
    const timedOut = err.killed || /ETIMEDOUT|timed out/i.test(err.message);
    return { ok: false, exitCode: err.status ?? -1, output, timedOut };
  }
}

async function rescanForFile(root, filePath, options) {
  if (options.sandbox && isDockerAvailable()) {
    const stdout = execFileSync('docker', [
      'run', '--rm',
      '-v', `${root}:/workspace`,
      '-v', `${praxisDir}:/opt/praxis:ro`,
      '-w', '/workspace',
      'node:18-alpine',
      'node', '/opt/praxis/cli/bin/praxis.js', 'scan', '.', '--json'
    ], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });

    const jsonStart = stdout.search(/^\s*\{/m);
    if (jsonStart === -1) throw new Error('Sandbox re-scan produced no JSON');
    const report = JSON.parse(stdout.slice(jsonStart));
    if (!Array.isArray(report.findings)) throw new Error('Sandbox re-scan produced no finding list');
    return report;
  }
  return auditCommand(root, { _agenticInner: true, json: true, deep: false, deps: false, noAi: true });
}

export async function verifyFile(root, filePath, originalFindings, options = {}) {
  const tiers = [];

  try {
    // Tier 0 — AST syntax verification
    const ext = path.extname(filePath).toLowerCase();
    if (['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.py'].includes(ext)) {
      try {
        const fileContent = fs.readFileSync(path.resolve(root, filePath), 'utf8');
        const parsed = ASTParser.parse(fileContent, filePath);
        const hasValidAST = parsed && parsed.ast && Array.isArray(parsed.ast.body);
        tiers.push({ tier: 'ast_syntax', ok: hasValidAST });
        if (!hasValidAST) {
          return {
            allResolved: false, someResolved: false, resolvedCount: 0,
            verification: 'failed', failedTier: 'ast_syntax',
            evidence: `AST syntax verification failed on fixed file: ${filePath}`,
            tiers,
          };
        }
      } catch (err) {
        return {
          allResolved: false, someResolved: false, resolvedCount: 0,
          verification: 'failed', failedTier: 'ast_syntax',
          evidence: `AST syntax verification failed: ${err.message}`,
          tiers,
        };
      }
    }

    // Tier 1 — build/lint
    const build = detectBuildCommand(root);
    if (build) {
      const r = runProjectCommand(root, build.command);
      tiers.push({ tier: 'build', command: build.command.join(' '), ok: r.ok, output: r.output });
      if (!r.ok) {
        return {
          allResolved: false, someResolved: false, resolvedCount: 0,
          verification: 'failed', failedTier: 'build',
          evidence: `Build failed (${build.label}): ${r.output}`.slice(0, 1200),
          tiers,
        };
      }
    }

    // Tier 2 — test suite
    const test = detectTestCommand(root);
    if (test) {
      const r = runProjectCommand(root, test.command, 600000);
      tiers.push({ tier: 'test', command: test.command.join(' '), ok: r.ok, output: r.output });
      if (!r.ok) {
        return {
          allResolved: false, someResolved: false, resolvedCount: 0,
          verification: 'failed', failedTier: 'test',
          evidence: `Tests failed (${test.label}): ${r.output}`.slice(0, 1200),
          tiers,
        };
      }
    }

    // Tier 3 — re-scan: original findings must be gone from the fixed file
    const result = await rescanForFile(root, filePath, options);
    if (!result || result.scanComplete !== true) throw new Error('Verification scan incomplete; findings cannot be treated as resolved');
    const remaining = (result.findings ?? []).filter(f => {
      const fPath = path.resolve(root, f.file);
      const targetPath = path.resolve(root, filePath);
      return fPath === targetPath;
    });

    let resolvedCount = 0;
    const survivors = [];
    for (const orig of originalFindings) {
      const stillThere = remaining.some(f =>
        f.rule === orig.rule &&
        Math.abs((f.line ?? 0) - (orig.line ?? 0)) <= 2,
      );
      if (!stillThere) resolvedCount++;
      else survivors.push(orig.rule);
    }

    const allResolved = resolvedCount === originalFindings.length;
    return {
      allResolved,
      someResolved: resolvedCount > 0,
      resolvedCount,
      verification: allResolved ? 'passed' : (resolvedCount > 0 ? 'partial' : 'failed'),
      failedTier: allResolved ? null : 'rescan',
      evidence: allResolved ? '' : `Re-scan still reports: ${survivors.join(', ')}`,
      tiers,
    };
  } catch (err) {
    return {
      allResolved: false, someResolved: false, resolvedCount: 0,
      verification: 'failed', failedTier: 'verify-error',
      evidence: err.message || 'verification crashed',
      tiers,
    };
  }
}

// =============================================================================
// LOGGING
// =============================================================================

function logFix(root, entry) {
  const dir  = path.join(root, FIX_LOG_DIR);
  const file = path.join(dir, FIX_LOG_FILE);
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(file, JSON.stringify(entry) + '\n', 'utf8');
}

// Append a structured record for every plan that didn't produce an apply.
// Useful for debugging regressions (the LLM said X, we rejected because Y).
function logFailure(root, entry) {
  const dir  = path.join(root, FIX_LOG_DIR);
  const file = path.join(dir, 'failures.jsonl');
  fs.mkdirSync(dir, { recursive: true });
  // Truncate raw response to keep the log readable
  const truncated = { ...entry };
  if (typeof truncated.raw === 'string' && truncated.raw.length > 4000) {
    truncated.raw = truncated.raw.slice(0, 4000) + '... [truncated]';
  }
  fs.appendFileSync(file, JSON.stringify(truncated) + '\n', 'utf8');
}

// Turn a structured plan failure into a user-facing one-liner.
function describePlanFailure(failure) {
  switch (failure.reason) {
    case 'file-read-failed':
      return { message: `Could not read source file: ${failure.error}`, reason: 'file-read-failed' };
    case 'provider-error':
      return { message: `LLM provider error — ${failure.error}`, reason: 'provider-error' };
    case 'empty-response':
      return { message: 'LLM returned an empty response (try again, or switch provider).', reason: 'empty-response' };
    case 'parse-error':
      return { message: 'LLM returned unparseable JSON — saved to .praxis/failures.jsonl for inspection.', reason: 'parse-error' };
    case 'llm-declined': {
      const summary = failure.plan?.summary;
      return { message: summary
        ? `LLM declined to fix this file — ${summary}`
        : 'LLM declined to fix this file (returned files=[] — needs manual review).',
        reason: 'llm-declined',
      };
    }
    default:
      return { message: `Plan failed: ${failure.reason}`, reason: failure.reason };
  }
}

// =============================================================================
// PR AUTOPILOT
// =============================================================================

async function openPullRequest(root, branch, applied) {
  const ghAvailable = (() => {
    try { execFileSync('gh', ['--version'], { stdio: 'pipe' }); return true; }
    catch { return false; }
  })();
  if (!ghAvailable) {
    console.log(chalk.yellow('  gh CLI not found. Install from https://cli.github.com to enable --pr.'));
    return;
  }

  // Push branch
  console.log(chalk.gray('  Pushing branch...'));
  try {
    execFileSync('git', ['push', '-u', 'origin', branch], { cwd: root, stdio: 'pipe' });
  } catch (err) {
    console.log(chalk.red(`  Push failed: ${err.message}`));
    return;
  }

  // Build PR body
  const totalFindings = applied.reduce((n, a) => n + (a.plan.files?.[0]?.edits?.length ?? 0), 0);
  const body = [
    '## Praxis — Security Fixes',
    '',
    `Applied ${applied.length} file(s) of fixes (${totalFindings} edit(s)) generated and verified by the Praxis agent.`,
    '',
    '### Files changed',
    ...applied.map(a => {
      const mark = a.verified.allResolved ? '✓' : '⚠';
      return `- ${mark} \`${a.file}\` — ${a.plan.summary || 'security fix'}`;
    }),
    '',
    '### Notes',
    '- Each fix was generated by an LLM and verified by re-scanning the file.',
    '- Files marked ⚠ have residual findings; review carefully before merging.',
    '- Full audit log: `.praxis/fixes.jsonl`',
    '',
    'Generated by `praxis agent`.',
  ].join('\n');

  const title = `Security fixes: ${applied.length} file(s)`;

  console.log(chalk.gray('  Opening PR...'));
  let prUrl = null;
  try {
    prUrl = execFileSync('gh', ['pr', 'create', '--title', title, '--body', body], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
    console.log(chalk.green(`  PR opened: ${prUrl}`));
  } catch (err) {
    console.log(chalk.red(`  PR creation failed: ${err.message}`));
    return;
  }

  // If we're running inside CI on a PR, leave a comment on the originating PR
  // pointing at our fix PR. Detect from common GitHub Actions env vars.
  const originPr = detectOriginPrNumber();
  if (originPr) {
    const note = [
      `### 🛡️ Praxis Agent — fix PR opened`,
      ``,
      `The Praxis agent found fixable security issues triggered by this PR and opened **${prUrl}** with proposed fixes.`,
      ``,
      `**Files changed:** ${applied.length}`,
      `**Total edits:** ${totalFindings}`,
      ``,
      `Review the fix PR and merge if it looks good.`,
    ].join('\n');
    try {
      execFileSync('gh', ['pr', 'comment', String(originPr), '--body', note], { cwd: root, stdio: 'pipe' });
      console.log(chalk.green(`  Commented on origin PR #${originPr}`));
    } catch (err) {
      console.log(chalk.yellow(`  Could not comment on origin PR #${originPr}: ${err.message}`));
    }
  }
}

// Detect the PR number that triggered this CI run. Supports GitHub Actions'
// pull_request and pull_request_target events. Returns null when not in CI
// or when the event isn't a PR event.
function detectOriginPrNumber() {
  // Explicit override (handy for testing or non-GHA CI providers)
  if (process.env.PRAXIS_ORIGIN_PR) return process.env.PRAXIS_ORIGIN_PR;

  // GitHub Actions: GITHUB_REF looks like "refs/pull/<n>/merge" or "refs/pull/<n>/head"
  const ref = process.env.GITHUB_REF || '';
  const m = ref.match(/^refs\/pull\/(\d+)\//);
  if (m) return m[1];

  // GitHub Actions PR event payload also exposes the number via GITHUB_EVENT_PATH
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath && fs.existsSync(eventPath)) {
    try {
      const payload = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
      if (payload?.pull_request?.number) return String(payload.pull_request.number);
      if (payload?.number) return String(payload.number);
    } catch { /* malformed event payload */ }
  }

  return null;
}

// =============================================================================
// GIT
// =============================================================================

function checkGitState(root) {
  try {
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: root, stdio: 'pipe' });
  } catch {
    return 'not-a-repo';
  }
  try {
    const out = execFileSync('git', ['status', '--porcelain'], { cwd: root, stdio: 'pipe' }).toString();
    const meaningful = out.split('\n').filter(line => {
      const path = line.slice(3).trim();
      if (!path) return false;
      if (path.startsWith('.praxis/')) return false;
      if (path === 'praxis-report.html') return false;
      return true;
    });
    return meaningful.length === 0 ? 'clean' : 'dirty';
  } catch {
    return 'clean';
  }
}

function getCurrentBranch(root) {
  try {
    return execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: root, stdio: 'pipe' }).toString().trim();
  } catch {
    return null;
  }
}

// =============================================================================
// PROMPTS
// =============================================================================

function prompt(question) {
  return new Promise(resolve => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, answer => { rl.close(); resolve(answer); });
  });
}

async function confirm(question) {
  const a = (await prompt(`${question} [y/N] `)).trim().toLowerCase();
  return a === 'y' || a === 'yes';
}

// Plan decision prompt with [e]dit support: opens the plan in $EDITOR for the
// user to tweak, then re-validates. Loops until accept/skip/quit.
async function promptDecision(plan, root) {
  while (true) {
    const raw = (await prompt(chalk.cyan('      [a]ccept  [s]kip  [e]dit  [q]uit > '))).trim().toLowerCase();
    if (['a', 'accept', 'y', 'yes'].includes(raw)) return 'a';
    if (['s', 'skip', 'n', 'no'].includes(raw))    return 's';
    if (['q', 'quit'].includes(raw))               return 'q';
    if (['e', 'edit'].includes(raw)) {
      const edited = await editPlanInEditor(plan, root);
      if (!edited) {
        console.log(chalk.yellow('      Edit cancelled — keeping original plan.'));
      } else {
        const validation = validatePlan(root, edited);
        if (!validation.ok) {
          console.log(chalk.red(`      Edited plan invalid: ${validation.reason}`));
          console.log(chalk.gray('      Returning to prompt — try editing again, or skip.'));
          continue;
        }
        // Replace the plan only after validation; an invalid edit cannot be accepted.
        plan.summary = edited.summary;
        plan.files   = edited.files;
        plan.risk    = edited.risk;
        printPlan(plan, root);
      }
      // Loop back and re-prompt
      continue;
    }
    console.log(chalk.gray('      Unknown choice. Type a, s, e, or q.'));
  }
}

async function editPlanInEditor(plan, root) {
  const editor = process.env.EDITOR || process.env.VISUAL || 'vi';
  const tmpFile = path.join(root, '.praxis', `plan-edit-${Date.now()}.json`);
  fs.mkdirSync(path.dirname(tmpFile), { recursive: true });
  // Strip _resolvedFind annotations before showing — they're internal
  const exportable = JSON.parse(JSON.stringify(plan, (k, v) => k === '_resolvedFind' ? undefined : v));
  fs.writeFileSync(tmpFile, JSON.stringify(exportable, null, 2), 'utf8');

  try {
    execFileSync(editor, [tmpFile], { stdio: 'inherit' });
    const updated = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
    fs.unlinkSync(tmpFile);
    return updated;
  } catch (err) {
    try { fs.unlinkSync(tmpFile); } catch { /* best effort */ }
    console.log(chalk.red(`      Editor failed: ${err.message}`));
    return null;
  }
}
