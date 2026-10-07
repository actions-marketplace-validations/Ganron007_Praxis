/**
 * Scan Standard Command
 * =====================
 *
 * Runs a normal scan and filters the result to findings tagged with a
 * specific AI-security standard (OWASP LLM, MITRE ATLAS, NIST AI 600-1, etc.).
 *
 * USAGE:
 *   praxis scan standard --list                  # list available standards
 *   praxis scan standard owasp-llm .             # findings tagged with the OWASP LLM Top 10
 *   praxis scan standard mitre-atlas . --json    # ATLAS findings as JSON
 *   praxis scan standard owasp-llm . --control LLM01   # filter to a single control
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { displayPath } from '../core/paths.js';
import { buildOrchestratorAsync } from '../agents/index.js';
import { ScoringEngine } from '../agents/scoring-engine.js';
import {
  ALL_STANDARDS,
  listStandards,
  getStandard,
  filterFindingsByStandard,
} from '../utils/standards/index.js';
import { render, hasFormat } from '../core/output/index.js';

const SEV_COLORS = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
};

export async function scanStandardCommand(name, targetPath = '.', options = {}) {
  if (options.list || name === 'list') {
    return printStandardsList(options);
  }

  if (!name) {
    console.error(chalk.red('  Missing standard name.'));
    console.error(chalk.gray('  Usage: praxis scan standard <name> [path]'));
    console.error(chalk.gray('         praxis scan standard --list'));
    process.exit(1);
  }

  const standard = getStandard(name);
  if (!standard) {
    console.error(chalk.red(`  Unknown standard: ${name}`));
    console.error(chalk.gray('  Available:'));
    for (const s of listStandards()) {
      console.error(chalk.gray(`    ${s.name.padEnd(16)} ${s.title}`));
    }
    process.exit(1);
  }

  const absolutePath = path.resolve(targetPath);
  if (!fs.existsSync(absolutePath)) {
    console.error(chalk.red(`  Path does not exist: ${absolutePath}`));
    process.exit(1);
  }

  const machine = !!(options.json || options.sarif);

  if (!machine) {
    console.log();
    console.log(chalk.cyan.bold(`  Praxis — ${standard.title} (${standard.version})`));
    console.log(chalk.gray(`  ${standard.description}`));
    console.log(chalk.gray(`  ${standard.url}`));
    console.log();
  }

  const spinner = machine ? null : ora({ text: 'Running agents...', color: 'cyan' }).start();
  const orchestrator = await buildOrchestratorAsync(absolutePath, { quiet: true });
  const result = await orchestrator.runAll(absolutePath, { quiet: true });
  if (spinner) spinner.succeed(chalk.green(`Scanned ${result.findings.length} finding(s) total`));

  const scoring = new ScoringEngine();
  const scoreResult = scoring.compute(result.findings);

  const filtered = filterFindingsByStandard(
    result.findings,
    standard.name,
    options.control || null
  );

  const standardSummary = buildStandardSummary(standard, filtered, options.control);

  const report = {
    standard: {
      name: standard.name,
      version: standard.version,
      title: standard.title,
      url: standard.url,
    },
    control: options.control || null,
    totalFindings: filtered.length,
    coverage: standardSummary.coverage,
    flaggedControls: standardSummary.flaggedControls,
    totalControls: standardSummary.totalControls,
    controls: standardSummary.controls,
    findings: filtered.map(f => ({
      ...f,
      file: displayPath(f.file, absolutePath),
    })),
    score: scoreResult.score,
    grade: scoreResult.grade?.letter || 'A',
    scannedAt: new Date().toISOString(),
  };

  // ATLAS enrichment: hydrate flagged techniques with mitigations + case studies
  if (standard.name === 'mitre-atlas') {
    try {
      const { getTechniqueDetails, atlasSnapshot } = await import('../utils/standards/sources/mitre-atlas.js');
      report.atlas = {
        snapshot: atlasSnapshot(),
        techniques: Object.fromEntries(
          standardSummary.controls
            .filter(c => c.findingCount > 0)
            .map(c => [c.id, getTechniqueDetails(c.id)])
            .filter(([, d]) => d)
        ),
      };
    } catch { /* enrichment is best-effort */ }
  }

  if (options.json) {
    console.log(render('json', report));
    return;
  }
  if (options.sarif) {
    console.log(render('sarif', report));
    return;
  }
  if (options.format && hasFormat(options.format)) {
    console.log(render(options.format, report));
    return;
  }

  await printHumanReport(standard, report, options);
}

function buildStandardSummary(standard, findings, controlFilter) {
  const counts = {};
  for (const f of findings) {
    const ids = (f.standards || {})[standard.name] || [];
    for (const id of ids) {
      if (controlFilter && id !== controlFilter) continue;
      counts[id] = (counts[id] || 0) + 1;
    }
  }
  const controls = (standard.controls || [])
    .filter(c => !controlFilter || c.id === controlFilter)
    .map(c => ({
      ...c,
      findingCount: counts[c.id] || 0,
      status: counts[c.id] ? 'flagged' : 'clear',
    }));
  const flaggedControls = controls.filter(c => c.findingCount > 0).length;
  return {
    totalControls: controls.length,
    flaggedControls,
    coverage: `${flaggedControls}/${controls.length}`,
    controls,
  };
}

function printStandardsList(options) {
  if (options.json) {
    console.log(JSON.stringify(listStandards(), null, 2));
    return;
  }
  console.log();
  console.log(chalk.cyan.bold('  Available AI-security standards'));
  console.log();
  for (const s of listStandards()) {
    console.log(`  ${chalk.white.bold(s.name.padEnd(16))} ${chalk.gray(`v${s.version}`).padEnd(12)} ${s.title}`);
    console.log(chalk.gray(`    ${s.controlCount} controls — ${s.url}`));
  }
  console.log();
  console.log(chalk.gray(`  Total: ${ALL_STANDARDS.length} standards.`));
  console.log();
}

async function printHumanReport(standard, report) {  console.log(chalk.white.bold(`  Coverage: ${report.coverage}  (${report.totalFindings} finding${report.totalFindings === 1 ? '' : 's'})`));
  console.log();

  for (const ctrl of report.controls) {
    const statusIcon = ctrl.findingCount > 0 ? chalk.red('●') : chalk.green('○');
    const head = ctrl.findingCount > 0
      ? chalk.white.bold(`${ctrl.id} — ${ctrl.title}`) + chalk.yellow(`  (${ctrl.findingCount})`)
      : chalk.gray(`${ctrl.id} — ${ctrl.title}`);
    console.log(`  ${statusIcon} ${head}`);
  }
  console.log();

  // ATLAS enrichment: mitigations + case studies for flagged techniques
  if (standard.name === 'mitre-atlas') {
    try {
      const { getTechniqueDetails, atlasSnapshot } = await import('../utils/standards/sources/mitre-atlas.js');
      const flagged = report.controls.filter(c => c.findingCount > 0);
      if (flagged.length > 0) {
        console.log(chalk.gray(`  ATLAS knowledge snapshot: ${atlasSnapshot()}`));
        console.log(chalk.white.bold('  Recommended mitigations (ATLAS):'));
        console.log();
        const shown = new Set();
        for (const ctrl of flagged) {
          const details = getTechniqueDetails(ctrl.id);
          if (!details) continue;
          for (const m of details.mitigations) {
            if (shown.has(m.id)) continue;
            shown.add(m.id);
            console.log(`    ${chalk.cyan(m.id)}  ${m.name}`);
          }
          if (details.caseStudies.length > 0) {
            console.log(chalk.gray(`      case studies: ${details.caseStudies.map(cs => cs.name).join('; ')}`));
          }
        }
        console.log();
      }
    } catch { /* enrichment is best-effort */ }
  }

  if (report.totalFindings === 0) {
    console.log(chalk.green(`  ✔ No findings tagged with ${standard.title}.`));
    console.log();
    return;
  }

  console.log(chalk.white.bold('  Findings:'));
  console.log();
  for (const f of report.findings.slice(0, 50)) {
    const ids = (f.standards || {})[standard.name] || [];
    const sev = (f.severity || 'medium').toUpperCase();
    const color = SEV_COLORS[f.severity] || chalk.white;
    const tag = ids.join(', ');
    const file = f.file ? displayPath(f.file, process.cwd()) : '';
    const loc = file ? `${file}:${f.line || 0}` : '';
    console.log(`  ${color(`[${sev}]`)} ${chalk.cyan(`[${tag}]`)} ${f.title || f.rule || ''}`);
    if (loc) console.log(chalk.gray(`    ${loc}`));
  }
  if (report.findings.length > 50) {
    console.log(chalk.gray(`  …and ${report.findings.length - 50} more (use --json for the full list).`));
  }
  console.log();
}
