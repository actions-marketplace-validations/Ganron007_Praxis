/**
 * `praxis rules` — inspect and export Praxis's detection rules.
 *
 * Two subcommands:
 *   list    summarise the rule inventory by source, severity and portability
 *   export  write a Semgrep-compatible bundle plus an honest manifest
 *
 * The manifest is the important half. A bundle without it would imply Praxis is
 * nothing but its patterns; the manifest names the layers that have no Semgrep
 * equivalent (AST/taint, the probe corpus, entropy heuristics). See
 * docs/USAGE.md.
 */

import path from 'path';
import chalk from 'chalk';
import { collectPortableRules, dedupeRules, writeBundle, SEMGREP_SEVERITY } from '../utils/rule-registry.js';
import { loadPortableBundle, writePlugin } from '../utils/rule-import.js';
import { toolVersion } from '../core/version.js';
import * as output from '../utils/output.js';

async function gather() {
  const collected = await collectPortableRules();
  const { rules, collisions } = dedupeRules(collected.rules);
  return { ...collected, rules, collisions };
}

export async function rulesListCommand(options = {}) {
  const { rules, errors, skipped, collisions } = await gather();

  const bySeverity = {};
  for (const r of rules) bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1;

  const byOrigin = {};
  for (const r of rules) {
    const src = r.origin.split(':')[0];
    byOrigin[src] = (byOrigin[src] || 0) + 1;
  }

  if (options.json) {
    console.log(JSON.stringify({
      total: rules.length,
      bySeverity,
      bySource: byOrigin,
      portable: rules.filter(r => r.valid).length,
      invalid: rules.filter(r => !r.valid).length,
      collisions,
      skipped,
      moduleErrors: errors,
    }, null, 2));
    return;
  }

  output.header('Praxis rule inventory');
  console.log();
  console.log(`  ${chalk.green(String(rules.length))} exportable pattern rules`);
  console.log(`  ${chalk.gray(`${rules.filter(r => r.valid).length} validated · ${rules.filter(r => !r.valid).length} invalid · ${collisions.length} id collision(s)`)}`);
  console.log();

  console.log(chalk.gray('  By severity:'));
  for (const [sev, n] of Object.entries(bySeverity).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${String(n).padStart(4)}  ${sev.padEnd(9)} semgrep: ${SEMGREP_SEVERITY[sev] || 'WARNING'}`);
  }
  console.log();

  console.log(chalk.gray('  By source (top 12):'));
  for (const [src, n] of Object.entries(byOrigin).sort((a, b) => b[1] - a[1]).slice(0, 12)) {
    console.log(`    ${String(n).padStart(4)}  ${src}`);
  }

  if (errors.length) {
    console.log();
    console.log(chalk.yellow(`  ${errors.length} module(s) could not be loaded:`));
    for (const e of errors) console.log(`    ${e.module}: ${e.error}`);
  }
  if (skipped.length) {
    console.log();
    console.log(chalk.gray(`  ${skipped.length} record(s) had no regex and were skipped.`));
  }

  console.log();
  console.log(chalk.gray('  Praxis-only layers (no Semgrep equivalent): AST/taint dataflow,'));
  console.log(chalk.gray('  the prompt-injection probe corpus, entropy-checked secrets, LLM deep analysis.'));
  console.log(chalk.gray('  Run `praxis rules export` for the full manifest.'));
}

export async function rulesExportCommand(options = {}) {
  const outDir = path.resolve(options.out || 'praxis-rules');
  const { rules, collisions, errors, skipped } = await gather();

  if (rules.length === 0) {
    output.error('No exportable rules found — refusing to write an empty bundle.');
    process.exitCode = 1;
    return;
  }

  const invalid = rules.filter(r => r.validationStatus === 'invalid');
  const unverifiable = rules.filter(r => r.validationStatus === 'unverifiable');

  // Refuse to ship a bundle containing patterns that do not compile. A partially
  // broken bundle would fail inside someone else's Semgrep with no useful context.
  if (invalid.length > 0 && !options.allowInvalid) {
    output.error(`${invalid.length} pattern(s) failed validation — refusing to write a broken bundle.`);
    for (const r of invalid.slice(0, 5)) console.log(`  ${r.id}: ${r.validationError}`);
    console.log(chalk.gray('  Fix them, or re-run with --allow-invalid to export anyway.'));
    process.exitCode = 1;
    return;
  }

  const { yamlPath, jsonPath, manifestPath } = writeBundle({
    rules,
    collisions,
    errors,
    skipped,
    outDir,
    toolVersion: toolVersion(),
  });

  output.success(`Exported ${rules.length - invalid.length} portable rule(s)`);
  console.log(`  ${yamlPath}   (Semgrep)`);
  console.log(`  ${jsonPath}   (canonical, re-importable)`);
  console.log(`  ${manifestPath}`);
  if (unverifiable.length) {
    console.log(chalk.yellow(`  (${unverifiable.length} pattern(s) could not be machine-checked — valid PCRE2 with no JS equivalent; listed in the manifest)`));
  }
  if (invalid.length) console.log(chalk.yellow(`  (${invalid.length} invalid pattern(s) included via --allow-invalid)`));
  if (collisions.length) console.log(chalk.yellow(`  (${collisions.length} duplicate rule id(s) suffixed; see the manifest)`));
  if (errors.length) console.log(chalk.yellow(`  (${errors.length} module(s) failed to load; see the manifest)`));
  console.log();
  console.log(chalk.gray('  Use with Semgrep:  semgrep --config ' + yamlPath + ' <target>'));
  console.log(chalk.gray('  Re-import with Praxis:  praxis rules import ' + jsonPath));
  console.log(chalk.gray('  praxis-rules.manifest.json lists what Praxis does that Semgrep cannot.'));
}

export async function rulesImportCommand(bundleFile, options = {}) {
  const loaded = loadPortableBundle(bundleFile);

  if (!loaded.ok) {
    output.error(loaded.error);
    process.exitCode = 1;
    return;
  }

  const { accepted, rejected, meta } = loaded;

  if (options.json) {
    console.log(JSON.stringify({
      source: meta.source,
      total: meta.total,
      accepted: accepted.length,
      rejected: rejected.length,
      rejections: rejected,
      praxisOnlyLayers: meta.praxisOnlyLayers,
    }, null, 2));
    return;
  }

  output.header('Portable rule import');
  console.log();
  console.log(`  bundle:  ${meta.source}`);
  if (meta.praxisVersion) console.log(chalk.gray(`  produced by Praxis ${meta.praxisVersion}`));
  console.log();
  console.log(`  ${chalk.green(String(accepted.length))} accepted · ${chalk.yellow(String(rejected.length))} rejected`);
  console.log();

  if (rejected.length) {
    console.log(chalk.gray('  Rejected (with reasons — nothing is imported in degraded form):'));
    const byReason = {};
    for (const r of rejected) byReason[r.reason] = (byReason[r.reason] || 0) + 1;
    for (const [reason, n] of Object.entries(byReason).sort((a, b) => b[1] - a[1])) {
      console.log(`    ${String(n).padStart(4)}  ${reason}`);
    }
    console.log();
  }

  if (meta.praxisOnlyLayers?.length) {
    console.log(chalk.gray('  Declared Praxis-only layers in this bundle (cannot be imported as patterns):'));
    for (const l of meta.praxisOnlyLayers) console.log(`    - ${l.layer}: ${l.reason}`);
    console.log();
  }

  if (accepted.length === 0) {
    output.error('No importable pattern rules in this bundle.');
    process.exitCode = 1;
    return;
  }

  if (options.writePlugin) {
    const dir = path.resolve(options.writePlugin);
    const file = writePlugin(accepted, dir, { name: options.name || 'PortableRules' });
    output.success(`Wrote ${accepted.length} rule(s) to ${file}`);
    console.log(chalk.gray('  It runs automatically in every `praxis audit` from this directory down.'));
  } else {
    console.log(chalk.gray('  Preview only. Re-run with --write-plugin <dir> to emit a runnable plugin.'));
    console.log(chalk.gray(`  e.g. --write-plugin ${path.join('.praxis', 'agents')}`));
  }
}