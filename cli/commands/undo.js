/**
 * Undo Command
 * ============
 *
 * Reverts changes applied by `praxis fix interactive`.
 *
 * Reads .praxis/fixes.jsonl, takes the most recent entry (or all entries
 * with --all), and reverses the recorded edits without changing unrelated files
 * or the Git index. Failed reversals retain their log entry for a later retry.
 *
 * USAGE:
 *   praxis undo                Revert the last applied fix
 *   praxis undo --all          Revert every fix in the log
 *   praxis undo --dry-run      Show what would be reverted, but don't write
 */

import fs from 'fs';
import path from 'path';
import writeFileAtomic from 'write-file-atomic';
import { reversePlan } from '../core/fix-plan.js';
import chalk from 'chalk';
import * as output from '../utils/output.js';

const FIX_LOG_PATH = '.praxis/fixes.jsonl';

export async function undoCommand(targetPath = '.', options = {}) {
  const root    = path.resolve(targetPath);
  const logPath = path.join(root, FIX_LOG_PATH);

  if (!fs.existsSync(logPath)) {
    output.error(`No fix log found at ${FIX_LOG_PATH}`);
    console.log(chalk.gray('  Run `praxis fix interactive` first to apply fixes.'));
    process.exit(1);
  }

  let entries;
  try {
    entries = fs.readFileSync(logPath, 'utf8').split('\n').filter(line => line.trim()).map(line => JSON.parse(line));
    if (entries.some(entry => !entry || typeof entry !== 'object' || Array.isArray(entry))) throw new Error('invalid entry');
  } catch {
    output.error('Fix log is malformed; repair it before undoing. No files were changed.');
    process.exitCode = 1;
    return;
  }

  if (entries.length === 0) {
    output.error('Fix log is empty.');
    process.exit(1);
  }

  const toUndo = options.all ? [...entries].reverse() : [entries[entries.length - 1]];

  console.log();
  output.header('Praxis — Undo');
  console.log();
  console.log(chalk.gray(`  Reverting ${toUndo.length} fix(es) from ${FIX_LOG_PATH}`));
  console.log();

  let reverted = 0;
  let failed   = 0;
  const undone = new Set();

  for (const entry of toUndo) {
    const file = entry.file || entry.finding?.file || '(unknown)';
    console.log(chalk.bold(`  ${chalk.cyan(file)}`));

    if (options.dryRun) {
      console.log(chalk.gray(`    Would reverse plan: ${entry.plan?.summary || 'no summary'}`));
      reverted++;
      continue;
    }

    try {
      reversePlan(root, entry.plan);
      console.log(chalk.green('    Reverted.'));
      reverted++;
      undone.add(entry);
    } catch (err) {
      console.log(chalk.red(`    Failed: ${err.message}`));
      failed++;
      // Older fixes may depend on this one. Stop so the log remains a valid stack.
      break;
    }
  }

  // Truncate the log
  if (!options.dryRun && reverted > 0) {
    const remaining = entries.filter(entry => !undone.has(entry));
    if (remaining.length === 0) {
      fs.unlinkSync(logPath);
    } else {
      writeFileAtomic.sync(logPath, remaining.map(e => JSON.stringify(e)).join('\n') + '\n', { encoding: 'utf8' });
    }
  }

  console.log();
  console.log(chalk.green(`  Reverted: ${reverted}`));
  if (failed > 0) console.log(chalk.red(`  Failed:   ${failed}`));
  console.log();

  if (failed > 0) {
    process.exitCode = 1;
    console.log(chalk.gray('  Failed and unattempted fixes remain in the log. Review the changed files before retrying.'));
    console.log();
  }
}
