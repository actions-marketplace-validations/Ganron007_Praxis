/**
 * GitHistoryScanner Agent
 * ========================
 *
 * Scans git commit history for secrets that were committed
 * and later removed but remain in repository history.
 * These are the most dangerous secrets — developers think
 * they're deleted but they're still accessible.
 */

import { execSync, execFileSync } from 'child_process';
import path from 'path';
import { createHash } from 'crypto';
import { BaseAgent, createFinding } from './base-agent.js';
import { SECRET_PATTERNS } from '../utils/patterns.js';
import { isDocumentedSecretExample } from '../utils/entropy.js';

// Compile a fast combined regex from all secret patterns
const FAST_SECRET_PATTERNS = SECRET_PATTERNS.map(p => ({
  name: p.name,
  pattern: p.pattern,
  severity: p.severity,
}));

export class GitHistoryScanner extends BaseAgent {
  constructor() {
    super('GitHistoryScanner', 'Scan git history for leaked secrets', 'history');
  }

  async analyze(context) {
    const { rootPath, options } = context;
    const findings = [];
    const seen = new Set();

    // Check if this is a git repository
    if (!this.isGitRepo(rootPath)) return [];

    try {
      // Get recent commits (default: last 50, configurable)
      const maxCommits = options?.maxCommits || 50;
      const since = options?.since || null;

      const gitArgs = ['-C', rootPath, 'log', '--all', '--diff-filter=A', '--diff-filter=M', '-p', '--no-color', `--max-count=${parseInt(maxCommits, 10)}`];
      if (since) {
        gitArgs.push(`--since=${since}`);
      }

      let diffOutput;
      try {
        diffOutput = execFileSync('git', gitArgs, {
          cwd: rootPath,
          encoding: 'utf-8',
          maxBuffer: 50 * 1024 * 1024, // 50MB buffer
          timeout: 60000, // 60s timeout
        });
      } catch (err) {
        throw new Error(`Git history scan failed: ${err.message}`);
      }

      if (!diffOutput) return [];

      // Parse the diff output
      let currentFile = '';
      let currentCommit = '';
      let currentDate = '';
      const lines = diffOutput.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Track current commit
        if (line.startsWith('commit ')) {
          currentCommit = line.slice(7, 17); // First 10 chars of hash
        }
        if (line.startsWith('Date:')) {
          currentDate = line.slice(5).trim();
        }

        // Track current file
        if (line.startsWith('diff --git ')) {
          const match = line.match(/diff --git a\/(.+) b\//);
          if (match) currentFile = match[1];
        }

        // Only check added lines (lines starting with +)
        if (!line.startsWith('+') || line.startsWith('+++')) continue;

        const addedLine = line.slice(1); // Remove the leading +

        // Check against all secret patterns
        for (const p of FAST_SECRET_PATTERNS) {
          p.pattern.lastIndex = 0;
          let match;
          while ((match = p.pattern.exec(addedLine)) !== null) {
            if (isDocumentedSecretExample(p.name, match[0])) continue;
            const key = `${p.name}:${createHash('sha256').update(match[0]).digest('hex')}`;
            if (seen.has(key)) continue;
            seen.add(key);
            // Check if this secret still exists in current working tree
            const stillExists = this.existsInWorkingTree(rootPath, match[0]);

            findings.push(createFinding({
              file: path.join(rootPath, currentFile),
              line: 0, // Line number not meaningful in history
              severity: stillExists ? p.severity : this.elevateSeverity(p.severity),
              category: 'history',
              rule: 'GIT_HISTORY_SECRET',
              title: `Historical Secret: ${p.name}`, // praxis-ignore AGENT_LOG_SECRET_KV — title template of a finding this scanner emits, not an agent definition
              description: stillExists
                ? `Secret found in current code AND in git history (commit ${currentCommit}).`
                : `Secret was removed from code but still exists in git history (commit ${currentCommit}, ${currentDate}). Anyone with repo access can retrieve it.`,
              matched: this.maskSecret(match[0]),
              confidence: 'high',
              fix: stillExists
                ? 'Remove from code, rotate the credential, then clean git history with BFG or git filter-repo'
                : 'Rotate this credential immediately, then clean history: npx bfg --replace-text passwords.txt',
            }));
          }
        }
      }

      return findings;

    } catch (err) {
      // Let the orchestrator mark this scanner incomplete instead of clean.
      throw new Error(`GitHistoryScanner incomplete: ${err.message}`, { cause: err });
    }
  }

  isGitRepo(dir) {
    try {
      execSync('git rev-parse --is-inside-work-tree', { cwd: dir, stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  existsInWorkingTree(rootPath, secret) {
    try {
      const result = execFileSync('git', [
        '-C', rootPath, 'grep', '-F', '-l', secret
      ], {
        cwd: rootPath,
        encoding: 'utf-8',
        timeout: 5000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return result.trim().length > 0;
    } catch {
      return false;
    }
  }

  elevateSeverity(sev) {
    // Secrets in history-only are MORE dangerous (developer thinks they're gone)
    if (sev === 'medium') return 'high';
    if (sev === 'high') return 'critical';
    return sev;
  }

  maskSecret(secret) {
    if (secret.length <= 10) return secret.slice(0, 4) + '***';
    return secret.slice(0, 8) + '***' + secret.slice(-4);
  }
}

export default GitHistoryScanner;
