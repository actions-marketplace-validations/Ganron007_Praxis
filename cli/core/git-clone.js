/**
 * Remote Git Repository Scanner Helper
 * =====================================
 *
 * Enables direct scanning of remote Git repositories (GitHub, GitLab, Bitbucket,
 * Azure DevOps, self-hosted Git, SSH repos).
 *
 * Features:
 *   - Automatic Git URL recognition (HTTPS, HTTP, SSH, git://, shorthand)
 *   - Shallow cloning (--depth 1 by default for fast SAST scans)
 *   - Branch/tag selection (--branch / -b)
 *   - Private repository auth (token injection via PRAXIS_GIT_TOKEN, GITHUB_TOKEN, or --git-token)
 *   - Complete token redaction: raw tokens never leak into console, logs, or reports
 *   - Git commit history secret scanning (--git-history)
 *   - Secure temporary workspace creation and guaranteed cleanup (try/finally)
 */

import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

// Regex matching remote Git URLs
const GIT_URL_PATTERN = /^(?:git@[a-zA-Z0-9_.-]+:|https?:\/\/|git:\/\/|ssh:\/\/|gh:|github:|gitlab:)[^\s]+$/i;

/**
 * Check if a target string is a remote Git URL.
 *
 * @param {string} target
 * @returns {boolean}
 */
export function isGitUrl(target = '') {
  if (!target || typeof target !== 'string') return false;
  const trimmed = target.trim();

  // If it's an existing file or directory on local disk, it's local
  if (fs.existsSync(trimmed)) return false;

  if (GIT_URL_PATTERN.test(trimmed)) return true;

  // Recognise host.com/owner/repo or host.com/owner/repo.git
  if (/^(?:github\.com|gitlab\.com|bitbucket\.org)\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(?:\.git)?$/i.test(trimmed)) {
    return true;
  }

  return false;
}

/**
 * Redact sensitive authentication credentials from a Git URL.
 *
 * @param {string} url
 * @returns {string}
 */
export function redactGitUrl(url = '') {
  if (!url || typeof url !== 'string') return '';
  return url.replace(/(https?:\/\/)([^:@\s]+)(?::([^@\s]+))?@/gi, '$1***@');
}

/**
 * Parse a Git URL into its constituent parts and normalize it for cloning.
 *
 * @param {string} target
 * @param {object} options
 * @returns {{ cloneUrl: string, displayUrl: string, repoName: string, provider: string }}
 */
export function parseGitUrl(target = '', options = {}) {
  let raw = target.trim();

  // Shorthand expansions
  if (raw.startsWith('gh:') || raw.startsWith('github:')) {
    const slug = raw.replace(/^(?:gh|github):/, '');
    raw = `https://github.com/${slug}`;
  } else if (raw.startsWith('gitlab:')) {
    const slug = raw.replace(/^gitlab:/, '');
    raw = `https://gitlab.com/${slug}`;
  } else if (/^(?:github\.com|gitlab\.com|bitbucket\.org)\//i.test(raw)) {
    raw = `https://${raw}`;
  }

  let hostname = raw.match(/^git@([^:]+):/)?.[1]?.toLowerCase() || '';
  try { hostname = new URL(raw).hostname.toLowerCase(); } catch { /* local clone path or SCP syntax */ }
  const provider = {
    'github.com': 'github', 'gitlab.com': 'gitlab', 'bitbucket.org': 'bitbucket', 'dev.azure.com': 'azure',
  }[hostname] || 'git';

  // Extract clean repository name
  let repoName = 'repository';
  const nameMatch = raw.match(/\/([a-zA-Z0-9_.-]+?)(?:\.git)?(?:\/)?$/);
  if (nameMatch && nameMatch[1]) {
    repoName = nameMatch[1];
  }

  const displayUrl = redactGitUrl(raw);

  // Auth token injection for private repositories (if requested)
  // A GitHub credential must never be forwarded to another Git host or a lookalike.
  const token = options.gitToken || process.env.PRAXIS_GIT_TOKEN || process.env.GIT_TOKEN ||
    (hostname === 'github.com' ? process.env.GITHUB_TOKEN : undefined);
  let cloneUrl = raw;

  if (token && raw.startsWith('https://')) {
    const urlObj = new URL(raw);
    urlObj.username = 'x-access-token';
    urlObj.password = token;
    cloneUrl = urlObj.toString();
  }

  return { cloneUrl, displayUrl, repoName, provider };
}

/**
 * Verify git CLI availability.
 *
 * @returns {boolean}
 */
export function checkGitInstalled() {
  try {
    execFileSync('git', ['--version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Clone a remote Git repository into a secure temporary directory.
 *
 * @param {string} gitTarget - Remote repository URL or shorthand
 * @param {object} options
 * @param {string} [options.branch] - Specific branch or tag
 * @param {number} [options.depth=1] - Shallow clone depth (0 for full history)
 * @param {string} [options.gitToken] - Auth token
 * @param {boolean} [options.submodules=false] - Clone submodules
 * @param {number} [options.timeout=120000] - Clone timeout in ms
 * @returns {{ tempDir: string, repoName: string, displayUrl: string, branch?: string, cleanup: () => void }}
 */
export function cloneGitRepo(gitTarget, options = {}) {
  if (!checkGitInstalled()) {
    throw new Error('git CLI is required to scan remote repositories. Please install git and ensure it is on PATH.');
  }

  const { cloneUrl, displayUrl, repoName } = parseGitUrl(gitTarget, options);

  // Create isolated temp workspace
  const randSuffix = crypto.randomBytes(6).toString('hex');
  const tempDir = path.join(os.tmpdir(), `praxis-repo-${repoName}-${randSuffix}`);
  fs.mkdirSync(tempDir, { recursive: true });

  const depth = options.depth !== undefined ? parseInt(options.depth, 10) : (options.gitHistory ? 50 : 1);
  const args = ['clone'];

  if (depth > 0 && !options.fullHistory) {
    args.push('--depth', String(depth));
  }

  if (options.branch) {
    args.push('--branch', String(options.branch), '--single-branch');
  }

  if (options.submodules) {
    args.push('--recurse-submodules');
  }

  args.push(cloneUrl, tempDir);

  const cleanup = () => {
    try {
      if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    } catch {
      // Best-effort cleanup
    }
  };

  try {
    execFileSync('git', args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: options.timeout || 120000,
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: '0', // Do not hang on interactive credentials
      },
    });

    return {
      tempDir,
      repoName,
      displayUrl,
      branch: options.branch,
      cleanup,
    };
  } catch (err) {
    cleanup();
    // Redact any tokens from error output before rethrowing
    const rawMsg = err.stderr ? err.stderr.toString('utf8') : err.message;
    const sanitizedMsg = redactGitUrl(rawMsg);
    throw new Error(`Failed to clone git repository (${displayUrl}): ${sanitizedMsg}`);
  }
}
