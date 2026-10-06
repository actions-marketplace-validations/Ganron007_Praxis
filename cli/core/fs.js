/**
 * Path & filesystem helpers
 * =========================
 *
 * One implementation of the path-validation logic that was previously
 * duplicated 16+ times across `cli/commands/`. Commands should use these
 * instead of rolling their own `path.resolve + fs.existsSync` checks.
 */

import fs from 'fs';
import path from 'path';
import * as output from '../utils/output.js';

/**
 * Resolve a user-supplied path to an absolute path and verify it exists.
 *
 * Exits the process with code 1 (and prints a friendly error) if the path
 * is missing, unless `{ exitOnMissing: false }` is passed. Returns the
 * absolute path on success.
 */
export function validatePath(targetPath, options = {}) {
  const { exitOnMissing = true, label = 'path' } = options;
  const absolutePath = path.resolve(targetPath || '.');

  if (!fs.existsSync(absolutePath)) {
    if (exitOnMissing) {
      output.error(`${label} does not exist: ${absolutePath}`);
      process.exit(1);
    }
    return null;
  }

  return absolutePath;
}

/**
 * Resolve a path and require that it points at a directory. Same exit
 * semantics as `validatePath`.
 */
export function validateDir(targetPath, options = {}) {
  const absolutePath = validatePath(targetPath, options);
  if (!absolutePath) return null;

  const stat = fs.statSync(absolutePath);
  if (!stat.isDirectory()) {
    if (options.exitOnMissing !== false) {
      output.error(`expected a directory, got a file: ${absolutePath}`);
      process.exit(1);
    }
    return null;
  }
  return absolutePath;
}

/**
 * Synchronously and atomically ensure a directory exists. Mirrors the
 * `mkdir -p` idiom used throughout the codebase.
 */
export function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Resolve a write target inside a project, including existing symlink parents. */
export function resolveProjectFile(root, candidate) {
  if (typeof candidate !== 'string' || !candidate || candidate.includes('\0')) {
    throw new Error('file path must be a non-empty string');
  }
  const project = fs.realpathSync(root);
  const inside = target => {
    const relative = path.relative(project, target);
    return relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
  };
  const absolute = path.resolve(project, candidate);
  if (!inside(absolute)) throw new Error(`path escapes project: ${candidate}`);
  let existing = absolute;
  while (!fs.existsSync(existing)) {
    // A dangling symlink is an existing directory entry and must not be followed.
    try {
      if (fs.lstatSync(existing).isSymbolicLink()) throw new Error(`dangling symlink: ${candidate}`);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    existing = path.dirname(existing);
  }
  const resolved = path.join(fs.realpathSync(existing), path.relative(existing, absolute));
  if (!inside(resolved)) throw new Error(`symlink escapes project: ${candidate}`);
  return resolved;
}
