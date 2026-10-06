import fs from 'fs';
import path from 'path';
import writeFileAtomic from 'write-file-atomic';
import { createHash } from 'crypto';
import { resolveProjectFile } from './fs.js';

const NEVER_EDIT = [
  /(^|\/)\.env(\.|$)/i,
  /\.pem$|\.key$|\.p12$|\.pfx$/i,
  /package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$/i,
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /\.min\.(js|css)$/,
];
// Files the agent IS allowed to create or update freely (companions to fixes)
const SAFE_NEW_FILES = [
  /(^|\/)\.env\.example$/i,
  /(^|\/)\.env\.sample$/i,
  /(^|\/)\.gitignore$/i,
];

export function isProtectedFixPath(relative) {
  const rel = relative.replace(/\\/g, '/');
  return /(^|\/)(\.git|\.praxis|node_modules|dist|build)(\/|$)/i.test(rel) ||
    (!SAFE_NEW_FILES.some(pattern => pattern.test(rel)) && NEVER_EDIT.some(pattern => pattern.test(rel)));
}

export function validatePlan(root, plan) {
  try {
    return validateFiles(root, plan);
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

function validateFiles(root, plan) {
  if (!plan || !Array.isArray(plan.files) || plan.files.length === 0) {
    return { ok: false, reason: 'no files in plan' };
  }

  const paths = new Set();
  for (const f of plan.files) {
    if (!f || typeof f.path !== 'string' || !f.path) return { ok: false, reason: 'file entry missing path' };

    const abs = resolveProjectFile(root, f.path);
    const key = process.platform === 'win32' ? abs.toLowerCase() : abs;
    if (paths.has(key)) return { ok: false, reason: `duplicate file: ${f.path}` };
    paths.add(key);
    const rel       = path.relative(fs.realpathSync(root), abs).replace(/\\/g, '/');
    const isSafeNew = SAFE_NEW_FILES.some(p => p.test(rel));

    // Block protected paths unless this is a known-safe companion file
    if (isProtectedFixPath(rel)) {
      return { ok: false, reason: `protected path: ${f.path}` };
    }

    const exists = fs.existsSync(abs);
    if (exists && !fs.statSync(abs).isFile()) return { ok: false, reason: `not a file: ${f.path}` };

    // Companion file forms (create / append)
    if (f.create || f.append !== undefined) {
      if (!exists && !isSafeNew) {
        return { ok: false, reason: `cannot create new file at ${f.path}` };
      }
      if (f.create && typeof f.content !== 'string') {
        return { ok: false, reason: 'create entry missing content' };
      }
      if (f.create && exists) return { ok: false, reason: `cannot overwrite existing file: ${f.path}` };
      if (f.create && f.append !== undefined) return { ok: false, reason: 'create and append cannot be combined' };
      if (f.append !== undefined && (typeof f.append !== 'string' || !f.append.trim())) {
        return { ok: false, reason: 'append must be a string' };
      }
      continue;
    }

    // Standard edit form
    if (!exists) return { ok: false, reason: `file not found: ${f.path}` };
    if (!Array.isArray(f.edits) || f.edits.length === 0) {
      return { ok: false, reason: `no edits for ${f.path}` };
    }

    let content = fs.readFileSync(abs, 'utf8');
    for (const e of f.edits) {
      if (!e || typeof e.find !== 'string' || !e.find || typeof e.replace !== 'string') {
        return { ok: false, reason: 'edit missing find/replace' };
      }
      if (e.find === e.replace) {
        return { ok: false, reason: 'edit is a no-op' };
      }
      const match = locateFindString(content, e.find);
      if (match.kind === 'missing') {
        return { ok: false, reason: `find string not present in ${f.path}` };
      }
      if (match.kind === 'ambiguous') {
        return { ok: false, reason: `find string is ambiguous (${match.count} matches) in ${f.path}` };
      }
      // Annotate the edit with the resolved match for use during apply
      e._resolvedFind = match.matched;
      content = content.replace(match.matched, () => e.replace);
    }
  }
  return { ok: true };
}

// Try exact match first, then whitespace-normalized match if exact misses.
// Returns { kind: 'unique'|'ambiguous'|'missing', matched, count }
function locateFindString(haystack, needle) {
  const exact = countOccurrences(haystack, needle);
  if (exact === 1) return { kind: 'unique', matched: needle, count: 1 };
  if (exact > 1)   return { kind: 'ambiguous', matched: needle, count: exact };

  // Whitespace-tolerant fallback: collapse whitespace runs and try again
  const norm = (s) => s.replace(/[ \t]+/g, ' ').replace(/\s*\n\s*/g, '\n').trim();
  const needleNorm = norm(needle);
  if (!needleNorm) return { kind: 'missing', matched: null, count: 0 };

  // Walk the haystack and check if any window normalizes to the same string
  // To keep this cheap, only attempt when needle has at least one newline (likely a code block)
  const lines = haystack.split('\n');
  const needleLines = needleNorm.split('\n').length;
  let foundIdx = -1;
  let foundCount = 0;
  for (let i = 0; i + needleLines <= lines.length; i++) {
    const window = lines.slice(i, i + needleLines).join('\n');
    if (norm(window) === needleNorm) {
      foundIdx = i;
      foundCount++;
      if (foundCount > 1) break;
    }
  }
  if (foundCount === 1) {
    const matched = lines.slice(foundIdx, foundIdx + needleLines).join('\n');
    return { kind: 'unique', matched, count: 1 };
  }
  if (foundCount > 1) return { kind: 'ambiguous', matched: null, count: foundCount };
  return { kind: 'missing', matched: null, count: 0 };
}

function countOccurrences(haystack, needle) {
  if (!needle) return 0;
  let count = 0, idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) { count++; idx += needle.length; }
  return count;
}

function applyEdit(root, fileChange) {
  const abs = resolveProjectFile(root, fileChange.path);

  if (fileChange.create) {
    if (fs.existsSync(abs)) throw new Error(`cannot overwrite existing file: ${fileChange.path}`);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    writeFileAtomic.sync(abs, fileChange.content, { encoding: 'utf8' });
    fileChange._afterHash = hashContent(fileChange.content);
    return;
  }

  if (fileChange.append !== undefined) {
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    const existed = fs.existsSync(abs);
    const existing = existed ? fs.readFileSync(abs, 'utf8') : '';
    fileChange._createdByAppend = !existed;
    fileChange._appendApplied = '';
    // Avoid duplicate appends
    if (existing.includes(fileChange.append.trim())) return;
    const sep = existing && !existing.endsWith('\n') ? '\n' : '';
    fileChange._appendApplied = sep + fileChange.append;
    const updated = existing + fileChange._appendApplied;
    writeFileAtomic.sync(abs, updated, { encoding: 'utf8' });
    fileChange._afterHash = hashContent(updated);
    return;
  }

  let content = fs.readFileSync(abs, 'utf8');
  for (const e of fileChange.edits) {
    const find = e._resolvedFind || e.find;
    if (countOccurrences(content, find) !== 1) {
      throw new Error(`find string drifted in ${fileChange.path} (file changed mid-plan)`);
    }
    e._offset = content.indexOf(find);
    content = content.replace(find, () => e.replace);
  }
  writeFileAtomic.sync(abs, content, { encoding: 'utf8' });
  fileChange._afterHash = hashContent(content);
}

const hashContent = content => createHash('sha256').update(content).digest('hex');

export function snapshotPlan(root, plan) {
  return plan.files.map(file => {
    const abs = resolveProjectFile(root, file.path);
    const existed = fs.existsSync(abs);
    return { abs, existed, content: existed ? fs.readFileSync(abs) : null };
  });
}

/** Restore every file or report exactly which restorations failed. */
export function restoreSnapshots(snapshots) {
  const failures = [];
  for (const snapshot of snapshots) {
    try {
      if (snapshot.existed) writeFileAtomic.sync(snapshot.abs, snapshot.content);
      else if (fs.existsSync(snapshot.abs)) fs.unlinkSync(snapshot.abs);
    } catch (err) {
      failures.push(`${snapshot.abs}: ${err.message}`);
    }
  }
  if (failures.length) throw new Error(`restore failed: ${failures.join('; ')}`);
}

/** Validate again after approval, then roll back any partially applied plan. */
export function applyPlan(root, plan) {
  const validation = validatePlan(root, plan);
  if (!validation.ok) throw new Error(validation.reason);
  const snapshots = snapshotPlan(root, plan);
  try {
    for (const file of plan.files) applyEdit(root, file);
    return snapshots;
  } catch (err) {
    try {
      restoreSnapshots(snapshots);
    } catch (restoreError) {
      throw new Error(`${err.message}; ${restoreError.message}`);
    }
    throw err;
  }
}

/** Preflight every reverse edit before touching any file; preserve later user edits. */
export function reversePlan(root, plan) {
  if (!plan || !Array.isArray(plan.files) || !plan.files.length) throw new Error('entry has no plan to reverse');
  const changes = plan.files.map(file => {
    const abs = resolveProjectFile(root, file.path);
    if (isProtectedFixPath(path.relative(fs.realpathSync(root), abs))) throw new Error(`protected path: ${file.path}`);
    const current = fs.readFileSync(abs, 'utf8');
    if (file._afterHash && hashContent(current) !== file._afterHash) {
      throw new Error(`file changed since fix: ${file.path}`);
    }
    if (file.create || file._createdByAppend) {
      const expected = file.create ? file.content : file._appendApplied;
      if (current !== expected) throw new Error(`created file changed since fix: ${file.path}`);
      return { abs, remove: true };
    }
    if (file.append !== undefined) {
      const appended = file._appendApplied ?? file.append;
      if (!appended) return { abs, content: current };
      if (!current.endsWith(appended)) throw new Error(`appended text no longer at end of ${file.path}`);
      return { abs, content: current.slice(0, -appended.length) };
    }
    if (!Array.isArray(file.edits)) throw new Error(`no edits to reverse: ${file.path}`);
    let content = current;
    for (const edit of [...file.edits].reverse()) {
      const original = edit._resolvedFind ?? edit.find;
      if (typeof edit.replace !== 'string' || typeof original !== 'string') throw new Error('invalid reverse edit');
      const offset = file._afterHash && Number.isInteger(edit._offset) ? edit._offset : content.indexOf(edit.replace);
      if ((!file._afterHash && countOccurrences(content, edit.replace) !== 1) || offset < 0 ||
          content.slice(offset, offset + edit.replace.length) !== edit.replace) {
        throw new Error(`reverted text missing or ambiguous in ${file.path}`);
      }
      content = content.slice(0, offset) + original + content.slice(offset + edit.replace.length);
    }
    return { abs, content };
  });
  const snapshots = snapshotPlan(root, plan);
  try {
    for (const change of changes) {
      if (change.remove) fs.unlinkSync(change.abs);
      else writeFileAtomic.sync(change.abs, change.content, { encoding: 'utf8' });
    }
  } catch (err) {
    restoreSnapshots(snapshots);
    throw err;
  }
}
