/**
 * Scanner file discovery boundary. Target-controlled patterns are bounded before
 * fast-glob/braces parse them (GHSA-vfj7-8cjw-p6xm has no upstream patch yet).
 * Directory symlinks must not turn a project scan into a scan of the host.
 */
import fastGlob from 'fast-glob';

const MAX_PATTERNS = 4096;
const MAX_LENGTH = 8192;
const MAX_DEPTH = 16;
const MAX_EXPANSIONS = 1024;

export function validateGlobPatterns(patterns) {
  const list = Array.isArray(patterns) ? patterns : [patterns];
  if (list.length > MAX_PATTERNS) throw new Error('Too many glob patterns');
  for (const pattern of list) {
    if (typeof pattern !== 'string' || pattern.length > MAX_LENGTH) throw new Error('Invalid or oversized glob pattern');
    const stack = [];
    let expansions = 1;
    for (let i = 0; i < pattern.length; i++) {
      const char = pattern[i];
      if (char === '\\') { i++; continue; }
      if (char === '{') {
        stack.push({ start: i, alternatives: 1 });
        if (stack.length > MAX_DEPTH) throw new Error('Glob brace nesting exceeds safe limit');
      } else if (char === ',' && stack.length) {
        stack[stack.length - 1].alternatives++;
      } else if (char === '}' && stack.length) {
        const group = stack.pop();
        const range = pattern.slice(group.start + 1, i).match(/^(-?\d+|[a-zA-Z])\.\.(-?\d+|[a-zA-Z])(?:\.\.(-?\d+))?$/);
        let alternatives = group.alternatives;
        if (range) {
          const number = value => /^-?\d+$/.test(value) ? Number(value) : value.charCodeAt(0);
          const step = Math.abs(Number(range[3] || 1));
          alternatives = Math.floor(Math.abs(number(range[2]) - number(range[1])) / step) + 1;
        }
        expansions *= alternatives;
        if (!Number.isFinite(expansions) || expansions > MAX_EXPANSIONS) throw new Error('Glob brace expansion exceeds safe limit');
      }
    }
  }
}

function safeOptions(patterns, options) {
  validateGlobPatterns(patterns);
  if (options.ignore) validateGlobPatterns(options.ignore);
  return { ...options, followSymbolicLinks: false };
}

function glob(patterns, options = {}) {
  return fastGlob(patterns, safeOptions(patterns, options));
}

glob.sync = (patterns, options = {}) => fastGlob.sync(patterns, safeOptions(patterns, options));

export default glob;
