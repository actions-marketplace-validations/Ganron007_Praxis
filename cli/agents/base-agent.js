/**
 * BaseAgent — Foundation for all security scanning agents
 * ========================================================
 *
 * Every agent in praxis extends BaseAgent. It provides:
 *   - Standard finding format
 *   - File discovery with skip-list support
 *   - Severity classification
 *   - Consistent output interface
 *
 * USAGE:
 *   class MyAgent extends BaseAgent {
 *     constructor() { super('MyAgent', 'Description', 'category'); }
 *     async analyze(context) { return [findings]; }
 *   }
 */

import fs from 'fs';
import path from 'path';
import fg from '../core/glob.js';
import { SKIP_DIRS, SKIP_EXTENSIONS, SKIP_FILENAMES, MAX_FILE_SIZE, MAX_SCAN_FILES, loadGitignorePatterns } from '../utils/patterns.js';

// =============================================================================
// RULE-TABLE SUPPRESSION
// =============================================================================
//
// A detection rule table is data, not code, and it necessarily contains the
// signatures it hunts for: a rule's `description:` spells out the insecure call
// it is looking for, so that prose matches the rule itself. Scanning our own
// tables therefore reported every rule describing itself — 138 of 271 findings
// in a self-scan, over half the report.
//
// Keep this comment free of concrete API names: quoting one makes this file a
// match for the very rule being discussed.
//
// Suppression is deliberately two-stage so it cannot mask a real finding:
//   1. the FILE must be a rule table (two or more matcher entries against rule
//      ids — something application code never declares), and
//   2. the LINE must be a rule field holding prose or a pattern.
// A file that merely uses the words "description" or "fix" fails stage 1 and is
// scanned normally.

const RULE_MATCHER_FIELD = /^\s*(?:regex|pattern|detectionRegex)\s*:/;
const RULE_ID_FIELD = /^\s*(?:rule|id|name)\s*:\s*['"`]/;
const RULE_PROSE_FIELD =
  /^\s*(?:title|description|fix|note|recommendation|regex|pattern|detectionRegex|severity|cwe|owasp|confidence|id|rule)\s*:/;

const MIN_RULE_TABLE_ENTRIES = 2;

/**
 * Build the set of line indexes that hold rule-table prose rather than code.
 *
 * Returns `null` when the file is not a rule table, so callers get "scan this
 * file normally" for free. Reuse the returned Set for the whole file: building
 * it is one cheap pass, and callers that scan line by line would otherwise
 * repeat it per line.
 *
 * @param {string[]} lines
 * @returns {Set<number>|null} zero-based indexes of rule-definition lines
 */
export function ruleTableLineMask(lines) {
  let matchers = 0;
  let ids = 0;
  for (const line of lines) {
    if (RULE_MATCHER_FIELD.test(line)) matchers++;
    else if (RULE_ID_FIELD.test(line)) ids++;
  }
  if (matchers < MIN_RULE_TABLE_ENTRIES || ids < MIN_RULE_TABLE_ENTRIES) return null;

  const mask = new Set();
  for (let i = 0; i < lines.length; i++) {
    if (RULE_PROSE_FIELD.test(lines[i])) mask.add(i);
  }
  return mask;
}

// =============================================================================
// FINDING FACTORY
// =============================================================================

/**
 * Create a standardized finding object.
 */
export function createFinding({
  file,
  line = 0,
  column = 0,
  severity = 'medium',
  category = 'vulnerability',
  rule,
  title,
  description,
  matched = '',
  confidence = 'high',
  cwe = null,
  owasp = null,
  eaa = null,
  fix = null,
}) {
  return {
    file,
    line,
    column,
    severity,
    category,
    rule,
    title,
    description,
    matched,
    confidence,
    cwe,
    owasp,
    ...(eaa ? { eaa } : {}),
    fix,
  };
}

// =============================================================================
// BASE AGENT CLASS
// =============================================================================

export class BaseAgent {
  /**
   * @param {string} name        — Agent name (e.g. 'InjectionTester')
   * @param {string} description — What this agent does
   * @param {string} category    — Finding category for scoring
   */
  constructor(name, description, category) {
    this.name = name;
    this.description = description;
    this.category = category;
  }

  /**
   * Run the agent's analysis on a codebase.
   * Subclasses MUST override this method.
   *
   * @param {object} context — { rootPath, files, recon, options }
   * @returns {Promise<object[]>} — Array of finding objects
   */
  async analyze(context) {
    throw new Error(`${this.name}.analyze() not implemented`);
  }

  /**
   * Whether this agent should run given the recon results.
   * Override in subclasses to skip irrelevant scans.
   * Default: always run.
   */
  shouldRun(recon) {
    return true;
  }

  // ── Helpers available to all agents ─────────────────────────────────────────

  /**
   * Discover all scannable files in a directory.
   * Respects SKIP_DIRS, SKIP_EXTENSIONS, and MAX_FILE_SIZE.
   */
  async discoverFiles(rootPath, extraGlobs = ['**/*']) {
    const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);

    // Respect .gitignore patterns
    const gitignoreGlobs = loadGitignorePatterns(rootPath);
    globIgnore.push(...gitignoreGlobs);

    // Load .praxisignore patterns
    const ignorePatterns = this._loadIgnorePatterns(rootPath);
    for (const p of ignorePatterns) {
      if (p.endsWith('/')) {
        globIgnore.push(`**/${p}**`);
      } else {
        globIgnore.push(`**/${p}`);
        globIgnore.push(p);
      }
    }

    const allFiles = await fg(extraGlobs, {
      cwd: rootPath,
      absolute: true,
      onlyFiles: true,
      ignore: globIgnore,
      dot: true,
    });

    const capped = allFiles.length > MAX_SCAN_FILES ? allFiles.slice(0, MAX_SCAN_FILES) : allFiles;

    return capped.filter(file => {
      const ext = path.extname(file).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) return false;
      const basename = path.basename(file);
      if (SKIP_FILENAMES.has(basename)) return false;
      if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) return false;
      try {
        // Scanner hardening: refuse symlinks (a hostile repo could link to
        // files outside the workspace) and cap file size.
        const lstats = fs.lstatSync(file);
        if (lstats.isSymbolicLink()) return false;
        const stats = fs.statSync(file);
        if (stats.size > MAX_FILE_SIZE) return false;
      } catch {
        return false;
      }
      return true;
    });
  }

  /**
   * Load .praxisignore patterns from the project root.
   */
  _loadIgnorePatterns(rootPath) {
    const ignorePath = path.join(rootPath, '.praxisignore');
    try {
      if (!fs.existsSync(ignorePath)) return [];
      return fs.readFileSync(ignorePath, 'utf-8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
    } catch {
      return [];
    }
  }

  /**
   * Get the files this agent should scan.
   * If incremental scanning is active (changedFiles in context), returns only changed files.
   * Otherwise returns all files. Agents that need the full file list can use context.files directly.
   */
  getFilesToScan(context) {
    return context.changedFiles || context.files;
  }

  /**
   * Read a file safely, returning null on failure.
   */
  readFile(filePath) {
    try {
      return fs.readFileSync(filePath, 'utf-8');
    } catch {
      return null;
    }
  }

  /**
   * Read a file and return its lines with line numbers.
   */
  readLines(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    return content.split('\n');
  }

  /**
   * Get surrounding code context for a finding.
   */
  getContext(filePath, lineNum, radius = 3) {
    const lines = this.readLines(filePath);
    if (lines.length === 0) return '';
    const start = Math.max(0, lineNum - 1 - radius);
    const end = Math.min(lines.length, lineNum + radius);
    return lines.slice(start, end).join('\n');
  }

  /**
   * Check if a line has the praxis-ignore suppression comment.
   */
  isSuppressed(line) {
    return /praxis-ignore/i.test(line);
  }

  /**
   * Scan file lines against an array of regex patterns.
   * Returns findings for every match.
   */
  scanFileWithPatterns(filePath, patterns) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const lines = content.split('\n');
    const findings = [];

    // Rule tables state what a vulnerability looks like, so their prose and
    // patterns match the rules looking for them. Skipping those lines is what
    // stops a self-scan from reporting every rule describing itself.
    const ruleTable = ruleTableLineMask(lines);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (this.isSuppressed(line)) continue;
      if (ruleTable && ruleTable.has(i)) continue;

      for (const p of patterns) {
        p.regex.lastIndex = 0;
        let match;
        while ((match = p.regex.exec(line)) !== null) {
          const finding = createFinding({
            file: filePath,
            line: i + 1,
            column: match.index + 1,
            severity: p.severity || 'medium',
            category: this.category,
            rule: p.rule,
            title: p.title,
            description: p.description,
            matched: match[0],
            confidence: p.confidence || 'high',
            cwe: p.cwe || null,
            owasp: p.owasp || null,
            fix: p.fix || null,
          });
          // Attach surrounding code context (3 lines before/after)
          const start = Math.max(0, i - 3);
          const end = Math.min(lines.length, i + 4);
          finding.codeContext = lines.slice(start, end).map((l, idx) => ({
            line: start + idx + 1,
            text: l,
            highlight: (start + idx) === i,
          }));
          findings.push(finding);
        }
      }
    }

    return findings;
  }

  /**
   * Check if content imports or requires a specific module.
   */
  hasImport(content, moduleName) {
    const importRe = new RegExp(
      `(?:import\\s+.*from\\s+['"]${moduleName}['"])|` +
      `(?:require\\s*\\(\\s*['"]${moduleName}['"]\\s*\\))`,
      'g'
    );
    return importRe.test(content);
  }
}

export default BaseAgent;
