/**
 * Prompt Injection Prober
 * ========================
 *
 * Loads a probe corpus from cli/data/probes/prompt-injection-corpus.json and
 * scans source code for static-detectable signals that match each probe.
 *
 * The corpus replaces hardcoded patterns: new probes are added by editing
 * the JSON file. Each probe carries `tags` (e.g. ['LLM01', 'AML.T0051'])
 * which feed into the standards registry automatically — once the agent
 * tags a finding with the probe IDs, the per-finding `standards` field is
 * populated by the ScoringEngine.
 *
 * Maps to: OWASP LLM01/05/06/07/08, MITRE ATLAS T0043/T0051/T0053/T0054/T0057/T0070.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { BaseAgent, createFinding, ruleTableLineMask } from './base-agent.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CORPUS_PATH = path.resolve(__dirname, '..', 'data', 'probes', 'prompt-injection-corpus.json');

const SCAN_EXTS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.rb', '.go', '.java', '.rs', '.php']);

let _cachedCorpus = null;

/** Reads a JSON file, returning null rather than throwing. */
function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch {
    return null;
  }
}

const THREATPACK_SEED = path.join(path.dirname(CORPUS_PATH), '..', 'threatpacks', 'latest.json');

function loadCorpus() {
  if (_cachedCorpus) return _cachedCorpus;
  try {
    const data = readJson(CORPUS_PATH) || {};
    const categoryById = {};
    for (const c of data.categories || []) categoryById[c.id] = c;

    const decorate = (p) => {
      const cat = categoryById[p.category] || {};
      let regex;
      try {
        regex = compileProbeRegex(p.regex);
      } catch {
        regex = null;
      }
      return {
        ...p,
        patternSource: p.regex,
        regex,
        categoryTitle: cat.title || p.category,
        tags: cat.tags || [],
      };
    };

    // 1. Bundled prompt-injection corpus.
    const probes = (data.probes || []).map(decorate);

    // 2. Bundled threat-pack seed — the detection floor for this release.
    //
    // The seed used to be consulted only via `praxis intel update`. Loading it here
    // means the shipped attack-vector families work on a first run with no network,
    // and it makes the release's own signatures authoritative.
    const seed = readJson(THREATPACK_SEED);
    const seedVersion = seed?.version || null;
    for (const p of seed?.probes || []) probes.push(decorate(p));

    // 3. Overlay the fetched intel feed, which may bring newer signatures.
    //
    //    Version-gated per probe: a feed older than the bundled seed must not replace
    //    a probe the release already ships. A stale `threat-intel.json` holding
    //    threatpack 1.0.0 was reinstating the pre-fix TP-003 pattern
    //    (`when\s+combined\s+with`, no referent, no instruction noun) and reporting
    //    ordinary English as prompt injection. A feed newer than, or equal to, the
    //    seed still wins, so updates keep working.
    let feedApplied = 0;
    let feedRejected = 0;
    const feed = readJson(path.join(os.homedir(), '.praxis', 'threat-intel.json'));
    const pack = feed?.threatPack;
    const feedVersion = pack?.version || null;
    const feedIsOlder = seedVersion && feedVersion
      && compareVersions(feedVersion, seedVersion) < 0;

    for (const p of pack?.probes || []) {
      if (feedIsOlder) { feedRejected++; continue; }
      const decorated = decorate(p);
      const existing = probes.findIndex(x => x.id === p.id);
      if (existing >= 0) probes[existing] = decorated;
      else probes.push(decorated);
      feedApplied++;
    }

    _cachedCorpus = {
      version: data.version,
      probes,
      seedThreatPackVersion: seedVersion,
      feedThreatPackVersion: feedVersion,
      feedApplied,
      feedRejected,
    };
    return _cachedCorpus;
  } catch {
    _cachedCorpus = { version: '0', probes: [], feedApplied: 0, feedRejected: 0 };
    return _cachedCorpus;
  }
}

/**
 * Compares dotted version strings numerically. Returns <0, 0 or >0.
 * Missing/invalid segments compare as 0, so `1.0` and `1.0.0` are equal.
 */
function compareVersions(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d;
  }
  return 0;
}

function compileProbeRegex(pattern) {
  let flags = 'g';
  let body = pattern;
  const m = body.match(/^\(\?([imsux]+)\)/);
  if (m) {
    for (const f of m[1]) if ('imsu'.includes(f) && !flags.includes(f)) flags += f;
    body = body.slice(m[0].length);
  }
  // Scanner hardening: reject nested-quantifier constructs that risk
  // catastrophic backtracking on adversarial input.
  if (NESTED_QUANTIFIER.test(body)) {
    throw new Error('ReDoS-unsafe probe regex (nested quantifiers)');
  }
  return new RegExp(body, flags);
}

const NESTED_QUANTIFIER = /\((?:[^()\\]|\\.)*[+*]\)[+*{]/;

export class PromptInjectionProber extends BaseAgent {
  constructor() {
    super(
      'PromptInjectionProber',
      'Probe-corpus-driven scan for prompt-injection patterns (OWASP LLM01, ATLAS T0043/T0051)',
      'llm'
    );
    this._corpus = loadCorpus();
    this.probeCount = this._corpus.probes.length;
  }

  shouldRun(recon) {
    if (!recon) return true;
    const langs = recon.languages instanceof Set ? [...recon.languages] : (recon.languages || []);
    if (langs.some(l => ['javascript', 'typescript', 'python', 'ruby', 'go', 'java', 'rust', 'php'].includes(l))) {
      return true;
    }
    return Boolean(recon.frameworks?.length || recon.apiRoutes?.length);
  }

  async analyze(context) {
    const findings = [];
    const probes = this._corpus.probes.filter(p => p.regex);
    if (probes.length === 0) return findings;

    const files = this.getFilesToScan(context).filter(f => SCAN_EXTS.has(path.extname(f).toLowerCase()));

    for (const file of files) {
      const content = this.readFile(file);
      if (!content) continue;
      const lines = content.split('\n');
      // A probe payload quoted in a rule table's own prose is the table
      // documenting the probe, not an injection.
      const ruleTable = ruleTableLineMask(lines);

      for (const probe of probes) {
        probe.regex.lastIndex = 0;
        let match;
        while ((match = probe.regex.exec(content)) !== null) {
          const idx = match.index;
          const before = content.slice(0, idx);
          const lineNum = before.split('\n').length;
          const lastNl = before.lastIndexOf('\n');
          const column = lastNl === -1 ? idx + 1 : idx - lastNl;
          const lineText = lines[lineNum - 1] || '';
          if (this.isSuppressed(lineText)) continue;
          if (ruleTable && ruleTable.has(lineNum - 1)) continue;

          const finding = createFinding({
            file,
            line: lineNum,
            column,
            severity: probe.severity || 'medium',
            category: 'llm',
            rule: `PROBE_${probe.id}`,
            title: probe.title,
            description: probe.description,
            matched: match[0].slice(0, 160),
            confidence: 'medium',
            cwe: 'CWE-77',
            owasp: 'ASI01',
            fix: probe.fix || 'Sanitize untrusted input before LLM prompt construction.',
          });
          finding.probe = { id: probe.id, category: probe.category, tags: probe.tags };
          findings.push(finding);

          if (!probe.regex.global) break;
          if (match.index === probe.regex.lastIndex) probe.regex.lastIndex++;
        }
      }
    }

    return findings;
  }
}

export const _internals = { loadCorpus, compileProbeRegex, CORPUS_PATH };
export default PromptInjectionProber;
