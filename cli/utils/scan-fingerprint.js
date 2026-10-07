/**
 * Scan fingerprint — identify exactly what produced a set of findings.
 * ============================================================================
 *
 * Why this exists: during self-dogfooding a scan reported 325 findings
 * where four subsequent scans of the identical tree reported 308. The extra 17 were
 * `PROBE_*` / `VIBE_*` rules in files nobody had touched. Data drift, test fixtures
 * and the scan cache were each ruled out, so the cause stayed unknown.
 *
 * The response to "I cannot explain this number" is not a suppression — it is to make
 * the number attributable. Every scan now carries the tool version, the runtime, and
 * the version of every vendored data asset that can change detection behaviour, so a
 * surprising result can be traced to a specific input instead of guessed at.
 *
 * Everything here is best-effort and never throws: a missing or malformed data file
 * degrades to `null`, because a fingerprint must not be able to fail a scan.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { toolVersion } from '../core/version.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_DIR = path.resolve(__dirname, '..');

/** Praxis version comes from the single source in `cli/core/version.js`. */

/**
 * Reads a vendored data asset, returning its version and item count.
 * Never throws — an unreadable asset degrades to nulls rather than failing a scan.
 */
function readAssetVersion(relPath, countKey) {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(CLI_DIR, 'data', relPath), 'utf8'));
    const items = countKey && Array.isArray(data[countKey]) ? data[countKey].length : null;
    return { version: data.version ?? null, items };
  } catch {
    return { version: null, items: null };
  }
}

/**
 * Builds the fingerprint for a scan run.
 *
 * @param {object}  [opts]
 * @param {number}  [opts.filesScanned]  Number of files the scan walked.
 * @returns {{tool: string|null, node: string, data: object, filesScanned: number|null}}
 */
export function buildScanFingerprint({ filesScanned = null } = {}) {
  return {
    tool: toolVersion(),
    node: process.version,
    data: {
      probeCorpus: readAssetVersion(path.join('probes', 'prompt-injection-corpus.json'), 'probes'),
      threatPack: readAssetVersion(path.join('threatpacks', 'latest.json'), 'probes'),
      eaaCatalog: readAssetVersion('eaa-catalog.json', null),
    },
    filesScanned: typeof filesScanned === 'number' ? filesScanned : null,
  };
}

/**
 * One-line, human-readable rendering of a fingerprint, for report footers and CI logs.
 * Unknown values render as `?` so a missing asset is visible rather than silent.
 */
export function fingerprintLine(fp) {
  if (!fp) return '';
  const d = fp.data || {};
  const probes = d.probeCorpus || {};
  const pack = d.threatPack || {};
  const eaa = d.eaaCatalog || {};
  return [
    `praxis ${fp.tool ?? '?'}`,
    `node ${fp.node ?? '?'}`,
    `probes v${probes.version ?? '?'}(${probes.items ?? '?'})`,
    `threatpack v${pack.version ?? '?'}(${pack.items ?? '?'})`,
    `eaa v${eaa.version ?? '?'}`,
    `files ${fp.filesScanned ?? '?'}`,
  ].join(' · ');
}

/**
 * Stable identity for a finding, used to compare two runs of the same target.
 *
 * Deliberately excludes severity, line numbers and messages so that a change in
 * *scoring* does not read as a change in *detection*.
 *
 * Uses a double colon as the separator: finding.file can be a Windows path
 * (`C:/src/a.js`), which already contains a colon, so a single colon would make the
 * identity ambiguous to split.
 */
export function findingIdentity(finding) {
  return `${finding?.file ?? '?'}::${finding?.rule ?? '?'}`;
}

/**
 * Compares two scans of the same target and returns the set differences.
 * @returns {{added: string[], removed: string[], common: number}}
 */
export function diffFindings(before = [], after = []) {
  const a = new Set((before || []).map(findingIdentity));
  const b = new Set((after || []).map(findingIdentity));
  return {
    added: [...b].filter(id => !a.has(id)).sort(),
    removed: [...a].filter(id => !b.has(id)).sort(),
    common: [...b].filter(id => a.has(id)).length,
  };
}