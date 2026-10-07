/**
 * Score history — read the scan-over-time series behind the trend section.
 * ============================================================================
 *
 * `.praxis/history.json` is appended once per scan with `{timestamp, score, grade,
 * totalFindings, totalDepVulns, categoryScores}`.
 *
 * The discipline here is about *not overstating* the data:
 *   - with no prior scans the project is at its **baseline** — the report must say so
 *     rather than draw an empty graph, which reads as "flat, no change"
 *   - a two-point series is **two measurements, not a trend**, and is labelled as such
 *   - the sample size and the time span are always shown next to the chart, so nobody
 *     reads three scans over four minutes as a security trajectory
 *
 * Best-effort and never throws: a corrupt history must not break a report, and it must
 * never be silently replaced with fabricated points.
 */

import fs from 'fs';
import path from 'path';

const HISTORY_FILE = path.join('.praxis', 'history.json');

/**
 * Reads the score history for a project.
 * @returns {{points: object[], unreadable: number, error: string|null}}
 */
export function readScoreHistory(rootPath = process.cwd()) {
  const root = typeof rootPath === 'string' && rootPath.length > 0 ? rootPath : process.cwd();
  let raw;
  try {
    raw = fs.readFileSync(path.join(root, HISTORY_FILE), 'utf8');
  } catch (err) {
    return { points: [], unreadable: 0, error: err.code === 'ENOENT' ? null : err.message };
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { points: [], unreadable: 0, error: `history.json is not valid JSON: ${err.message}` };
  }

  if (!Array.isArray(parsed)) {
    return { points: [], unreadable: 0, error: 'history.json is not an array of scan entries' };
  }

  const points = [];
  let unreadable = 0;
  for (const entry of parsed) {
    if (entry && typeof entry === 'object' && typeof entry.score === 'number') {
      points.push({
        timestamp: entry.timestamp || null,
        score: entry.score,
        grade: entry.grade ?? null,
        totalFindings: typeof entry.totalFindings === 'number' ? entry.totalFindings : null,
      });
    } else {
      unreadable++;
    }
  }

  // Oldest → newest, so callers can treat the tail as "latest".
  points.sort((a, b) => String(a.timestamp ?? '').localeCompare(String(b.timestamp ?? '')));
  return { points, unreadable, error: null };
}

/**
 * Summarises a series for display, and states plainly how much data there is.
 *
 * @param {object[]} points   History points, oldest first (from readScoreHistory).
 * @param {object}   [current] `{score, grade}` for the scan being reported, so the
 *                             live score appears on the chart even before it is
 *                             appended to history.
 */
export function summarizeHistory(points = [], current = null) {
  // Coerce first: spreading null/undefined throws, which would break the
  // "never throws" contract this module advertises.
  const series = Array.isArray(points) ? [...points] : [];

  // Append the in-flight scan if history doesn't already end with it. Without this the
  // chart would show the *previous* score as the latest point and quietly mislead.
  const last = series[series.length - 1];
  const currentAlreadyPresent =
    current && typeof current.score === 'number' && last && last.score === current.score;
  if (current && typeof current.score === 'number' && !currentAlreadyPresent) {
    series.push({ timestamp: null, score: current.score, grade: current.grade ?? null, totalFindings: null, isCurrent: true });
  }

  const scores = series.map(p => p.score);
  const latest = scores[scores.length - 1] ?? null;
  const previous = scores.length >= 2 ? scores[scores.length - 2] : null;

  // How many *measurements* exist, and how many are prior runs (excluding the live one).
  const measurementCount = scores.length;
  const priorCount = Math.max(0, measurementCount - (current && !currentAlreadyPresent ? 1 : 0));

  let spanDays = null;
  const dated = series.filter(p => p.timestamp);
  if (dated.length >= 2) {
    const t0 = Date.parse(dated[0].timestamp);
    const tN = Date.parse(dated[dated.length - 1].timestamp);
    if (Number.isFinite(t0) && Number.isFinite(tN)) spanDays = Math.round(((tN - t0) / 86400000) * 10) / 10;
  }

  return {
    series,
    measurementCount,
    priorCount,
    latest,
    previous,
    delta: latest !== null && previous !== null ? Math.round((latest - previous) * 10) / 10 : null,
    best: scores.length ? Math.max(...scores) : null,
    worst: scores.length ? Math.min(...scores) : null,
    isBaseline: measurementCount <= 1 && !current,
    needsMoreData: measurementCount >= 1 && measurementCount < 3,
    spanDays,
  };
}