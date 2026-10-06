/**
 * Bounded job queue for the web UI.
 * ============================================================================
 *
 * Runs scans through the existing `Orchestrator` so the web UI never reimplements
 * detection — the numbers in the browser are the same numbers the CLI produces.
 *
 * Threat T7 (resource exhaustion): concurrency is capped and the queue length is
 * capped, because a scan is expensive (28 agents) and an untrusted local caller could
 * otherwise pile up work. Jobs live in memory; the report is what gets persisted, so // praxis-ignore AGENT_MEMORY_NO_EXPIRY — doc comment; JobQueue._trim() bounds retention to 50 finished jobs
 * restarting the server does not lose scan *results* the report already captured.
 */

import path from 'path';
import { EventEmitter } from 'events';

export const MAX_CONCURRENCY = 2;
export const MAX_QUEUE = 16;
const JOB_RETENTION = 50; // keep the most recent N finished jobs for inspection

let seq = 0;

export class JobQueue extends EventEmitter {
  constructor({ concurrency = MAX_CONCURRENCY, runScan } = {}) {
    super();
    this.concurrency = Math.max(1, concurrency);
    this.maxQueue = MAX_QUEUE;
    this.runScan = runScan;
    this.jobs = [];
    this.pending = [];
    this.running = 0;
  }

  /**
   * Enqueues a scan for a registered project.
   * @returns {{ok:true, job:object} | {ok:false, error:string}}
   */
  enqueue(project) {
    const queued = this.running + this.pending.length;
    if (queued >= this.maxQueue) {
      return { ok: false, error: `queue is full (max ${this.maxQueue} scans)` };
    }
    const job = {
      id: `job-${++seq}`,
      projectId: project.id,
      projectName: project.name,
      root: project.root,
      status: 'queued',
      queuedAt: new Date().toISOString(),
      startedAt: null,
      finishedAt: null,
      progress: { done: 0, total: 0, current: null },
      result: null,
      error: null,
    };
    this.jobs.push(job);
    this.pending.push(job);
    this._emitUpdate(job);
    // Snapshot before draining: _drain() starts the job synchronously, so capturing
    // afterwards would hand the client a job already marked 'running' and make the
    // 'queued' state unobservable.
    const snapshot = this._public(job);
    this._drain();
    return { ok: true, job: snapshot };
  }

  get(id) {
    return this.jobs.find(j => j.id === id) || null;
  }

  /** All jobs, oldest first, as API-safe objects. */
  list() {
    return this.jobs.map(j => this._public(j));
  }

  cancel(id) {
    const job = this.get(id);
    if (!job) return { ok: false, error: 'unknown job' };
    if (job.status === 'running') {
      // The orchestrator is not abortable mid-scan; be honest rather than pretend.
      return { ok: false, error: 'scan already running and cannot be cancelled' };
    }
    if (job.status === 'queued') {
      this.pending = this.pending.filter(j => j.id !== id);
      job.status = 'cancelled';
      job.finishedAt = new Date().toISOString();
      this._emitUpdate(job);
      return { ok: true };
    }
    return { ok: false, error: `job is already ${job.status}` };
  }

  _public(job) {
    const { result, root: _root, ...rest } = job;
    return { ...rest, hasResult: Boolean(result) };
  }

  _emitUpdate(job) {
    this.emit('update', this._public(job));
  }

  _drain() {
    while (this.running < this.concurrency && this.pending.length > 0) {
      const job = this.pending.shift();
      this._run(job);
    }
  }

  async _run(job) {
    this.running++;
    job.status = 'running';
    job.startedAt = new Date().toISOString();
    job.progress = { done: 0, total: 0, current: null };
    this._emitUpdate(job);

    try {
      if (typeof this.runScan !== 'function') {
        throw new Error('no scan runner configured');
      }
      const result = await this.runScan(job.root, progress => {
        // Real per-agent progress from the orchestrator hook. If the hook never fires
        // (no agents applicable), progress stays 0/0 rather than inventing a number.
        if (progress) {
          job.progress = {
            done: Number(progress.done) || 0,
            total: Number(progress.total) || 0,
            current: progress.agent || null,
          };
          this._emitUpdate(job);
        }
      });
      job.result = result;
      job.status = 'done';
      job.finishedAt = new Date().toISOString();
    } catch (err) {
      job.status = 'failed';
      job.error = err.message || String(err);
      job.finishedAt = new Date().toISOString();
    } finally {
      this.running--;
      this._emitUpdate(job);
      this._trim();
      this._drain();
    }
  }

  _trim() {
    // Bound memory: drop the oldest finished jobs past the retention window.
    const finished = this.jobs.filter(j => j.status !== 'running' && j.status !== 'queued');
    if (finished.length <= JOB_RETENTION) return;
    const drop = new Set(finished.slice(0, finished.length - JOB_RETENTION).map(j => j.id));
    this.jobs = this.jobs.filter(j => !drop.has(j.id));
  }
}

/**
 * Default scan runner: drives the real Orchestrator so the UI cannot drift from the CLI.
 * Returns the same shape the CLI's JSON output produces, enriched with score and grade.
 */
export async function runScanWithOrchestrator(rootPath, onProgress) {
  const { buildOrchestratorAsync } = await import('../../agents/index.js');
  const orchestrator = await buildOrchestratorAsync(rootPath, { quiet: true });

  // runAll returns { recon, findings, agentResults } — the same telemetry the CLI
  // report renders, so the UI cannot drift from `praxis scan`.
  // `quiet` must be passed to runAll itself, not just the builder: runAll reads its own
  // options object, so omitting it would print CLI spinners into the HTTP server's stdout.
  const { findings, agentResults, recon } = await orchestrator.runAll(rootPath, { // praxis-ignore AGENT_ESCALATED_PERMISSIONS — destructuring runAll()'s result; no permission handling
    quiet: true,
    onProgress: info => {
      if (typeof onProgress === 'function') onProgress(info);
    },
  });

  let score = 100;
  let grade = 'A';
  let categories = {};
  let standardsSummary = null;
  try {
    const { ScoringEngine } = await import('../../agents/scoring-engine.js');
    const engine = new ScoringEngine();
    const computed = engine.compute(findings || []);
    if (computed) {
      score = computed.score ?? 100;
      grade = computed.grade?.letter || (typeof computed.grade === 'string' ? computed.grade : 'A');
      categories = computed.categories || {};
      standardsSummary = computed.standardsSummary || null;
    }
  } catch {
    // fallback gracefully
  }

  return {
    root: path.basename(rootPath),
    agentCount: (agentResults || []).length,
    totalFindings: (findings || []).length,
    agents: agentResults || [],
    recon: recon || null,
    findings: findings || [],
    score,
    grade,
    categories,
    standardsSummary,
    scannedAt: new Date().toISOString(),
  };
}
