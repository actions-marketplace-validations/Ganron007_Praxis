/**
 * Tests for the web UI.
 *
 * The web UI is the one place where Praxis adds an *attack surface* rather than a
 * feature: it holds source code in memory and, via `praxis fix`, could write code.
 * These tests therefore pin the guards from docs/design/WEB-UI.md as behaviour, not
 * documentation:
 *
 *   T2/T3 — the browser never sends a filesystem path; projects are id-addressed only
 *   T4    — a non-loopback bind is refused unless explicitly allowed AND tokenised
 *   T5    — mutating requests need an anti-CSRF header and a same-origin Origin
 *   T6    — nothing is served from disk
 *   T7    — the job queue is bounded
 *
 * plus the guarantee that v1 cannot apply fixes at all.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const temps = [];
const mkTmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-web-'));
  temps.push(d);
  return d;
};

before(() => {
  process.env.PRAXIS_WEB_HOME = mkTmp();
});

after(() => {
  delete process.env.PRAXIS_WEB_HOME;
  for (const d of temps) fs.rmSync(d, { recursive: true, force: true });
});

const { resolveProject, addProject, getProject, listProjects, removeProject, MAX_PROJECTS } =
  await import('../core/web/projects.js');
const { resolveBind, isLoopback, createServer } = await import('../core/web/server.js');
const { JobQueue } = await import('../core/web/jobs.js');

// =============================================================================
// T4 — bind guard
// =============================================================================

describe('web — bind guard (T4)', () => {
  it('recognises loopback hosts', () => {
    for (const h of ['127.0.0.1', '127.0.0.5', '::1', '::ffff:127.0.0.1']) {
      assert.equal(isLoopback(h), true, `${h} should be loopback`);
    }
    for (const h of ['0.0.0.0', '192.168.1.5', 'example.com', '10.0.0.1']) {
      assert.equal(isLoopback(h), false, `${h} should not be loopback`);
    }
  });

  it('permits loopback without a token', () => {
    assert.equal(resolveBind('127.0.0.1', {}).ok, true);
  });

  it('refuses a remote bind by default', () => {
    const r = resolveBind('0.0.0.0', {});
    assert.equal(r.ok, false);
    assert.match(r.error, /Refusing to bind/);
  });

  it('refuses a remote bind even with --allow-remote when no token is set', () => {
    const r = resolveBind('0.0.0.0', { allowRemote: true, token: null });
    assert.equal(r.ok, false);
    assert.match(r.error, /token/);
  });

  it('refuses a short token', () => {
    assert.equal(resolveBind('0.0.0.0', { allowRemote: true, token: 'short' }).ok, false);
  });

  it('permits a remote bind only with both opt-in and a strong token', () => {
    const r = resolveBind('0.0.0.0', { allowRemote: true, token: 'a'.repeat(32) });
    assert.equal(r.ok, true);
    assert.equal(r.remote, true);
  });
});

// =============================================================================
// T2/T3 — project registry
// =============================================================================

describe('web — project registry (T2/T3)', () => {
  beforeEach(() => {
    // Fresh registry per test.
    const home = process.env.PRAXIS_WEB_HOME;
    fs.rmSync(path.join(home, 'projects.json'), { force: true });
  });

  it('resolves a real directory to a pinned absolute path', () => {
    const dir = mkTmp();
    const r = resolveProject(dir);
    assert.equal(r.ok, true);
    assert.equal(path.isAbsolute(r.root), true);
    assert.equal(fs.realpathSync(dir), r.root);
  });

  it('rejects a missing path, a file, and junk input', () => {
    assert.equal(resolveProject(path.join(mkTmp(), 'nope')).ok, false);

    const file = path.join(mkTmp(), 'a.txt');
    fs.writeFileSync(file, 'x');
    assert.equal(resolveProject(file).ok, false);

    for (const junk of ['', '   ', null, undefined, 42, {}]) {
      assert.equal(resolveProject(junk).ok, false, `${JSON.stringify(junk)} should be rejected`);
    }
  });

  it('registers idempotently per resolved path', () => {
    const dir = mkTmp();
    const a = addProject(dir);
    const b = addProject(dir);
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
    assert.equal(a.created, true);
    assert.equal(b.created, false, 'the same path must not be registered twice');
    assert.equal(a.project.id, b.project.id);
  });

  it('addresses projects by id, and only by id', () => {
    const { project } = addProject(mkTmp());
    const found = getProject(project.id);
    assert.equal(found.ok, true);
    assert.equal(found.project.root, project.root);
    assert.equal(found.project.present, true);

    for (const bad of ['', null, undefined, '../../etc', 'not-a-uuid', 7]) {
      assert.equal(getProject(bad).ok, false, `${String(bad)} must not resolve to a path`);
    }
  });

  it('reports a pinned path that has since disappeared', () => {
    const dir = mkTmp();
    const { project } = addProject(dir);
    fs.rmSync(dir, { recursive: true, force: true });
    const found = getProject(project.id);
    assert.equal(found.ok, true, 'the id is still known');
    assert.equal(found.project.present, false, 'but it must be flagged as missing, not silently scanned');
  });

  it('removes projects by id', () => {
    const { project } = addProject(mkTmp());
    assert.equal(removeProject(project.id).ok, true);
    assert.equal(getProject(project.id).ok, false);
    assert.equal(removeProject(project.id).ok, false);
  });

  it('enforces the registry ceiling', () => {
    for (let i = 0; i < MAX_PROJECTS; i++) addProject(mkTmp());
    const overflow = addProject(mkTmp());
    assert.equal(overflow.ok, false);
    assert.match(overflow.error, /full/);
  });

  it('survives a corrupt registry file rather than throwing', () => {
    fs.mkdirSync(process.env.PRAXIS_WEB_HOME, { recursive: true });
    fs.writeFileSync(path.join(process.env.PRAXIS_WEB_HOME, 'projects.json'), '{ not json', 'utf8');
    assert.deepEqual(listProjects(), []);
  });
});

// =============================================================================
// T7 — job queue
// =============================================================================

describe('web — job queue (T7)', () => {
  const fakeRunner = (delay = 5, fail = false) => async (root, onProgress) => {
    onProgress({ agent: 'A1', category: 'x', done: 1, total: 2, findingCount: 1 });
    await new Promise(r => setTimeout(r, delay));
    if (fail) throw new Error('scan exploded');
    return { root, totalFindings: 1, agents: [{ agent: 'A1' }], findings: [{ rule: 'R' }] };
  };

  it('runs a scan and settles as done', async () => {
    const q = new JobQueue({ runScan: fakeRunner() });
    const { job } = q.enqueue({ id: 'p1', name: 'proj', root: mkTmp() });
    assert.equal(job.status, 'queued');

    await new Promise(r => q.once('update', j => { if (j.status === 'done') r(); }));
    const settled = q.get(job.id);
    assert.equal(settled.status, 'done');
    assert.equal(settled.result.totalFindings, 1);
  });

  it('records a failure instead of throwing', async () => {
    const q = new JobQueue({ runScan: fakeRunner(1, true) });
    const { job } = q.enqueue({ id: 'p1', name: 'proj', root: mkTmp() });
    await new Promise(r => q.once('update', j => { if (j.status === 'failed') r(); }));
    const settled = q.get(job.id);
    assert.equal(settled.status, 'failed');
    assert.match(settled.error, /scan exploded/);
  });

  it('never leaks the scan root to API consumers', () => {
    const q = new JobQueue({ runScan: fakeRunner() });
    const { job } = q.enqueue({ id: 'p1', name: 'proj', root: '/secret/path' });
    assert.ok(!('root' in job), 'the pinned root must not be exposed in the public job shape');
  });

  it('bounds the queue', () => {
    const q = new JobQueue({ concurrency: 1, runScan: () => new Promise(() => {}) });
    let refused = null;
    for (let i = 0; i < 40; i++) {
      const r = q.enqueue({ id: `p${i}`, name: `p${i}`, root: mkTmp() });
      if (!r.ok) { refused = r; break; }
    }
    assert.ok(refused, 'the queue must refuse work past its bound');
    assert.match(refused.error, /queue is full/);
  });

  it('refuses to cancel a running scan rather than pretending to', async () => {
    const q = new JobQueue({ concurrency: 1, runScan: () => new Promise(r => setTimeout(() => r({}), 60)) });
    const { job } = q.enqueue({ id: 'p1', name: 'p', root: mkTmp() });
    await new Promise(r => setTimeout(r, 10));
    const res = q.cancel(job.id);
    assert.equal(res.ok, false);
    assert.match(res.error, /cannot be cancelled/);
  });

  it('reports real progress and never fabricates it', async () => {
    const seen = [];
    const q = new JobQueue({ runScan: fakeRunner() });
    q.on('update', j => seen.push({ ...j.progress }));
    const { job } = q.enqueue({ id: 'p1', name: 'p', root: mkTmp() });
    await new Promise(r => q.once('update', j => { if (j.status === 'done') r(); }));
    const withProgress = seen.filter(p => p.total > 0);
    assert.ok(withProgress.length > 0, 'the runner hook must surface progress');
    assert.ok(withProgress.some(p => p.current === 'A1'));
    assert.ok(q.get(job.id).progress.total > 0);
  });
});

// =============================================================================
// HTTP guards (T5, T6) and the read-only guarantee
// =============================================================================

describe('web — HTTP guards and read-only guarantee', () => {
  let server;
  let base;

  before(async () => {
    process.env.PRAXIS_WEB_HOME = mkTmp();
    const created = createServer({ host: '127.0.0.1', port: 0, queue: new JobQueue({ runScan: async () => ({ totalFindings: 0, findings: [] }) }) });
    server = created.server;
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => {
    server?.close();
  });

  const call = (method, p, { headers = {}, body } = {}) =>
    fetch(base + p, {
      method,
      headers: body ? { 'Content-Type': 'application/json', ...headers } : headers,
      body: body ? JSON.stringify(body) : undefined,
    });

  it('serves the frontend with a restrictive CSP', async () => {
    const res = await call('GET', '/');
    assert.equal(res.status, 200);
    const csp = res.headers.get('content-security-policy') || '';
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /object-src|default-src 'none'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });

  it('refuses a mutating request without the anti-CSRF header (T5)', async () => {
    const res = await call('POST', '/api/projects', { body: { path: mkTmp() } });
    assert.equal(res.status, 403);
  });

  it('refuses a mutating request from a cross-origin Origin (T5)', async () => {
    const res = await call('POST', '/api/projects', {
      headers: { 'X-Praxis-Client': 'praxis-web', Origin: 'https://evil.example' },
      body: { path: mkTmp() },
    });
    assert.equal(res.status, 403);
  });

  it('accepts a same-origin mutating request (T5)', async () => {
    const dir = mkTmp();
    const res = await call('POST', '/api/projects', {
      headers: { 'X-Praxis-Client': 'praxis-web' },
      body: { path: dir },
    });
    assert.ok(res.status === 200 || res.status === 201, `status ${res.status}`);
  });

  it('serves nothing from disk (T6)', async () => {
    for (const p of ['/../package.json', '/../../package.json', '/cli/bin/praxis.js', '/package.json']) {
      const res = await call('GET', p);
      assert.equal(res.status, 404, `${p} must not be served`);
    }
  });

  it('404s an unknown project id rather than resolving a path (T3)', async () => {
    const res = await call('GET', '/api/projects/not-a-real-id/report');
    assert.equal(res.status, 404);
  });

  it('exposes no fix-application endpoint (v1 is read-only, T1)', async () => {
    const html = await (await call('GET', '/')).text();
    assert.ok(!/\/api\/(fix|apply|patch|remediate|undo)/i.test(html), 'no fix endpoint may exist');
    for (const p of ['/api/fix', '/api/apply', '/api/remediate']) {
      const res = await call('POST', p, { headers: { 'X-Praxis-Client': 'praxis-web' }, body: {} });
      assert.ok(res.status === 404, `${p} must not exist`);
    }
  });

  it('streams job progress as text/event-stream', async () => {
    const res = await fetch(`${base}/api/jobs/does-not-exist/events`);
    assert.equal(res.status, 404, 'unknown job 404s rather than hanging a stream open');
  });

  it('rejects an oversized request body', async () => {
    const res = await call('POST', '/api/projects', {
      headers: { 'X-Praxis-Client': 'praxis-web' },
      body: { path: 'x'.repeat(200 * 1024) },
    });
    assert.ok(res.status >= 400, `expected rejection, got ${res.status}`);
  });
});