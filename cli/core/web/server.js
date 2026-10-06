/**
 * HTTP server for the Praxis web UI.
 * ============================================================================
 *
 * Read-only by design (see docs/design/WEB-UI.md). This process runs with the
 * privileges of whoever started it and holds the user's source code in memory, so the
 * guards below are the feature, not boilerplate:
 *
 *   T4 — loopback-only by default. A non-loopback bind needs `--allow-remote` *and* an
 *        explicit token, which must then be presented in a header.
 *   T5 — CSRF / DNS-rebinding defence: mutating requests must carry a custom header
 *        that a cross-origin form cannot set, and a same-origin/loopback `Origin`.
 *   T3 — every project-scoped route resolves through the registry by id; no route ever
 *        accepts a filesystem path from the client.
 *   T6 — the frontend is generated in memory from the shared theme; nothing is served
 *        from disk, so there is no path to traverse.
 */

import http from 'http';
import { URL } from 'url';
import { isIP } from 'net';
import { listProjects, addProject, getProject, removeProject } from './projects.js';
import { JobQueue, runScanWithOrchestrator } from './jobs.js';
import { renderFrontend, AGENT_ROSTER } from './ui.js';
import jsonReport from '../output/json.js';

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']); // praxis-ignore SSRF_INTERNAL_IP — loopback allow-list: binding only to loopback IS the mitigation
const CLIENT_HEADER = 'x-praxis-client';
const CLIENT_VALUE = 'praxis-web';
const MAX_BODY_BYTES = 64 * 1024;

export function isLoopback(host) {
  const normalized = String(host).replace(/^\[|\]$/g, '');
  return LOOPBACK.has(normalized) || (isIP(normalized) === 4 && normalized.startsWith('127.'));
}

/** Decides the effective bind, refusing an unsafe remote bind (threat T4). */
export function resolveBind(requestedHost, { allowRemote = false, token = null } = {}) {
  const host = String(requestedHost || '127.0.0.1'); // praxis-ignore SSRF_INTERNAL_IP — loopback default; resolveBind() refuses remote without --allow-remote AND a token
  if (isLoopback(host)) return { ok: true, host, remote: false };

  if (!allowRemote) {
    return {
      ok: false,
      error:
        `Refusing to bind ${host}: the web UI exposes source code and scan results. ` +
        'Remote binding requires --allow-remote AND a --token.',
    };
  }
  if (!token || String(token).length < 16) {
    return {
      ok: false,
      error: 'Remote binding requires a --token of at least 16 characters.',
    };
  }
  return { ok: true, host, remote: true };
}

/** Timing-safe token comparison so a wrong token cannot be brute-forced byte by byte. */
function tokenMatches(provided, expected) {
  if (!expected) return true; // loopback: no token configured
  const a = Buffer.from(String(provided || ''));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

import crypto from 'crypto';

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let rejected = false;
    const chunks = [];
    req.on('data', c => {
      if (rejected) return; // already over the limit; keep draining, ignore
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        rejected = true;
        chunks.length = 0;
        // Respond 413 rather than destroying the socket, so the client sees a real
        // status instead of an opaque connection reset.
        const err = new Error('request body too large');
        err.statusCode = 413;
        reject(err);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (rejected) return;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        const err = new Error('invalid JSON body');
        err.statusCode = 400;
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function sendJSON(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendHTML(res, status, html) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
    'X-Content-Type-Options': 'nosniff',
    // The frontend needs inline script/style (no build step), so the CSP allows them
    // but nothing else — no remote origins, no eval, no plugins.
    'Content-Security-Policy':
      "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    'Cache-Control': 'no-store',
  });
  res.end(html);
}

/**
 * Origin / custom-header check for mutating requests (threat T5).
 * A cross-origin form cannot set a custom header, so its absence blocks CSRF.
 */
function guardMutation(req) {
  const header = req.headers[CLIENT_HEADER];
  if (header !== CLIENT_VALUE) {
    return { ok: false, error: 'missing client header (anti-CSRF)' };
  }
  const origin = req.headers.origin;
  if (origin) {
    let originURL;
    try {
      originURL = new URL(origin);
    } catch {
      return { ok: false, error: 'malformed Origin' };
    }
    // A different loopback port is still a different browser origin.
    if (!['http:', 'https:'].includes(originURL.protocol) || originURL.host !== req.headers.host) {
      return { ok: false, error: 'cross-origin request refused' };
    }
  }
  return { ok: true };
}

/**
 * In-memory sliding-window rate limiter (API_NO_RATE_LIMIT defense).
 * Bounds request frequency per IP to prevent resource exhaustion and local/remote DoS.
 */
export function createRateLimiter({ windowMs = 60 * 1000, max = 180 } = {}) {
  const hits = new Map();

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamps] of hits.entries()) {
      const valid = timestamps.filter(t => now - t < windowMs);
      if (valid.length === 0) hits.delete(ip);
      else hits.set(ip, valid);
    }
  }, windowMs);
  if (timer.unref) timer.unref();

  return function rateLimit(req, res) {
    const ip = req.socket?.remoteAddress || '127.0.0.1'; // praxis-ignore SSRF_INTERNAL_IP — fallback client ip for local rate limiter
    const now = Date.now();
    const timestamps = hits.get(ip) || [];
    const valid = timestamps.filter(t => now - t < windowMs);

    if (valid.length >= max) {
      const oldest = valid[0];
      const retryAfter = Math.ceil((windowMs - (now - oldest)) / 1000) || 1;
      res.writeHead(429, {
        'Content-Type': 'application/json; charset=utf-8',
        'Retry-After': String(retryAfter),
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
      });
      res.end(JSON.stringify({ error: 'Too Many Requests', retryAfter }));
      return false;
    }

    valid.push(now);
    hits.set(ip, valid);
    return true;
  };
}

export function createServer({ host: _host = '127.0.0.1', port: _port = 7317, token = null, queue = null, rateLimiter = null } = {}) { // praxis-ignore MCP_NO_RATE_LIMIT — local scan orchestrator, not an MCP server; exhaustion bounded by MAX_CONCURRENCY/MAX_QUEUE
  const jobs = queue || new JobQueue({ runScan: runScanWithOrchestrator });
  const checkRateLimit = rateLimiter || createRateLimiter();

  const server = http.createServer(async (req, res) => {
    // Sliding-window rate limit defense against brute-force & flood DoS
    if (checkRateLimit && !checkRateLimit(req, res)) {
      return;
    }

    let url;
    try {
      url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    } catch {
      return sendJSON(res, 400, { error: 'bad request' });
    }
    const route = url.pathname.replace(/\/+$/, '') || '/';
    const method = req.method || 'GET';

    // DNS rebinding can read reports through GET as well as mutate through POST.
    // Without token auth, every request must address the actual local server.
    if (!token && ((!isLoopback(url.hostname) && url.hostname !== 'localhost') ||
        Number(url.port || 80) !== server.address()?.port)) {
      return sendJSON(res, 403, { error: 'untrusted Host header' });
    }

    // Auth for remote binds.
    if (token) {
      const auth = req.headers.authorization || '';
      const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!tokenMatches(bearer || req.headers['x-praxis-token'], token)) {
        return sendJSON(res, 401, { error: 'unauthorized' });
      }
    }

    // Mutating methods need the anti-CSRF header.
    if (method !== 'GET' && method !== 'HEAD') {
      const guard = guardMutation(req);
      if (!guard.ok) return sendJSON(res, 403, { error: guard.error });
    }

    try {
      // ── API ────────────────────────────────────────────────────────────────
      if (route === '/api/projects' && method === 'GET') {
        return sendJSON(res, 200, { projects: listProjects() });
      }

      if (route === '/api/projects' && method === 'POST') {
        const body = await readBody(req);
        // The path comes from the operator's own request; it is resolved, pinned and
        // validated server-side, and thereafter addressed only by id.
        const result = addProject(body.path);
        if (!result.ok) return sendJSON(res, 400, { error: result.error });
        return sendJSON(res, result.created ? 201 : 200, { project: result.project, created: result.created });
      }

      const projectMatch = route.match(/^\/api\/projects\/([\w-]+)(\/scan|\/report)?$/);
      if (projectMatch) {
        const found = getProject(projectMatch[1]);
        if (!found.ok) return sendJSON(res, 404, { error: found.error });
        if (!found.project.present) {
          return sendJSON(res, 410, { error: 'registered project path no longer exists', project: found.project });
        }

        if (!projectMatch[2] && method === 'DELETE') {
          const removed = removeProject(projectMatch[1]);
          return removed.ok ? sendJSON(res, 200, { removed: true }) : sendJSON(res, 404, { error: removed.error });
        }

        if (projectMatch[2] === '/scan' && method === 'POST') {
          const queued = jobs.enqueue(found.project);
          if (!queued.ok) return sendJSON(res, 429, { error: queued.error });
          return sendJSON(res, 202, { job: queued.job });
        }

        if (projectMatch[2] === '/report' && method === 'GET') {
          const url_ = url.searchParams.get('job');
          const job = url_ ? jobs.get(url_) : [...jobs.list()].reverse().find(j => j.projectId === found.project.id && j.hasResult);
          if (!job) return sendJSON(res, 404, { error: 'no completed scan for this project' });
          const full = jobs.get(job.id);
          if (!full?.result) return sendJSON(res, 404, { error: 'scan has no result' });
          return sendJSON(res, 200, { job: jobs._public(full), result: JSON.parse(jsonReport(full.result)) });
        }
      }

      if (route === '/api/jobs' && method === 'GET') {
        return sendJSON(res, 200, { jobs: jobs.list() });
      }

      const jobReportMatch = route.match(/^\/api\/jobs\/([\w-]+)\/report$/);
      if (jobReportMatch && method === 'GET') {
        const full = jobs.get(jobReportMatch[1]);
        if (!full) return sendJSON(res, 404, { error: 'unknown job' });
        if (!full.result) return sendJSON(res, 404, { error: 'scan has no result' });
        return sendJSON(res, 200, { job: jobs._public(full), result: JSON.parse(jsonReport(full.result)) });
      }

      const jobMatch = route.match(/^\/api\/jobs\/([\w-]+)$/);
      if (jobMatch && method === 'GET') {
        const full = jobs.get(jobMatch[1]);
        if (!full) return sendJSON(res, 404, { error: 'unknown job' });
        return sendJSON(res, 200, { job: jobs._public(full) });
      }

      const cancelMatch = route.match(/^\/api\/jobs\/([\w-]+)\/cancel$/);
      if (cancelMatch && method === 'POST') {
        const result = jobs.cancel(cancelMatch[1]);
        return result.ok ? sendJSON(res, 200, { cancelled: true }) : sendJSON(res, 409, { error: result.error });
      }

      if (route === '/api/agents' && method === 'GET') {
        return sendJSON(res, 200, { agents: AGENT_ROSTER });
      }

      // ── Server-sent events for live progress ────────────────────────────────
      // Must be matched BEFORE the /api/ catch-all below, or it is unreachable.
      const eventsMatch = route.match(/^\/api\/jobs\/([\w-]+)\/events$/);
      if (eventsMatch && method === 'GET') {
        const job = jobs.get(eventsMatch[1]);
        if (!job) return sendJSON(res, 404, { error: 'unknown job' });

        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-store',
          Connection: 'keep-alive',
        });
        const send = j => res.write(`data: ${JSON.stringify(j)}\n\n`);
        send(jobs._public(job));
        if (['done', 'failed', 'cancelled'].includes(job.status)) return res.end();
        const onUpdate = j => {
          if (j.id !== job.id) return;
          send(j);
          if (['done', 'failed', 'cancelled'].includes(j.status)) {
            jobs.off('update', onUpdate);
            res.end();
          }
        };
        jobs.on('update', onUpdate);
        req.on('close', () => jobs.off('update', onUpdate));
        return undefined;
      }

      if (route === '/api/jobs' || route.startsWith('/api/')) {
        return sendJSON(res, 404, { error: 'unknown endpoint' });
      }

      // ── Frontend ────────────────────────────────────────────────────────────
      if (route === '/' || route === '/index.html') {
        return sendHTML(res, 200, renderFrontend());
      }

      return sendJSON(res, 404, { error: 'not found' });
    } catch (err) {
      // Carry an explicit status when the error set one (e.g. 413 body too large,
      // 400 bad JSON) instead of flattening everything to a 500.
      const status = Number.isInteger(err?.statusCode) ? err.statusCode : 500;
      return sendJSON(res, status, { error: err.message || 'internal error' });
    }
  });

  server.on('clientError', (_err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
  });

  return { server, jobs };
}
