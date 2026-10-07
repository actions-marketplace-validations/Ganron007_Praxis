/**
 * Shared HTML report theme — single source of truth for every Praxis HTML surface.
 * ============================================================================
 *
 * Extracted because `cli/agents/html-reporter.js` and
 * `cli/commands/team-report.js` each carried their own ~100-line inline stylesheet
 * and their own severity palette. Those palettes had already drifted
 * (`critical` was `#ef4444` in one and `#dc2626` in the other), so every brand or
 * styling fix had to be applied twice — and the two files disagreed on the same
 * concept.
 *
 * Also centralises the primitives that must never be re-implemented per report:
 *   - `esc()`               — HTML escaping. `team-report.js` previously had none and
 *                             interpolated finding text straight into markup, which is
 *                             an injection sink in a file users open in a browser.
 *   - `severityBadgeClass()` — maps a severity to a *known* CSS class, so an arbitrary
 *                             severity string can't be injected into a class attribute.
 *   - `countBySeverity()`    — one counting implementation, not one per report.
 *
 * Design constraints (per AGENTS.md): no build step, no bundler, no framework. These
 * are plain template strings and functions, so every report stays a single
 * self-contained offline HTML file.
 */

/** Severity → accent colour. Used for bars, legends, and inline accents. */
export const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#38bdf8',
  info: '#64748b',
};

/** Security-score letter grade → colour. */
export const GRADE_COLORS = {
  A: '#22c55e',
  B: '#06b6d4',
  C: '#eab308',
  D: '#f97316',
  F: '#ef4444',
};

/** Every severity we recognise, in report order. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/**
 * Severities rendered in distribution bars/legends. Includes `info` so the segments
 * always sum to 100% of the findings shown — omitting it left the bar visibly
 * under-filled whenever a scan produced informational findings.
 */
export const DISPLAY_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Escapes text for interpolation into HTML markup or a quoted attribute.
 * Null/undefined become an empty string so callers can interpolate directly.
 */
export function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Maps a severity to a known-safe CSS class suffix.
 *
 * Returns `''` for anything unrecognised so the result is always a safe subset of
 * the class attribute — a finding whose `severity` came from a parsed report file
 * must never be able to break out of `class="sev-badge …"`.
 */
export function severityBadgeClass(severity) {
  const key = String(severity || '').toLowerCase();
  return SEVERITIES.includes(key) || key === 'info' ? key : '';
}

/** Renders a severity badge span. Escapes the label and sanitises the class. */
export function severityBadge(severity, label) {
  const cls = severityBadgeClass(severity);
  const text = label ?? String(severity || 'unknown');
  const classes = cls ? `sev-badge sev-${cls}` : 'sev-badge';
  return `<span class="${classes}">${esc(text)}</span>`;
}

/** Counts findings per severity, always returning a fully-populated record. */
export function countBySeverity(findings = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of Array.isArray(findings) ? findings : []) {
    const key = String(f?.severity || '').toLowerCase();
    if (key in counts) counts[key]++;
  }
  return counts;
}

/**
 * The shared base stylesheet: reset, typography, layout container, tables, code,
 * severity badges, and the muted/empty/footer primitives. Every report includes
 * this, then appends its own component styles.
 */
export function baseStyles() {
  return `
      *{margin:0;padding:0;box-sizing:border-box}
      html{scroll-behavior:smooth}
      body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#090d16;color:#cbd5e1;line-height:1.55;font-size:14px}
      a{color:#38bdf8;text-decoration:none}
      a:hover{text-decoration:underline}

      .container{max-width:1440px;margin:1.8rem auto;padding:0 2rem}
      h1{font-size:1.8rem;font-weight:700;color:#f8fafc;margin-bottom:0.25rem}
      h2{font-size:1.1rem;font-weight:600;margin:2rem 0 1rem;color:#94a3b8;border-bottom:1px solid #1e293b;padding-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em}

      .table-responsive{overflow-x:auto}
      table{width:100%;border-collapse:collapse;font-size:0.86rem;text-align:left}
      th{background:#131d33;color:#94a3b8;padding:0.75rem 1rem;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.6px;border-bottom:1px solid #1e293b}
      td{padding:0.75rem 1rem;border-bottom:1px solid #172239;vertical-align:top}
      tr:hover td{background:#111b30}
      code{background:#050811;border:1px solid #1e293b;color:#7dd3fc;padding:2px 6px;border-radius:4px;font-size:0.8rem;word-break:break-word}
      small{color:#64748b}

      .sev-badge{display:inline-block;padding:3px 9px;border-radius:6px;font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:0.5px}
      .sev-critical{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}
      .sev-high{background:#431407;color:#fdba74;border:1px solid #9a3412}
      .sev-medium{background:#422006;color:#fde047;border:1px solid #854d0e}
      .sev-low{background:#082f49;color:#7dd3fc;border:1px solid #075985}
      .sev-info{background:#1e293b;color:#cbd5e1;border:1px solid #334155}

      .muted{color:#64748b}
      .ok{color:#6ee7b7}
      .fail{color:#fca5a5}
      .empty-state{text-align:center;color:#64748b;padding:2.5rem 1rem;font-size:0.9rem}
      .footer{text-align:center;padding:2.5rem 0 1.5rem;color:#64748b;font-size:0.8rem;border-top:1px solid #1e293b;margin-top:3rem}
      @media(max-width:1024px){.container{padding:0 1rem}}
    `;
}

/**
 * Wraps body markup in a complete, self-contained HTML document.
 *
 * `styles` is injected verbatim and must be trusted (it is always generated by
 * this module, never derived from scan findings). `body` and `title` are escaped.
 */
export function documentShell({ title, styles, body, bodyClass = '' }) {
  const cls = bodyClass ? ` class="${esc(bodyClass)}"` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>${styles}</style>
</head>
<body${cls}>
${body}
</body>
</html>`;
}
