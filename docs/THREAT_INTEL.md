# Threat Intelligence — Praxis

This is the local quick reference for the multi-source threat-intel system that
powers `praxis scan`, `praxis intel deps`, the supply-chain agent, and every
other command that consumes the merged feed. It explains what each command
does, how the system is laid out internally, and what knobs you can turn.

For everything else (general CLI usage, scanning, hooks, etc.), see the main
[`README.md`](../README.md) and the full [`USAGE.md`](USAGE.md) reference.

---

## 1. Commands

Feed-update commands store caches under `~/.praxis/`. Scan commands also read
the selected project and can update its local Praxis state. Updates contact
configured remote sources; cached data is not a guarantee of current coverage.

| Command | What it does |
| --- | --- |
| `praxis intel update` | Refresh every configured source in parallel |
| `praxis intel update --list` | List all available sources and which are active |
| `praxis intel update --only osv,kev,epss` | Refresh a subset (comma-separated names) |
| `praxis intel update --force` | Ignore per-source TTL caches and re-fetch |
| `praxis scan ci .` | Normal CI run (does not enforce intel freshness) |
| `praxis scan ci . --strict-intel` | Fail CI if the merged feed is stale or core sources errored |
| `praxis scan ci . --strict-intel --max-intel-age 24h` | Custom freshness window (`7d`, `24h`, `30m`, `60s`) |

`praxis intel update` is safe to run any time — it caches per source and falls
back to the last good payload if a source is offline. Stale data is preferred
over no data.

### First-time setup

```bash
# Pull every free source. No keys required.
praxis intel update
```

Illustrative output (versions and counts depend on the fetched feeds):

```
  Fetching sources...

    osv           OK
    ghsa          OK
    kev           OK
    epss          OK
    nvd           OK
    gitleaks      OK
    snyk          skipped (SNYK_TOKEN not set)
    socket        skipped (SOCKET_API_KEY not set)
    ...

  Merged feed v1.0.1 written.

  Indicators loaded:
    CVE advisories:   ...
    KEV entries:      1586
    EPSS scores:      ...
    Extra secret rules: 221
```

### CI usage

```bash
# Soft mode — runs even if the feed is missing.
praxis scan ci .

# Hard mode — fails the build if intel is older than 7 days
# or any core source erred on the last update.
praxis scan ci . --strict-intel
```

---

## 2. Architecture

```
cli/
├── bin/
│   └── praxis.js                 # CLI entry; defines update-intel + ci flags
├── commands/
│   ├── update-intel.js           # User-facing command (progress, summary)
│   └── ci.js                     # Reads intel-meta.json, applies strict-intel
├── utils/
│   ├── threat-intel.js           # ThreatIntel class — query API
│   └── intel/
│       ├── index.js              # runUpdate() orchestrator + isStale()
│       ├── cache.js              # Per-source TTL'd disk cache
│       ├── http.js               # safeFetch (timeout + retry + backoff)
│       ├── merge.js              # mergeIntel(seed, results) → unified schema
│       └── sources/
│           ├── osv.js            # core
│           ├── ghsa.js           # core
│           ├── kev.js            # core
│           ├── epss.js           # core
│           ├── nvd.js            # core
│           ├── gitleaks.js       # core
│           ├── snyk.js           # optional
│           ├── socket.js         # optional
│           ├── gitguardian.js    # optional
│           ├── sonatype.js       # optional (works anonymously, env raises limits)
│           └── phylum.js         # optional
└── agents/
    └── supply-chain-agent.js     # Consumes ThreatIntel.lookupOsv / lookupGhsa,
                                  # enriches findings with KEV/EPSS signals
```

### Update flow

1. `praxis intel update` calls `runUpdate()` in `cli/utils/intel/index.js`.
2. **Pass 1** — every source except NVD runs in parallel via `Promise.all`.
   - Each source first checks `cache.read(name)`. If the cache is fresh
     (within its TTL), it's reused and `'cached'` is reported.
   - Otherwise it calls `source.fetchAll()`, writes the result to
     `~/.praxis/intel/<name>.json`, and reports `'ok'`.
   - On fetch error, the source falls back to whatever's in the cache
     (even if stale) so a transient outage doesn't blow away your data.
   - Optional sources without their env var return `{ skipped: true }` and
     are reported `'skipped'`.
3. **Pass 2** — NVD runs after Pass 1, using the union of CVEs collected from
   OSV/GHSA/KEV to decide which CVE descriptions to fetch (capped at 500).
4. `mergeIntel(seed, results)` produces the unified feed. Internal merge
   functions per source build:
   - `osvIndex[ecosystem/package]` → array of advisories
   - `ghsaIndex[ecosystem/package]` → array of advisories
   - `cveAdvisories[]` (deduplicated by CVE)
   - `kevList[]`, `kevDetails{}`, `epssScores{}`, `nvdDetails{}`
   - `secretRules[]` (Gitleaks regex rules)
   - `sources{}` (per-source status / stats / error)
5. The merged feed is written to `~/.praxis/threat-intel.json` and a
   summary to `~/.praxis/intel-meta.json`.

### Query flow

`ThreatIntel` (in `cli/utils/threat-intel.js`) lazy-loads the merged feed once
and caches it in memory. Resolution order:

1. `~/.praxis/threat-intel.json` (merged feed)
2. `cli/data/threat-intel.json` (bundled seed)

Public API (used by agents and scanners):

```js
ThreatIntel.lookupOsv(pkg, version, ecosystem)   // → [{...advisory, isAffected}]
ThreatIntel.lookupGhsa(pkg, ecosystem)
ThreatIntel.getEpss(cve)                          // → {score, percentile} | null
ThreatIntel.isInKev(cve)                          // → bool
ThreatIntel.getKevDetails(cve)
ThreatIntel.getNvdDetail(cve)
ThreatIntel.getExtraSecretRules()                 // → [{id, regex, ...}]
ThreatIntel.stats()                               // → counts for each indicator
ThreatIntel.isStale(maxAgeMs)
```

### File layout (on disk)

```
~/.praxis/
├── intel/
│   ├── osv.json          # raw per-source payload + fetchedAt + ttlMs
│   ├── ghsa.json
│   ├── kev.json
│   └── ...
├── threat-intel.json     # merged feed (everything joined into one file)
└── intel-meta.json       # { updatedAt, version, sources: {...} }
```

You can delete any of these to force a clean re-fetch. They will be recreated
on the next `praxis intel update` run.

---

## 3. Customization

### Sources

| Source | Tier | Env var | TTL | Notes |
| --- | --- | --- | --- | --- |
| `osv` | core | — | 12h | OSV.dev queries (npm, PyPI, Go, Maven, NuGet, RubyGems...) |
| `ghsa` | core | `GITHUB_TOKEN` or `GH_TOKEN` *(optional, raises rate limit)* | 12h | GitHub Advisory DB |
| `kev` | core | — | 24h | CISA Known Exploited Vulnerabilities |
| `epss` | core | — | 24h | FIRST.org exploit-likelihood scores |
| `nvd` | core | `NVD_API_KEY` *(optional, faster requests)* | 7d | CVE detail enrichment |
| `gitleaks` | core | — | 7d | Gitleaks regex rule set |
| `threatpack` | core | — (override with `PRAXIS_THREATPACK_URL`) | 7d | Praxis AI attack-vector signature pack — prompt-injection probes, EAA additions, model-gateway allowlists. Bundled seed at `cli/data/threatpacks/latest.json`; a fetch failure degrades to the seed |
| `snyk` | optional | `SNYK_TOKEN` (+ `SNYK_ORG_ID`) | 12h | Snyk Vulnerability DB |
| `socket` | optional | `SOCKET_API_KEY` | 6h | Socket.dev supply-chain risk |
| `gitguardian` | optional | `GITGUARDIAN_API_KEY` | 7d | GitGuardian secret detector defs |
| `sonatype` | optional | `SONATYPE_USER` + `SONATYPE_TOKEN` *(works anonymously too)* | 12h | OSS Index |
| `phylum` | optional | `PHYLUM_API_KEY` | 6h | Phylum supply-chain risk |

Without any env vars the system fully works using the seven core sources. Optional
sources gracefully report `skipped` and don't fail the run.

### Environment variables

```bash
# Optional — speeds up GHSA and NVD by raising rate limits.
export GITHUB_TOKEN=ghp_...
export NVD_API_KEY=...

# Optional paid sources — enable any subset by setting the corresponding key.
export SNYK_TOKEN=...
export SNYK_ORG_ID=...
export SOCKET_API_KEY=...
export GITGUARDIAN_API_KEY=...
export SONATYPE_USER=...
export SONATYPE_TOKEN=...
export PHYLUM_API_KEY=...
```

After setting an env var, run `praxis intel update --list` to confirm it
shows up as `[active]`.

### Tuning freshness

Per-source TTLs are constants at the top of each
`cli/utils/intel/sources/<name>.js` file (see the table above). To shorten the
TTL — e.g. fetch KEV every 6 hours instead of 24 — edit `kev.js`:

```js
const TTL_MS = 6 * 60 * 60 * 1000;
```

### CI freshness gate

```bash
praxis scan ci . --strict-intel --max-intel-age 24h
```

Accepted duration formats: `7d`, `24h`, `30m`, `60s`. Default is `7d`. The
gate fails if either:
- `~/.praxis/intel-meta.json` is missing or older than the threshold, **or**
- any **core** source's last update errored without a stale-cache fallback.

Optional/paid sources never fail the gate — only core sources do.

### Adding a custom source

A source is just an ES module that exports five things:

```js
// cli/utils/intel/sources/my-source.js
export const name = 'mysource';
export const tier = 'optional';                       // 'core' or 'optional'
export const description = 'My custom advisory feed';
export const envKey = 'MYSOURCE_API_KEY';             // optional
export const TTL = 6 * 60 * 60 * 1000;                // 6h

export async function fetchAll(args) {
  const key = process.env.MYSOURCE_API_KEY;
  if (!key) return { skipped: true, reason: 'MYSOURCE_API_KEY not set' };
  // ...fetch and return a payload...
  return { records: [...] };
}
```

Then register it in `cli/utils/intel/index.js`:

```js
import * as mysource from './sources/my-source.js';
const ALL_SOURCES = [..., mysource];
```

If you want the merger to do something special with the payload (e.g. populate
`osvIndex`), add a case for `name === 'mysource'` in `cli/utils/intel/merge.js`.
Otherwise it'll just appear under `sources.mysource` in the merged feed without
contributing to any index.

### Reset everything

```bash
rm -rf ~/.praxis/intel ~/.praxis/threat-intel.json ~/.praxis/intel-meta.json
praxis intel update
```

This wipes all caches and the merged feed. The bundled seed at
`cli/data/threat-intel.json` is untouched, so scanning still works in the
window between deletion and the next update.

---

## 4. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Indicators loaded: 0` after a successful update | The in-memory `ThreatIntel` cache wasn't invalidated — re-run the command, or restart the process. |
| `praxis intel update` is slow | NVD is rate-limited (6s between requests without a key). Set `NVD_API_KEY` to drop to 600ms. |
| GHSA reports `error: HTTP 403` | Set `GITHUB_TOKEN` to lift the unauthenticated rate limit. |
| A source reports `error` but the run still succeeds | By design — the orchestrator falls back to the cached payload. Check `~/.praxis/intel/<source>.json` for the last known good copy. |
| `praxis scan ci --strict-intel` fails locally | Run `praxis intel update` first. The freshness window defaults to 7 days. |
| Feed lives somewhere else | `~/.praxis/` is derived from `os.homedir()`. Override `HOME` (Unix) or `USERPROFILE` (Windows) to relocate it (this is how the test suite isolates state). |
