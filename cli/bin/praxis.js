#!/usr/bin/env node

/**
 * Praxis CLI
 * ==========
 *
 * Canonical entry point. The 38 legacy `praxis` commands are reorganized
 * into six verb-led groups so a new user reading `--help` builds an accurate
 * mental model in 30 seconds:
 *
 *   praxis scan       run security scans
 *   praxis fix        apply remediations
 *   praxis agents     audit AI/agent surface (skills, MCP, attestation, BOM)
 *   praxis intel      threat-feed + advisory operations
 *   praxis report     format/diff/share existing scan results
 *   praxis project    init, hooks, watch, doctor, baseline, plugins, etc.
 *
 * Plus three top-level shortcuts that preserve the indie/vibe-coder voice:
 *   praxis vibe       emoji-graded score (A=immaculate, F=cooked)
 *   praxis score      numeric 0-100 score
 *   praxis            (no args) drops into the interactive REPL
 *
 * The legacy `praxis` binary continues to expose all 38 original commands
 * unchanged for back-compat — that surface lives in `cli/bin/praxis.js`.
 */

import { program } from 'commander';
import chalk from 'chalk';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

import { printBanner, TAGLINE, SUBTITLE } from '../core/branding.js';
import { toolVersion } from '../core/version.js';
import { loadDotEnv } from '../core/env.js';

// Load .env from the working directory early so API keys and LLM settings
// (OPENAI_API_KEY, OPENAI_BASE_URL, PRAXIS_LLM_MODEL, ...) are available to
// every command. Real environment variables always take precedence.
loadDotEnv(process.cwd());

// Existing command implementations (unchanged — praxis is a new surface,
// not a reimplementation).
import { scanCommand } from '../commands/scan.js';
import { checklistCommand } from '../commands/checklist.js';
import { initCommand } from '../commands/init.js';
import { fixCommand as legacyFixCommand } from '../commands/fix.js';
import { guardCommand } from '../commands/guard.js';
import { mcpCommand } from '../commands/mcp.js';
import { remediateCommand } from '../commands/remediate.js';
import { rotateCommand } from '../commands/rotate.js';
import { agentFixCommand } from '../commands/agent-fix.js';
import { undoCommand } from '../commands/undo.js';
import { shellCommand } from '../commands/shell.js';
import { depsCommand } from '../commands/deps.js';
import { scoreCommand } from '../commands/score.js';
import { redTeamCommand } from '../commands/red-team.js';
import { watchCommand } from '../commands/watch.js';
import { auditCommand } from '../commands/audit.js';
import { doctorCommand } from '../commands/doctor.js';
import { baselineCommand } from '../commands/baseline.js';
import { ciCommand } from '../commands/ci.js';
import { diffCommand } from '../commands/diff.js';
import { vibeCheckCommand } from '../commands/vibe-check.js';
import { webCommand } from '../commands/web.js';
import { rulesListCommand, rulesExportCommand, rulesImportCommand } from '../commands/rules.js';
import { benchmarkCommand } from '../commands/benchmark.js';
import { openclawCommand } from '../commands/openclaw.js';
import { scanSkillCommand } from '../commands/scan-skill.js';
import { scanMcpCommand } from '../commands/scan-mcp.js';
import { scanStandardCommand } from '../commands/scan-standard.js';
import { abomCommand } from '../commands/abom.js';
import { updateIntelCommand } from '../commands/update-intel.js';
import { hooksCommand } from '../commands/hooks.js';
import { legalCommand } from '../commands/legal.js';
import { runLiveAdvisories } from '../commands/live-advisories.js';
import { envAuditCommand } from '../commands/env-audit.js';
import { autofixCommand } from '../commands/autofix.js';
import { teamReportCommand } from '../commands/team-report.js';
import { redteamCommand } from '../commands/redteam.js';
import { memoryCommand } from '../utils/security-memory.js';
import { playbookCommand } from '../utils/scan-playbook.js';
import { listPluginFiles, scaffoldPlugin } from '../utils/plugin-loader.js';
import { SBOMGenerator } from '../agents/sbom-generator.js';
import { PolicyEngine } from '../agents/policy-engine.js';

// =============================================================================
// PROGRAM SETUP
// =============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const VERSION = toolVersion();

program
  .name('praxis')
  .description(`${TAGLINE} ${SUBTITLE}`)
  .version(VERSION)
  .addHelpText('before', renderHelpBanner());

function renderHelpBanner() {
  return [
    '',
    chalk.cyan('██████╗ ██████╗  █████╗ ██╗  ██╗██╗███████╗'),
    chalk.cyan('██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝██║██╔════╝'),
    chalk.cyan('██████╔╝██████╔╝███████║ ╚███╔╝ ██║███████╗'),
    chalk.cyan('██╔═══╝ ██╔══██╗██╔══██║ ██╔██╗ ██║╚════██║'),
    chalk.cyan('██║     ██║  ██║██║  ██║██╔╝ ██╗██║███████║'),
    chalk.cyan('╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝'),
    '',
    chalk.white.bold(`  ${TAGLINE}`),
    chalk.gray(`  ${SUBTITLE}`),
    '',
  ].join('\n');
}

// =============================================================================
// scan — run security scans
// =============================================================================

const scan = program
  .command('scan')
  .description('Run security scans (default = full audit)');

scan
  .command('full [path]', { isDefault: true })
  .description('Full audit: secrets + 28 agents + deps + score + remediation plan')
  .option('--trust-plugins', 'Execute trusted local .praxis/agents plugins with your permissions')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--csv', 'Output results as CSV')
  .option('--md', 'Output results as Markdown')
  .option('--html [file]', 'HTML report path (default: praxis-report.html)')
  .option('--html-dir [dir]', 'Generate granular multi-page report suite in directory')
  .option('--compare', 'Show detailed comparison with last scan')
  .option('--timeout <ms>', 'Per-agent timeout in milliseconds (default: 30000)', parseInt)
  .option('--no-deps', 'Skip dependency audit')
  .option('--no-ai', 'Skip AI classification')
  .option('--no-cache', 'Force full rescan')
  .option('--baseline', 'Only show findings not in the baseline')
  .option('--pdf [file]', 'Generate PDF report (requires Chrome/Chromium)')
  .option('--deep', 'LLM-powered taint analysis for critical/high findings')
  .option('--think', 'Enable extended thinking mode')
  .option('--local', 'Use local Ollama model for deep analysis')
  .option('--model <model>', 'LLM model for deep/AI analysis')
  .option('--provider <name>', 'LLM provider')
  .option('--base-url <url>', 'Custom OpenAI-compatible endpoint')
  .option('--budget <cents>', 'Max spend in cents for deep analysis (default: 50)', parseInt)
  .option('--verify', 'Check if leaked secrets are still active')
  .option('--include-legal', 'Also run the legal risk scan')
  .option('--agentic [iterations]', 'Agentic scan→fix→verify loop', (v) => v ? parseInt(v) : true)
  .option('--agentic-target <score>', 'Target security score for agentic loop', parseInt)
  .option('--hermes-only', 'Run only Hermes-relevant agents')
  .option('--fail-below <threshold>', 'Exit 1 if score is below threshold')
  .option('-b, --branch <name>', 'Git branch or tag to scan (when target is a Git URL)')
  .option('--depth <n>', 'Git clone depth (default: 1 for shallow clone, 0 for full history)', parseInt)
  .option('--git-token <token>', 'Auth token for private Git repositories (or set PRAXIS_GIT_TOKEN / GITHUB_TOKEN)')
  .option('--git-history', 'Include Git commit history secret scanning')
  .option('--keep-clone', 'Keep cloned repository on disk after scan instead of deleting')
  .option('--submodules', 'Recursively clone Git submodules')
  .option('-v, --verbose', 'Verbose output')
  .action(auditCommand);

scan
  .command('git <url>')
  .description('Direct remote Git repository audit: clone to secure temp workspace and scan')
  .option('-b, --branch <name>', 'Git branch or tag to clone and scan')
  .option('--depth <n>', 'Git clone depth (default: 1 for shallow clone)', parseInt)
  .option('--git-token <token>', 'Auth token for private repositories (or set PRAXIS_GIT_TOKEN / GITHUB_TOKEN)')
  .option('--git-history', 'Include Git commit history secret scanning')
  .option('--keep-clone', 'Keep cloned repository on disk after scan')
  .option('--submodules', 'Recursively clone Git submodules')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--csv', 'Output results as CSV')
  .option('--md', 'Output results as Markdown')
  .option('--html [file]', 'HTML report path (default: praxis-report.html)')
  .option('--no-deps', 'Skip dependency audit')
  .option('--no-ai', 'Skip AI classification')
  .option('--deep', 'LLM-powered taint analysis for critical/high findings')
  .option('-v, --verbose', 'Verbose output')
  .action((url, opts) => auditCommand(url, opts));

scan
  .command('repo <url>')
  .description('Alias for "praxis scan git <url>"')
  .option('-b, --branch <name>', 'Git branch or tag to clone and scan')
  .option('--depth <n>', 'Git clone depth (default: 1)', parseInt)
  .option('--git-token <token>', 'Auth token for private repositories')
  .option('--git-history', 'Include Git commit history secret scanning')
  .option('--keep-clone', 'Keep cloned repository on disk after scan')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--html [file]', 'HTML report path (default: praxis-report.html)')
  .option('--no-deps', 'Skip dependency audit')
  .option('-v, --verbose', 'Verbose output')
  .action((url, opts) => auditCommand(url, opts));

scan
  .command('secrets [path]')
  .description('Fast pattern-based secret scan only (no agents)')
  .option('-v, --verbose', 'Show all files being scanned')
  .option('--no-color', 'Disable colored output')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--include-tests', 'Also scan test files')
  .option('--no-cache', 'Force full rescan')
  .option('-b, --branch <name>', 'Git branch or tag to scan (when target is a Git URL)')
  .option('--depth <n>', 'Git clone depth (default: 1)', parseInt)
  .option('--git-token <token>', 'Auth token for private Git repositories')
  .option('--keep-clone', 'Keep cloned repository on disk after scan')
  .action(scanCommand);

scan
  .command('changed [ref]')
  .description('Scan only files changed since <ref> (default: HEAD)')
  .option('--staged', 'Scan only staged changes')
  .option('--json', 'Output results as JSON')
  .option('-p, --path <path>', 'Project path (default: cwd)')
  .option('--timeout <ms>', 'Per-agent timeout in milliseconds', parseInt)
  .action(diffCommand);

scan
  .command('env [path]')
  .description('Credential health check: .env coverage, source cross-ref, git history')
  .option('--json', 'Output results as JSON')
  .action(envAuditCommand);

scan
  .command('redteam [path]')
  .description('28 agents in parallel — adversarial scan of 80+ attack classes')
  .option('--agents <list>', 'Comma-separated list of agents to run')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--html [file]', 'Generate HTML security report')
  .option('--sbom [file]', 'Generate CycloneDX SBOM')
  .option('--no-deps', 'Skip dependency audit')
  .option('--no-ai', 'Skip AI classification')
  .option('--deep', 'LLM-powered taint analysis')
  .option('--swarm', 'AI swarm mode — 23 parallel agents via DeepSeek/Kimi')
  .option('--think', 'Enable extended thinking mode')
  .option('--local', 'Use local Ollama model')
  .option('--model <model>', 'LLM model')
  .option('--provider <name>', 'LLM provider')
  .option('--base-url <url>', 'Custom OpenAI-compatible endpoint')
  .option('--budget <cents>', 'Max spend in cents', parseInt)
  .option('-v, --verbose', 'Verbose output')
  .action(redTeamCommand);

scan
  .command('standard [name] [path]')
  .description('Filter findings by AI-security standard (owasp-llm, mitre-atlas, ...)')
  .option('--list', 'List available standards and exit')
  .option('--control <id>', 'Filter to a single control within the standard (e.g., LLM01)')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results in SARIF format')
  .option('--format <name>', 'Output format from the registry (json, sarif)')
  .action((name, targetPath, options) => scanStandardCommand(name, targetPath, options));

scan
  .command('ci [path]')
  .description('CI/CD pipeline mode: scan, score, exit 1 on failure')
  .option('--threshold <score>', 'Minimum passing score (default: 75)', parseInt)
  .option('--fail-on <severity>', 'Fail on findings at this severity or above')
  .option('--always-fail-on <severity>', 'Severity floor that even an accepted baseline cannot suppress')
  .option('--include-findings', 'Include the finding list (file/rule/severity) in JSON output for diffing')
  .option('--deep', 'Enable LLM deep analysis (requires an API key)')
  .option('--sarif <file>', 'Write SARIF output for GitHub Code Scanning')
  .option('--json', 'JSON output')
  .option('--no-deps', 'Skip dependency audit')
  .option('--baseline', 'Only check new findings (not in baseline)')
  .option('--github-pr', 'Post findings as a GitHub PR comment')
  .option('--strict-intel', 'Fail if threat-intel feed is stale')
  .option('--max-intel-age <duration>', 'Max acceptable intel age', '7d')
  .action(ciCommand);

// =============================================================================
// fix — apply remediations
// =============================================================================

const fix = program
  .command('fix')
  .description('Apply remediations (LLM-guided, deterministic, or PR-based)');

fix
  .command('interactive [path]', { isDefault: true })
  .description('Interactive LLM-guided fixes: scan → plan → diff → ask → apply → verify')
  .option('--plan-only', 'Generate plans for review but never write changes')
  .option('--severity <level>', 'Minimum severity to fix', 'low')
  .option('--provider <name>', 'LLM provider')
  .option('--model <model>', 'Specific model name')
  .option('--think', 'Enable extended thinking')
  .option('--allow-dirty', 'Allow running with uncommitted changes')
  .option('--branch [name]', 'Create a branch and commit one fix per file')
  .option('--pr', 'Push branch and open a PR via gh CLI (requires --branch)')
  .option('--yolo', 'Auto-accept every plan without prompting')
  .option('--auto-low', 'Auto-accept plans marked risk:low')
  .option('--sandbox', 'Verify each fix in a Docker sandbox')
  .option('--max-attempts <n>', 'Max plan attempts per file (verification ladder retries)', parseInt)
  .option('--ci', 'Non-interactive CI/CD mode (auto-accept fixes)')
  .action(agentFixCommand);

fix
  .command('quick [path]')
  .description('Deterministic secret fixer: rewrite source + write .env (no LLM)')
  .option('--dry-run', 'Preview changes without writing')
  .option('--yes', 'Apply all fixes without prompting')
  .option('--stage', 'Run git add on modified files')
  .option('--all', 'Also fix common agent findings (debug, TLS bypass, shell injection)')
  .action(remediateCommand);

fix
  .command('from-report [path]')
  .description('Apply LLM fixes from a deep-analysis JSON report and open a PR')
  .option('--report <file>', 'Path to praxis JSON report')
  .option('--severity <level>', 'Minimum severity to fix')
  .option('--dry-run', 'Preview without applying')
  .option('--yes', 'Skip confirmation')
  .action((targetPath, options) => autofixCommand({ ...options, path: targetPath }));

fix
  .command('rotate [path]')
  .description('Open provider dashboards to revoke exposed secrets')
  .option('--provider <name>', 'Only rotate secrets for a specific provider')
  .option('--plan <file>', 'Execute a rotation plan')
  .action(rotateCommand);

fix
  .command('undo [path]')
  .description('Revert the last fix applied by `praxis fix interactive` (or all with --all)')
  .option('--all', 'Revert every fix in the log')
  .option('--dry-run', 'Show what would be reverted')
  .action(undoCommand);

fix
  .command('env-template')
  .description('Generate a .env.example with placeholder values from found secrets')
  .option('--dry-run', 'Preview without writing')
  .action(legacyFixCommand);

// =============================================================================
// agents — AI-agent surface security
// =============================================================================

const agents = program
  .command('agents')
  .description('Audit the AI agent surface (configs, skills, MCP, attestation)');

agents
  .command('audit [path]', { isDefault: true })
  .description('Audit agent configs (CLAUDE.md, .cursorrules, MCP servers, skills)')
  .option('--fix', 'Auto-harden agent configurations')
  .option('--preflight', 'Exit non-zero on critical findings (for CI)')
  .option('--red-team', 'Simulate adversarial attacks against agent configs')
  .option('--json', 'Output results as JSON')
  .action(openclawCommand);

agents
  .command('skill [target]')
  .description('Vet an AI agent skill before installing it')
  .option('--all', 'Scan all skills defined in openclaw.json')
  .option('--json', 'Output results as JSON')
  .action(scanSkillCommand);

agents
  .command('mcp [target]')
  .description("Vet an MCP server's tool manifest before connecting")
  .option('--test-live', 'Perform runtime JSON-RPC handshakes and tool fuzzing')
  .option('--json', 'Output results as JSON')
  .action(scanMcpCommand);

agents
  .command('bom [path]')
  .description('Generate Agent Bill of Materials (CycloneDX ABOM)')
  .option('-o, --output <file>', 'Output file path', 'abom.json')
  .option('--json', 'Output to stdout as JSON')
  .action(abomCommand);

agents
  .command('serve')
  .description('Start praxis as an MCP server (Claude Desktop, Cursor, Windsurf)')
  .action(mcpCommand);

program
  .command('redteam [endpoint]')
  .description('Dynamic AI red teaming & behavioral prober for live LLM endpoints (DAST)')
  .option('--header <header>', 'Custom HTTP header (can specify multiple)')
  .option('--timeout <ms>', 'Timeout in ms (default: 10000)')
  .option('--json', 'Output results as JSON')
  .action(redteamCommand);

// =============================================================================
// intel — threat-intelligence operations
// =============================================================================

const intel = program
  .command('intel')
  .description('Threat-intelligence: feed updates, advisories, dependency CVEs');

intel
  .command('update')
  .description('Refresh threat intel: OSV, GHSA, KEV, EPSS, NVD, Gitleaks, +paid')
  .option('--only <sources>', 'Comma-separated subset (e.g. osv,kev,epss)')
  .option('--force', 'Ignore per-source TTL caches')
  .option('--list', 'Print available sources and exit')
  .action(updateIntelCommand);

intel
  .command('deps [path]')
  .description('Audit deps via package manager (npm/yarn/pnpm/pip-audit/bundler-audit)')
  .option('--fix', 'Run package manager fix command after auditing')
  .action(depsCommand);

intel
  .command('advisories [path]')
  .description('Check deps against live advisory feeds (OSV.dev, GitHub Advisories)')
  .option('--ecosystem <type>', 'Filter by ecosystem (npm, PyPI)')
  .option('--json', 'Output as JSON')
  .action(async (targetPath = '.', options) => {
    const absolutePath = resolve(targetPath);
    try {
      const result = await runLiveAdvisories(absolutePath, options);
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }
      console.log();
      console.log(chalk.cyan.bold('  Praxis — Live Advisories'));
      console.log(chalk.gray(`  Checked ${result.checked} dependencies against OSV.dev`));
      console.log();
      if (result.advisories.length === 0) {
        console.log(chalk.green('  ✔ No known advisories for your current dependency versions.\n'));
      } else {
        const malware = result.advisories.filter(a => a.isMalware);
        const vulns = result.advisories.filter(a => !a.isMalware);
        if (malware.length > 0) {
          console.log(chalk.red.bold(`  !! ${malware.length} MALWARE ADVISORY(S) FOUND`));
          for (const a of malware) {
            console.log(chalk.red(`     ${a.package}@${a.version} — ${a.id}: ${a.summary.slice(0, 80)}`));
          }
          console.log();
        }
        if (vulns.length > 0) {
          console.log(chalk.yellow(`  ${vulns.length} vulnerability advisory(s):`));
          for (const a of vulns) {
            const sev = a.severity === 'critical' ? chalk.red.bold(a.severity)
                      : a.severity === 'high' ? chalk.yellow(a.severity)
                      : chalk.blue(a.severity);
            console.log(`    ${sev} ${a.package}@${a.version} — ${a.id}`);
          }
          console.log();
        }
      }
    } catch (err) {
      console.error(chalk.red(`  Error: ${err.message}\n`));
      process.exit(1);
    }
  });

// =============================================================================
// report — format & share scan results
// =============================================================================

const report = program
  .command('report')
  .description('Format, diff, or share existing scan results');

report
  .command('team [file]')
  .description('Convert Hermes Agent team output into a Praxis report')
  .option('--html [path]', 'Save as HTML report')
  .option('--json', 'JSON output')
  .action(teamReportCommand);

report
  .command('legal [path]')
  .description('Legal risk audit: DMCA, leaked-source derivatives, IP disputes')
  .option('--json', 'Output results as JSON')
  .action(legalCommand);

report
  .command('checklist')
  .description('Run the launch-day security checklist interactively')
  .option('--no-interactive', 'Print checklist without prompts')
  .action(checklistCommand);

report
  .command('sbom [path]')
  .description('Generate Software Bill of Materials (CycloneDX SBOM)')
  .option('-o, --output <file>', 'Output file path', 'sbom.json')
  .action((targetPath = '.', options) => {
    const absolutePath = resolve(targetPath);
    const sbom = new SBOMGenerator();
    sbom.generateToFile(absolutePath, options.output);
    console.log(chalk.green(`✔ SBOM saved to ${options.output}`));
  });

report
  .command('benchmark [path]')
  .description('Compare your security score against industry averages')
  .option('--json', 'Output results as JSON')
  .action(benchmarkCommand);

// =============================================================================
// project — setup & state
// =============================================================================

const project = program
  .command('project')
  .description('Project setup, hooks, watch, doctor, baseline, plugins, policies');

project
  .command('init')
  .description('Initialize security configs in your project')
  .option('-f, --force', 'Overwrite existing files')
  .option('--gitignore', 'Only copy .gitignore')
  .option('--headers', 'Only copy security headers config')
  .option('--agents', 'Only add security rules to AI agent instruction files')
  .option('--openclaw', 'Generate a hardened openclaw.json template')
  .option('--hermes', 'Bootstrap Hermes Agent security config')
  .option('--from <url>', 'Fetch a pre-built Hermes config bundle from a setup URL')
  .action(initCommand);

project
  .command('doctor')
  .description('Diagnose environment: Node.js, git, API keys, cache, dependencies')
  .action(doctorCommand);

project
  .command('hooks [action]')
  .description('Manage Claude Code hooks — real-time security gate on tool calls')
  .action(hooksCommand);

project
  .command('guard [action]')
  .description('Install pre-commit/pre-push git hook to block secret commits')
  .option('--pre-commit', 'Install as pre-commit hook instead of pre-push')
  .option('--generate-hooks', 'Generate defensive Claude Code hooks')
  .action(guardCommand);

project
  .command('watch [path]')
  .description('Continuous monitoring: watch files for security issues in real-time')
  .option('--poll', 'Use polling mode')
  .option('--configs', 'Watch only agent config files')
  .option('--deep', 'Run full agent scanning on changes')
  .option('--stateful', 'Keep Kimi K2.6 conversation context between scans')
  .option('--model <model>', 'LLM model for stateful watch')
  .option('--provider <name>', 'LLM provider for stateful watch')
  .option('--status', 'Show current watch status and exit')
  .option('--threshold <score>', 'Alert when score drops below threshold', parseInt)
  .option('--debounce <ms>', 'Debounce interval in ms', parseInt)
  .option('--slack [webhook]', 'Post findings to Slack webhook URL')
  .option('--pr-comment', 'Post inline findings as GitHub PR review comments')
  .action(watchCommand);

project
  .command('baseline [path]')
  .description('Create/manage a findings baseline — only report new findings')
  .option('--diff', 'Show what changed since baseline')
  .option('--clear', 'Remove the baseline')
  .action(baselineCommand);

project
  .command('memory [subcommand]')
  .description('Manage false-positive memory (list / forget <key> / clear)')
  .argument('[args...]')
  .action((subcommand, args, options) => memoryCommand(subcommand, args, options));

project
  .command('playbook [subcommand]')
  .description('Manage repo-specific LLM context playbook (show / add-note "text")')
  .argument('[args...]')
  .action((subcommand, args, options) => playbookCommand(subcommand, args, options));

project
  .command('plugins [action]')
  .description('Manage custom security agent plugins from .praxis/agents/')
  .argument('[args...]')
  .action((action, args, options) => {
    const rootPath = resolve(process.cwd());
    if (action === 'new') {
      const pluginName = args?.[0] || 'my-rule';
      try {
        const filePath = scaffoldPlugin(rootPath, pluginName);
        console.log(chalk.green(`  ✔ Plugin scaffolded: ${filePath}`));
      } catch (err) {
        console.error(chalk.red(`  Error: ${err.message}`));
        process.exit(1);
      }
    } else {
      const plugins = listPluginFiles(rootPath);
      if (plugins.length === 0) {
        console.log('\n  No custom plugins found in .praxis/agents/');
        console.log(chalk.gray('  Create one with: praxis project plugins new my-rule\n'));
      } else {
        console.log(`\n  ${chalk.cyan.bold('Custom Plugins')} — ${plugins.length} found\n`);
        for (const p of plugins) {
          console.log(`  ${chalk.white(p.name)}  ${chalk.gray(`(${(p.size / 1024).toFixed(1)} KB)  ${p.path}`)}`);
        }
        console.log();
      }
    }
  });

project
  .command('policy <action>')
  .description('Manage security policies (init: create policy template)')
  .action((action) => {
    if (action === 'init') {
      const policyPath = PolicyEngine.generateTemplate(process.cwd());
      console.log(chalk.green(`✔ Policy template created: ${policyPath}`));
      console.log(chalk.gray('  Edit .praxis.policy.json to configure your security policy.'));
    } else {
      console.log(chalk.yellow(`Unknown policy action: ${action}. Use: policy init`));
    }
  });

// =============================================================================
// Top-level shortcuts (preserve indie voice)
// =============================================================================

const rules = program.command('rules').description('Inspect and export Praxis detection rules');

rules
  .command('list')
  .description('Summarise the rule inventory by source, severity and portability')
  .option('--json', 'Output results as JSON')
  .action(rulesListCommand);

rules
  .command('export')
  .description('Write a Semgrep-compatible rule bundle plus a portability manifest')
  .option('-o, --out <dir>', 'Output directory', 'praxis-rules')
  .option('--allow-invalid', 'Export even if some patterns fail validation', false)
  .action(rulesExportCommand);

rules
  .command('import <bundle>')
  .description('Load a Praxis portable rule bundle (JSON) and optionally emit a runnable plugin')
  .option('--write-plugin <dir>', 'Write a runnable plugin to this directory (e.g. .praxis/agents)')
  .option('--name <name>', 'Plugin class name prefix', 'PortableRules')
  .option('--json', 'Output results as JSON')
  .action(rulesImportCommand);

program
  .command('web')
  .description('Local web UI for scans and scan projects (read-only; loopback by default)')
  .option('--port <port>', 'Port to listen on', '7317')
  .option('--host <host>', 'Host to bind (non-loopback requires --allow-remote and --token)', '127.0.0.1')
  .option('--allow-remote', 'Permit a non-loopback bind (requires --token)', false)
  .option('--token <token>', 'Bearer token required for every request when remotely bound')
  .action(webCommand);

program
  .command('vibe [path]')
  .description('Vibe-graded security score with emoji and shareable badge')
  .option('--badge', 'Generate a shields.io markdown badge for your README')
  .action(vibeCheckCommand);

program
  .command('score [path]')
  .description('Compute a 0-100 security health score for your project')
  .option('--no-deps', 'Skip dependency audit')
  .action(scoreCommand);

program
  .command('hooks [action]')
  .description('Manage Claude Code hooks — real-time security gate on tool calls')
  .action(hooksCommand);

// =============================================================================
// Legacy top-level surface (back-compat)
// =============================================================================
// The original flat `praxis` command set is re-exposed here so existing docs,
// scripts, GitHub Actions, and Claude Code skills keep working unchanged.

const legacy = (name, description, flags) => {
  const cmd = program.command(name).description(description);
  for (const [flag, help, parse] of flags) {
    if (parse) cmd.option(flag, help, parse);
    else cmd.option(flag, help);
  }
  return cmd;
};

legacy('ci [path]', 'CI/CD mode: scan, score, exit 1 on failure (alias of `scan ci`)', [
  ['--threshold <score>', 'Minimum passing score (default: 75)', parseInt],
  ['--fail-on <severity>', 'Fail on findings at this severity or above'],
  ['--always-fail-on <severity>', 'Severity floor that even an accepted baseline cannot suppress'],
  ['--include-findings', 'Include the finding list (file/rule/severity) in JSON output for diffing'],
  ['--deep', 'Enable LLM deep analysis (requires an API key)'],
  ['--sarif <file>', 'Write SARIF output for GitHub Code Scanning'],
  ['--json', 'JSON output'],
  ['--no-deps', 'Skip dependency audit'],
  ['--baseline', 'Only check new findings (not in baseline)'],
  ['--github-pr', 'Post findings as a GitHub PR comment'],
  ['--strict-intel', 'Fail if threat-intel feed is stale'],
  ['--max-intel-age <duration>', 'Max acceptable intel age', undefined],
]).action(ciCommand);

legacy('audit [path]', 'Audit agent configs (CLAUDE.md, .cursorrules, MCP, skills) — alias of `agents audit`', [
  ['--trust-plugins', 'Execute trusted local .praxis/agents plugins with your permissions'],
  ['--fix', 'Auto-harden agent configurations'],
  ['--preflight', 'Exit non-zero on critical findings (for CI)'],
  ['--red-team', 'Simulate adversarial attacks against agent configs'],
  ['--json', 'Output results as JSON'],
]).action(openclawCommand);

legacy('openclaw [path]', 'Agent-config security audit (alias of `agents audit`)', [
  ['--fix', 'Auto-harden agent configurations'],
  ['--preflight', 'Exit non-zero on critical findings (for CI)'],
  ['--red-team', 'Simulate adversarial attacks against agent configs'],
  ['--json', 'Output results as JSON'],
]).action(openclawCommand);

legacy('scan-mcp [target]', 'Vet an MCP server tool manifest (alias of `agents mcp`)', [
  ['--json', 'Output results as JSON'],
]).action(scanMcpCommand);

legacy('mcp', 'Start praxis as an MCP server over stdio (alias of `agents serve`)', [])
  .action(mcpCommand);

legacy('scan-skill [target]', 'Vet an AI agent skill (alias of `agents skill`)', [
  ['--all', 'Scan all skills defined in openclaw.json'],
  ['--json', 'Output results as JSON'],
]).action(scanSkillCommand);

legacy('scan-standard [name] [path]', 'Filter findings by AI-security standard (alias of `scan standard`)', [
  ['--list', 'List available standards and exit'],
  ['--control <id>', 'Filter to a single control within the standard'],
  ['--json', 'Output results as JSON'],
  ['--sarif', 'Output results in SARIF format'],
  ['--format <name>', 'Output format from the registry (json, sarif)'],
]).action((name, targetPath, options) => scanStandardCommand(name, targetPath, options));

legacy('update-intel', 'Refresh threat intel feeds (alias of `intel update`)', [
  ['--only <sources>', 'Comma-separated subset (e.g. osv,kev,epss)'],
  ['--force', 'Ignore per-source TTL caches'],
  ['--list', 'Print available sources and exit'],
]).action(updateIntelCommand);

legacy('deps [path]', 'Audit dependency CVEs (alias of `intel deps`)', [
  ['--fix', 'Run package manager fix command after auditing'],
]).action(depsCommand);

legacy('advisories [path]', 'Check deps against live advisory feeds (alias of `intel advisories`)', [
  ['--ecosystem <type>', 'Filter by ecosystem (npm, PyPI)'],
  ['--json', 'Output as JSON'],
]).action(async (targetPath = '.', options) => {
  const absolutePath = resolve(targetPath);
  try {
    const result = await runLiveAdvisories(absolutePath, options);
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    console.log();
    console.log(chalk.cyan.bold('  Praxis — Live Advisories'));
    console.log(chalk.gray(`  Checked ${result.checked} dependencies against OSV.dev`));
    console.log();
    if (result.advisories.length === 0) {
      console.log(chalk.green('  ✔ No known advisories for your current dependency versions.\n'));
    } else {
      const malware = result.advisories.filter(a => a.isMalware);
      const vulns = result.advisories.filter(a => !a.isMalware);
      if (malware.length > 0) {
        console.log(chalk.red.bold(`  !! ${malware.length} MALWARE ADVISORY(S) FOUND`));
        for (const a of malware) {
          console.log(chalk.red(`     ${a.package}@${a.version} — ${a.id}: ${a.summary.slice(0, 80)}`));
        }
        console.log();
      }
      if (vulns.length > 0) {
        console.log(chalk.yellow(`  ${vulns.length} vulnerability advisory(s):`));
        for (const a of vulns) {
          const sev = a.severity === 'critical' ? chalk.red.bold(a.severity)
                    : a.severity === 'high' ? chalk.yellow(a.severity)
                    : chalk.blue(a.severity);
          console.log(`    ${sev} ${a.package}@${a.version} — ${a.id}`);
        }
        console.log();
      }
    }
  } catch (err) {
    console.error(chalk.red(`  Error: ${err.message}\n`));
    process.exit(1);
  }
});

legacy('remediate [path]', 'Deterministic secret fixer: rewrite source + write .env (alias of `fix quick`)', [
  ['--dry-run', 'Preview changes without writing'],
  ['--yes', 'Apply all fixes without prompting'],
  ['--stage', 'Run git add on modified files'],
  ['--all', 'Also fix common agent findings'],
]).action(remediateCommand);

legacy('rotate [path]', 'Open provider dashboards to revoke exposed secrets (alias of `fix rotate`)', [
  ['--provider <name>', 'Only rotate secrets for a specific provider'],
  ['--plan <file>', 'Execute a rotation plan'],
]).action(rotateCommand);

legacy('undo [path]', 'Revert the last fix (alias of `fix undo`)', [
  ['--all', 'Revert every fix in the log'],
  ['--dry-run', 'Show what would be reverted'],
]).action(undoCommand);

legacy('env-template', 'Generate .env.example from found secrets (alias of `fix env-template`)', [
  ['--dry-run', 'Preview without writing'],
]).action(legacyFixCommand);

legacy('red-team [path]', 'Adversarial agent pack scan (alias of `scan redteam`)', [
  ['--agents <list>', 'Comma-separated list of agents to run'],
  ['--json', 'Output results as JSON'],
  ['--sarif', 'Output results in SARIF format'],
  ['--html [file]', 'Generate HTML security report'],
  ['--sbom [file]', 'Generate CycloneDX SBOM'],
  ['--no-deps', 'Skip dependency audit'],
  ['--no-ai', 'Skip AI classification'],
  ['--deep', 'LLM-powered taint analysis'],
  ['--swarm', 'AI swarm mode via DeepSeek/Kimi'],
  ['--think', 'Enable extended thinking mode'],
  ['--local', 'Use local Ollama model'],
  ['--model <model>', 'LLM model'],
  ['--provider <name>', 'LLM provider'],
  ['--base-url <url>', 'Custom OpenAI-compatible endpoint'],
  ['--budget <cents>', 'Max spend in cents', parseInt],
  ['-v, --verbose', 'Verbose output'],
]).action(redTeamCommand);

legacy('abom [path]', 'Generate Agent Bill of Materials (alias of `agents bom`)', [
  ['-o, --output <file>', 'Output file path', undefined],
  ['--json', 'Output to stdout as JSON'],
]).action(abomCommand);

legacy('legal [path]', 'Legal risk audit (alias of `report legal`)', [
  ['--json', 'Output results as JSON'],
]).action(legalCommand);

legacy('team [file]', 'Convert Hermes Agent output into a Praxis report (alias of `report team`)', [
  ['--html [path]', 'Save as HTML report'],
  ['--json', 'JSON output'],
]).action(teamReportCommand);

legacy('checklist', 'Run the launch-day security checklist (alias of `report checklist`)', [
  ['--no-interactive', 'Print checklist without prompts'],
]).action(checklistCommand);

legacy('benchmark [path]', 'Compare your score against industry averages (alias of `report benchmark`)', [
  ['--json', 'Output results as JSON'],
]).action(benchmarkCommand);

legacy('init', 'Initialize security configs in your project (alias of `project init`)', [
  ['-f, --force', 'Overwrite existing files'],
  ['--gitignore', 'Only copy .gitignore'],
  ['--headers', 'Only copy security headers config'],
  ['--agents', 'Only add security rules to AI agent instruction files'],
  ['--openclaw', 'Generate a hardened openclaw.json template'],
  ['--hermes', 'Bootstrap Hermes Agent security config'],
  ['--from <url>', 'Fetch a pre-built Hermes config bundle from a setup URL'],
]).action(initCommand);

legacy('doctor', 'Diagnose environment (alias of `project doctor`)', []).action(doctorCommand);

legacy('baseline [path]', 'Manage findings baseline (alias of `project baseline`)', [
  ['--diff', 'Show what changed since baseline'],
  ['--clear', 'Remove the baseline'],
]).action(baselineCommand);

legacy('guard [action]', 'Install pre-commit/pre-push secret guard (alias of `project guard`)', [
  ['--pre-commit', 'Install as pre-commit hook instead of pre-push'],
  ['--generate-hooks', 'Generate defensive Claude Code hooks'],
]).action(guardCommand);

legacy('watch [path]', 'Continuous security monitoring (alias of `project watch`)', [
  ['--poll', 'Use polling mode'],
  ['--configs', 'Watch only agent config files'],
  ['--deep', 'Run full agent scanning on changes'],
  ['--stateful', 'Keep Kimi K2.6 conversation context between scans'],
  ['--model <model>', 'LLM model for stateful watch'],
  ['--provider <name>', 'LLM provider for stateful watch'],
  ['--status', 'Show current watch status and exit'],
  ['--threshold <score>', 'Alert when score drops below threshold', parseInt],
  ['--debounce <ms>', 'Debounce interval in ms', parseInt],
  ['--slack [webhook]', 'Post findings to Slack webhook URL'],
  ['--pr-comment', 'Post inline findings as GitHub PR review comments'],
]).action(watchCommand);

legacy('shell', 'Interactive REPL (same as `praxis` with no args on a TTY)', [])
  .action(() => shellCommand('.', {}).then(() => process.exit(0)).catch(() => process.exit(1)));

// =============================================================================
// PARSE AND RUN
// =============================================================================

if (process.argv.length === 2 && process.stdin.isTTY) {
  // No args + TTY → interactive REPL.
  shellCommand('.', {}).then(() => process.exit(0)).catch(() => process.exit(1));
} else if (process.argv.length === 2) {
  printBanner(VERSION);
  console.log(chalk.yellow('Quick start:\n'));
  console.log(chalk.white('  praxis scan .          ') + chalk.gray('# Full audit'));
  console.log(chalk.white('  praxis fix .           ') + chalk.gray('# Interactive LLM-guided fixes'));
  console.log(chalk.white('  praxis agents audit .  ') + chalk.gray('# Audit AI agent surface'));
  console.log(chalk.white('  praxis intel update    ') + chalk.gray('# Refresh threat intel'));
  console.log(chalk.white('  praxis project init    ') + chalk.gray('# Add security configs'));
  console.log(chalk.white('  praxis vibe .          ') + chalk.gray('# Emoji-graded score'));
  console.log(chalk.white('  praxis --help          ') + chalk.gray('# Show all groups'));
  console.log();
  console.log(chalk.gray('Migrating from `praxis`? Any legacy command (audit, ci, mcp, ...) still —'));
  console.log(chalk.gray('the `praxis` binary continues to work with full back-compat.'));
  console.log();
  process.exit(0);
} else {
  program.parse();
}
