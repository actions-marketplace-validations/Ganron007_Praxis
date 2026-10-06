/**
 * Endpoint Agent Abuse Agent
 * ==========================
 *
 * Static detection of local-AI-agent abuse techniques from the Endpoint AI
 * Agent Abuse (EAA) catalog — the attack surface where malware, malicious
 * packages, and repo-borne payloads compromise coding agents (Claude Code,
 * Cursor, Codex, Gemini CLI, etc.) through their config, hooks, MCP servers,
 * environment, and committed state.
 *
 * Techniques covered (see cli/data/eaa-catalog.json, CC0):
 *   EAA-001  Agent CLI invocation by untrusted parent (lifecycle scripts)
 *   EAA-002  Permissive or unattended agent execution (bypass flags)
 *   EAA-003  Lifecycle hook persistence (observed: Mini Shai-Hulud)
 *   EAA-005  Committed agent transcripts/state (secret-harvest surface)
 *   EAA-007  Hostile model/API gateway routing (base-URL overrides)
 *   EAA-008  Shadow agent config directory (CLAUDE_CONFIG_DIR overrides)
 *   EAA-011  Environment-expanded MCP activation (${VAR} in MCP config)
 *   EAA-012  Observability/logging exfiltration (OTEL endpoints)
 *
 * Rule confidence is backed by the catalog's evidence tier:
 *   observed / malicious-artifact → high, research / documented → medium.
 *
 * Complements (does not duplicate): AgentConfigScanner + MemoryPoisoningAgent
 * (instruction content), MCPSecurityAgent (MCP tool semantics).
 */

import fs from 'fs';
import path from 'path';
import fg from '../core/glob.js';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// FILE TARGETS
// =============================================================================

const HOOK_CONFIG_GLOBS = [
  '.claude/settings.json',
  '.claude/settings.local.json',
];

const MCP_CONFIG_GLOBS = [
  '.mcp.json',
  'mcp.json',
  '.cursor/mcp.json',
  'claude_desktop_config.json',
];

const ENV_FILE_GLOBS = [
  '.env', '.env.*', '*.env', '.envrc',
];

const SCRIPT_GLOBS = [
  '.github/workflows/*.yml', '.github/workflows/*.yaml',
  'Makefile', '*.mk',
  'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
  'scripts/**/*.sh', 'setup.sh', 'install.sh', 'bootstrap.sh',
];

const AGENT_STATE_GLOBS = [
  '.claude/projects/**/*.jsonl',
  '.claude/history.jsonl',
  '.claude/todos/**/*.jsonl',
];

// =============================================================================
// DETECTION LOGIC
// =============================================================================

// EAA-003: hook commands that fetch, decode, or execute opaque payloads
const HOOK_DANGEROUS_CMD = /(?:curl|wget|iwr|Invoke-WebRequest|nc\s|netcat|base64\s+-d|base64\s+--decode|\beval\b|bash\s+-c|sh\s+-c|powershell\s+-(?:e|enc)|npx\s|pip\s+install|pip3\s+install|\/tmp\/|%TEMP%|\$\{?TEMP\}?)/i;

// EAA-002: agent CLI bypass flags in checked-in automation
const PERMISSIVE_FLAGS = /--dangerously-skip-permissions|--yolo|--trust-all|--full-auto|--no-sandbox|--allow-all-tools/i;
const AGENT_CLI = /\b(?:claude|claude-code|codex|gemini|cursor-agent|opencode)\b/i;

// EAA-001: lifecycle script names in package.json
const LIFECYCLE_SCRIPTS = new Set(['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare']);

// EAA-011: env-var interpolation inside MCP config values
const ENV_EXPANSION = /\$\{([A-Z_][A-Z0-9_]*)\}/g;
const CREDENTIAL_VAR = /(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CRED|AWS_|GH_|GITHUB_|ANTHROPIC_|OPENAI_)/i;

// EAA-007: provider endpoint overrides
const GATEWAY_VARS = /^(?:ANTHROPIC_BASE_URL|ANTHROPIC_API_BASE|ANTHROPIC_AUTH_TOKEN|OPENAI_BASE_URL|OPENAI_API_BASE|GEMINI_API_BASE|GOOGLE_AI_BASE_URL)$/;
const KNOWN_ENDPOINTS = /(?:api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis\.com|localhost|127\.0\.0\.1|0\.0\.0\.0)/i;
const KNOWN_GATEWAYS = /(?:openrouter\.ai|together\.xyz|api\.groq\.com|api\.deepseek\.com|api\.moonshot\.ai|api\.mistral\.ai|api\.x\.ai|api\.perplexity\.ai|api\.cohere\.com|api\.fireworks\.ai|api\.together\.xyz)/i;

// EAA-012: telemetry/observability endpoints and raw-content logging
const TELEMETRY_VARS = /^(?:OTEL_EXPORTER_OTLP_ENDPOINT|OTEL_EXPORTER_OTLP_TRACES_ENDPOINT|CLAUDE_CODE_ENABLE_TELEMETRY|OTEL_LOG_TOOL_CONTENT|OTEL_LOG_PROMPTS)$/;

// EAA-008: alternate agent config directory overrides
const SHADOW_DIR_VARS = /^(?:CLAUDE_CONFIG_DIR|CURSOR_CONFIG_DIR|CODEX_CONFIG_DIR)$/;

// EAA-005: secret patterns worth escalating committed transcripts with
const TRANSCRIPT_SECRET = /(?:sk-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{30,}|xox[baprs]-[a-zA-Z0-9-]{10,})/;

const VAR_LINE = /^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*[=:]\s*(.*)$/;

// =============================================================================
// AGENT
// =============================================================================

export class EndpointAgentAbuseAgent extends BaseAgent {
  constructor() {
    super(
      'EndpointAgentAbuseAgent',
      'Detects local AI agent abuse techniques (EAA catalog): hook persistence, MCP env-expansion, gateway overrides, committed agent state',
      'agentic'
    );
  }

  shouldRun() {
    return true; // agent config surfaces exist in any modern repo
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    const opts = { cwd: rootPath, absolute: true, dot: true, onlyFiles: true };

    const hookFiles = await fg(HOOK_CONFIG_GLOBS, opts).catch(() => []);
    for (const f of hookFiles) findings.push(...this._scanHookConfig(f));

    const mcpFiles = await fg(MCP_CONFIG_GLOBS, opts).catch(() => []);
    for (const f of mcpFiles) findings.push(...this._scanMcpEnvExpansion(f));

    const pkgPath = path.join(rootPath, 'package.json');
    if (fs.existsSync(pkgPath)) findings.push(...this._scanPackageLifecycle(pkgPath));

    const scriptFiles = await fg(SCRIPT_GLOBS, opts).catch(() => []);
    for (const f of scriptFiles) findings.push(...this._scanScriptsForPermissiveAgent(f));

    const envFiles = await fg(ENV_FILE_GLOBS, opts).catch(() => []);
    for (const f of [...envFiles, ...scriptFiles]) findings.push(...this._scanEnvOverrides(f));

    const stateFiles = await fg(AGENT_STATE_GLOBS, opts).catch(() => []);
    for (const f of stateFiles) findings.push(...this._scanCommittedState(f, rootPath));

    return findings;
  }

  // -------------------------------------------------------------------------

  _scanHookConfig(file) {
    const findings = [];
    let settings;
    try {
      settings = JSON.parse(fs.readFileSync(file, 'utf-8'));
    } catch {
      return findings;
    }

    const hooks = settings?.hooks;
    if (!hooks || typeof hooks !== 'object') return findings;

    for (const [event, entries] of Object.entries(hooks)) {
      const commands = this._collectHookCommands(entries);
      for (const cmd of commands) {
        if (!HOOK_DANGEROUS_CMD.test(cmd)) continue;
        findings.push(createFinding({
          file, line: 1,
          severity: 'critical',
          category: this.category,
          rule: 'EAA_HOOK_SUSPICIOUS_COMMAND',
          title: `Agent Hook (${event}) Runs Suspicious Command`,
          description: `A ${event} agent hook executes a command that fetches, decodes, or runs opaque payloads. Malicious packages have planted SessionStart hooks for persistence (EAA-003, observed in the Mini Shai-Hulud incident).`,
          matched: cmd.slice(0, 200),
          confidence: 'high',
          cwe: 'CWE-506',
          owasp: 'ASI04',
          eaa: 'EAA-003',
          fix: 'Remove the hook or replace the command with a reviewed, pinned local script. Hooks should never fetch and execute remote content.',
        }));
      }
    }
    return findings;
  }

  _collectHookCommands(entries) {
    const commands = [];
    const walk = (node) => {
      if (!node) return;
      if (Array.isArray(node)) { node.forEach(walk); return; }
      if (typeof node === 'object') {
        if (typeof node.command === 'string') commands.push(node.command);
        for (const v of Object.values(node)) walk(v);
      }
    };
    walk(entries);
    return commands;
  }

  _scanMcpEnvExpansion(file) {
    const findings = [];
    let content;
    try {
      content = fs.readFileSync(file, 'utf-8');
      JSON.parse(content); // only well-formed config
    } catch {
      return findings;
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      ENV_EXPANSION.lastIndex = 0;
      let m;
      while ((m = ENV_EXPANSION.exec(lines[i])) !== null) {
        const varName = m[1];
        const credLike = CREDENTIAL_VAR.test(varName);
        findings.push(createFinding({
          file, line: i + 1,
          severity: credLike ? 'high' : 'medium',
          category: this.category,
          rule: 'EAA_MCP_ENV_EXPANSION',
          title: 'MCP Config Uses Environment Variable Expansion',
          description: `Checked-in MCP config interpolates \${${varName}} at activation time, so the server that actually starts depends on the victim machine's environment (EAA-011).${credLike ? ' The variable looks credential-bearing — a repo-shipped config can resolve to attacker-controlled values.' : ''}`,
          matched: m[0],
          confidence: 'medium',
          cwe: 'CWE-15',
          owasp: 'ASI04',
          eaa: 'EAA-011',
          fix: 'Pin literal commands/URLs in checked-in MCP config. If per-machine values are required, document the expansion and review what each variable can resolve to.',
        }));
      }
    }
    return findings;
  }

  _scanPackageLifecycle(file) {
    const findings = [];
    let pkg;
    try {
      pkg = JSON.parse(fs.readFileSync(file, 'utf-8'));
    } catch {
      return findings;
    }

    const scripts = pkg?.scripts || {};
    for (const [name, cmd] of Object.entries(scripts)) {
      if (!LIFECYCLE_SCRIPTS.has(name) || typeof cmd !== 'string') continue;
      if (!AGENT_CLI.test(cmd)) continue;
      findings.push(createFinding({
        file, line: 1,
        severity: 'medium',
        category: this.category,
        rule: 'EAA_AGENT_CLI_IN_LIFECYCLE',
        title: `Lifecycle Script "${name}" Invokes an AI Agent CLI`,
        description: `An npm lifecycle hook launches a coding-agent CLI. Package installs run without user review, making this a vector for driving a trusted agent from an untrusted parent (EAA-001, observed in the Nx s1ngularity and Trivy OpenVSX incidents).`, // praxis-ignore AGENT_RECURSIVE_INVOCATION — description of a finding this scanner emits, not an agent definition
        matched: cmd.slice(0, 200),
        confidence: 'medium',
        cwe: 'CWE-506',
        owasp: 'ASI04',
        eaa: 'EAA-001',
        fix: 'Remove agent invocations from lifecycle scripts. If automation is intended, run it as an explicit, reviewed step (CI job with approval), not an install side effect.',
      }));
    }
    return findings;
  }

  _scanScriptsForPermissiveAgent(file) {
    const findings = [];
    let content;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      return findings;
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!AGENT_CLI.test(line) || !PERMISSIVE_FLAGS.test(line)) continue;
      findings.push(createFinding({
        file, line: i + 1,
        severity: 'high',
        category: this.category,
        rule: 'EAA_PERMISSIVE_AGENT_INVOCATION',
        title: 'Checked-in Automation Runs an Agent with Permission Bypass',
        description: 'A repo script/CI step launches a coding agent with approval/sandbox bypass flags. Unattended permissive agents are the execution primitive behind agent-abuse campaigns (EAA-002, malicious-artifact evidence).',
        matched: line.trim().slice(0, 200),
        confidence: 'high',
        cwe: 'CWE-862',
        owasp: 'ASI02',
        eaa: 'EAA-002',
        fix: 'Drop bypass flags from checked-in automation. Use scoped permissions, an allowlisted tool set, and a human-approval step for anything sensitive.',
      }));
    }
    return findings;
  }

  _scanEnvOverrides(file) {
    const findings = [];
    let content;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      return findings;
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(VAR_LINE);
      if (!m) continue;
      const [, name, rawValue] = m;
      const value = rawValue.trim().replace(/^["']|["']$/g, '');

      if (GATEWAY_VARS.test(name) && value) {
        const known = KNOWN_ENDPOINTS.test(value) || KNOWN_GATEWAYS.test(value);
        findings.push(createFinding({
          file, line: i + 1,
          severity: known ? 'low' : 'medium',
          category: this.category,
          rule: 'EAA_PROVIDER_GATEWAY_OVERRIDE',
          title: 'AI Provider Endpoint Override',
          description: `${name} routes agent traffic to ${known ? 'a known gateway' : 'a non-vendor endpoint'}. Hostile routing points a trusted agent at an attacker-controlled gateway that can read or alter every prompt and response (EAA-007).${known ? ' Recognized gateway — verify it is intentional.' : ' Unrecognized host — verify before trusting.'}`,
          matched: `${name}=${value.slice(0, 120)}`,
          confidence: known ? 'low' : 'medium',
          cwe: 'CWE-441',
          owasp: 'ASI04',
          eaa: 'EAA-007',
          fix: 'Keep provider base URLs on vendor or explicitly approved gateway domains. Treat unexpected overrides in repo-shipped files as suspicious.',
        }));
      }

      if (TELEMETRY_VARS.test(name) && value) {
        const rawLogging = /OTEL_LOG_(?:TOOL_CONTENT|PROMPTS)/.test(name);
        findings.push(createFinding({
          file, line: i + 1,
          severity: rawLogging ? 'high' : 'medium',
          category: this.category,
          rule: 'EAA_TELEMETRY_EXTERNAL',
          title: rawLogging ? 'Raw Agent Content Logging to External Collector' : 'Agent Telemetry Endpoint Configured',
          description: rawLogging
            ? `${name} enables logging of raw prompts/tool content. Combined with an external collector this exfiltrates everything the agent sees (EAA-012).`
            : `${name} sends agent telemetry to ${value}. Prompts and tool output may include secrets and source code (EAA-012).`,
          matched: `${name}=${value.slice(0, 120)}`,
          confidence: 'medium',
          cwe: 'CWE-532',
          owasp: 'ASI03',
          eaa: 'EAA-012',
          fix: 'Point telemetry at an approved internal collector and disable raw prompt/tool-content logging unless explicitly required and reviewed.',
        }));
      }

      if (SHADOW_DIR_VARS.test(name) && value) {
        findings.push(createFinding({
          file, line: i + 1,
          severity: 'medium',
          category: this.category,
          rule: 'EAA_SHADOW_CONFIG_DIR',
          title: 'Agent Config Directory Override',
          description: `${name} redirects the agent to an alternate config directory. A shadow profile can carry attacker-controlled settings, hooks, and MCP servers past the user's normal environment (EAA-008).`,
          matched: `${name}=${value.slice(0, 120)}`,
          confidence: 'medium',
          cwe: 'CWE-15',
          owasp: 'ASI04',
          eaa: 'EAA-008',
          fix: 'Remove the override unless a reviewed workflow requires it. Never accept config-dir overrides from repo-shipped scripts or untrusted environments.',
        }));
      }
    }
    return findings;
  }

  _scanCommittedState(file, rootPath) {
    const findings = [];
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      return findings;
    }
    if (stat.size > 2 * 1024 * 1024) return findings; // skip huge transcripts

    let content;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      return findings;
    }

    const rel = path.relative(rootPath, file).replace(/\\/g, '/');
    const hasSecret = TRANSCRIPT_SECRET.test(content);
    findings.push(createFinding({
      file, line: 1,
      severity: hasSecret ? 'high' : 'medium',
      category: this.category,
      rule: 'EAA_COMMITTED_AGENT_STATE',
      title: hasSecret ? 'Committed Agent Transcript Contains Secrets' : 'Committed Agent Session State',
      description: hasSecret
        ? `Agent session state (${rel}) is committed and contains what looks like a live secret. Transcripts capture prompts, tool output, and credentials shown during sessions — a harvest target (EAA-005).`
        : `Agent session state (${rel}) is committed to the repo. Transcripts and history files capture prompts and tool output and are a collection target for agent-state harvesting (EAA-005).`,
      matched: rel,
      confidence: hasSecret ? 'high' : 'medium',
      cwe: 'CWE-538',
      owasp: 'ASI03',
      eaa: 'EAA-005',
      fix: 'Add agent state directories (.claude/, session logs) to .gitignore and purge them from history. Rotate any secret visible in the transcript.',
    }));
    return findings;
  }
}
