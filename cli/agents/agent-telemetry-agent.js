/**
 * Agent Telemetry Agent — AI Agent Session Audit Scanner
 * =======================================================
 *
 * Audits workspace and developer environment AI agent session histories
 * (Claude Code, Cursor IDE, Codex CLI, Warp Terminal, Cline) for security hazards:
 *   1. Plaintext secrets / API keys embedded in chat transcripts
 *   2. Unverified or dangerous shell execution logs (curl | bash, rm -rf, reverse shells)
 *   3. Prompt injection payloads in agent interaction trails
 *   4. LLM-output exfiltration signatures (EchoLeak-class: zero-width/bidi stego,
 *      encoded URL params, base64 blocks, JWT/PEM/bearer leaks)
 *   5. Session forensics (tool-result errors, permission-mode escalation,
 *      sub-agent sidechains, transcript tampering/parse errors)
 *
 * Maps to: OWASP Agentic AI ASI01 (Prompt Injection), ASI02 (Tool Misuse),
 *          ASI05 (Credential Exposure), ASI03 (Data Compromise).
 *
 * Data-model notes (asftriage-derived): Claude Code transcripts are JSONL
 * records { type, uuid, parentUuid, timestamp, sessionId, isSidechain?,
 * message: { role, content } }; Codex rollout sessions are typed envelopes
 * { timestamp, type, payload }. Never silently drop unknown record types —
 * surface them as generic evidence.
 */

import fs from 'fs';
import { BaseAgent, createFinding, ruleTableLineMask } from './base-agent.js';
import { isDocumentedSecretExample } from '../utils/entropy.js';

// =============================================================================
// PATTERNS & REGEXES
// =============================================================================

export const SECRET_PATTERNS = [
  {
    rule: 'AGENT_LOG_EXPOSED_OPENAI_KEY',
    title: 'Exposed OpenAI API Key in Agent Session History',
    regex: /sk-(?:proj-)?[a-zA-Z0-9_-]{32,90}/g,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    description: 'Plaintext OpenAI API key detected inside AI agent conversation history or execution log.',
    fix: 'Remove secret from session logs and rotate the compromised credential immediately.',
  },
  {
    rule: 'AGENT_LOG_EXPOSED_ANTHROPIC_KEY',
    title: 'Exposed Anthropic API Key in Agent Session History',
    regex: /sk-ant-api03-[a-zA-Z0-9_-]{40,90}/g,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    description: 'Plaintext Anthropic API key detected inside AI agent conversation history.',
    fix: 'Revoke the Anthropic key and ensure agent logs are scrubbed before storage.',
  },
  {
    rule: 'AGENT_LOG_EXPOSED_GITHUB_TOKEN',
    title: 'Exposed GitHub Access Token in Agent Log',
    regex: /gh[po]_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    description: 'GitHub Personal Access Token or OAuth token detected in agent session state.',
    fix: 'Revoke the token in GitHub settings and purge telemetry logs.',
  },
  {
    rule: 'AGENT_LOG_EXPOSED_AWS_KEY',
    title: 'Exposed AWS Access Key in Agent Log',
    regex: /A[KS]IA[0-9A-Z]{16}/g,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    description: 'AWS Access Key ID (AKIA long-term or ASIA session token) detected in agent transcript.',
    fix: 'Invalidate AWS credentials and configure secret masking in agent tools.',
  },
];

const HAZARDOUS_CMD_PATTERNS = [
  {
    rule: 'AGENT_LOG_PIPE_REMOTE_SHELL',
    title: 'Piped Remote Shell Execution in Agent History',
    regex: /(?:curl|wget)\s+-[^\n|]*\|\s*(?:bash|sh|powershell)/gi,
    severity: 'high',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Agent session recorded execution of remote shell script pipe (curl | bash).',
    fix: 'Audit agent command execution policies to disallow arbitrary unverified pipe scripts.',
  },
  {
    rule: 'AGENT_LOG_RECURSIVE_DESTRUCTION',
    title: 'Destructive File Deletion in Agent Log',
    regex: /rm\s+-rf\s+[/~]/gi,
    severity: 'high',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Agent session recorded execution of recursive destructive command (rm -rf / or ~).',
    fix: 'Enforce workspace path boundaries on agent tool executions.',
  },
];

const PROMPT_INJECTION_PATTERNS = [
  {
    rule: 'AGENT_LOG_PROMPT_OVERRIDE',
    title: 'Prompt Injection Override Payload in Transcript',
    regex: /ignore\s+(?:all\s+)?previous\s+instructions/gi,
    severity: 'high',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'Agent conversation history contains explicit prompt injection override directive.',
    fix: 'Sanitize incoming tool outputs and user inputs before injecting into context window.',
  },
];

// LLM-output exfiltration signatures (EchoLeak-class; derived from the
// MIT-licensed exfil-scan rule set).
const EXFIL_PATTERNS = [
  {
    rule: 'AGENT_LOG_ZERO_WIDTH_TEXT',
    title: 'Invisible Text in Agent Transcript (EchoLeak class)',
    // eslint-disable-next-line no-misleading-character-class -- deliberate invisible-char detection
    regex: /[\u200B\u200C\u200D\uFEFF\u2060\u180E]/g,
    severity: 'high',
    cwe: 'CWE-506',
    owasp: 'ASI03',
    description: 'Agent transcript contains zero-width/invisible Unicode characters — the canonical EchoLeak / CVE-2025-32711-class hidden-payload signature. A leading BOM (U+FEFF) at file start is benign; mid-text occurrences are steganography.',
    fix: 'Strip invisible characters from prompt-facing content. Inspect with a hex viewer.',
  },
  {
    rule: 'AGENT_LOG_BIDI_CONTROL',
    title: 'Bidi Control Character in Agent Transcript',
    regex: /[\u202A-\u202E\u2066-\u2069]/g,
    severity: 'high',
    cwe: 'CWE-94',
    owasp: 'ASI01',
    description: 'Agent transcript contains bidi control characters (RLO/LRI/PDI/FSI) used to visually reorder hidden instructions or filenames.',
    fix: 'Strip bidi controls from untrusted content and from displayed paths.',
  },
  {
    rule: 'AGENT_LOG_JWT_TOKEN',
    title: 'JWT Token Leaked in Agent Transcript',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    severity: 'high',
    cwe: 'CWE-200',
    owasp: 'ASI05',
    description: 'A three-segment JWT appears in the transcript — session/auth tokens pasted into prompts or returned by tools.',
    fix: 'Revoke the token and scrub the transcript. Mask tool outputs that may contain credentials.',
  },
  {
    rule: 'AGENT_LOG_SECRET_KV',
    title: 'Credential Assignment Detected in Agent Transcript',
    regex: /\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*["']?([^\s"',;]{8,})/gi,
    severity: 'high',
    cwe: 'CWE-522',
    owasp: 'ASI05',
    description: 'A key=value credential assignment appears in the transcript. Placeholders (REDACTED, <your-...>, changeme, example, ***) are excluded.',
    fix: 'Verify whether the value is a live credential; rotate if so. Mask assignments in future tool output.',
  },
  {
    rule: 'AGENT_LOG_BEARER_TOKEN',
    title: 'Authorization Bearer Token in Agent Transcript',
    regex: /\b(?:Bearer|Authorization:?)\s+[A-Za-z0-9._-]{16,}/gi,
    severity: 'high',
    cwe: 'CWE-200',
    owasp: 'ASI05',
    description: 'A Bearer/Authorization header token appears in the transcript — typically from curl/httpie commands in tool inputs or outputs.',
    fix: 'Rotate the token. Redact Authorization headers from command logs.',
  },
  {
    rule: 'AGENT_LOG_ENCODED_URL_PARAM',
    title: 'Encoded Payload in URL Parameter (Agent Transcript)',
    regex: /https?:\/\/[^\s<>\]\)]+\?[^&\s]*=[A-Za-z0-9+/]{40,}/g,
    severity: 'medium',
    cwe: 'CWE-201',
    owasp: 'ASI03',
    description: 'A URL in the transcript carries a long base64-looking query parameter — a common exfiltration carrier in tool output and citations.',
    fix: 'Review the URL. Long encoded query values should not leave the environment.',
  },
  {
    rule: 'AGENT_LOG_BASE64_BLOCK',
    title: 'Large Base64 Block in Agent Transcript',
    regex: /(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){8,}(?:==|=)?(?![A-Za-z0-9+/=])/g,
    severity: 'medium',
    cwe: 'CWE-506',
    owasp: 'ASI03',
    description: 'A 32+ character base64 block appears outside code fences — possible encoded payload. Verify before treating as benign.',
    fix: 'Decode and inspect the block. Apply output filtering for encoded payloads.',
  },
];

const PLACEHOLDER_VALUE = /^(?:REDACTED|\*{2,}|<[^>]{1,40}>|changeme|change_me|example|your[-_ ].*|xxx+|dummy|placeholder|not[_-]?a[_-]?(?:real|valid)[_-]?.*|sk-(?:test|demo))$/i;

// Whole-file patterns (multiline)
const WHOLE_FILE_PATTERNS = [
  {
    rule: 'AGENT_LOG_PEM_PRIVATE_KEY',
    title: 'Private Key Material in Agent Transcript',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,8000}?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    severity: 'critical',
    cwe: 'CWE-320',
    owasp: 'ASI05',
    description: 'A PEM-encoded private key block appears in the transcript. The most severe form of credential exposure in agent telemetry.',
    fix: 'Revoke the key immediately and purge the transcript from all retention.',
  },
];

// Structural JSONL forensics (asftriage-derived signals)
const FORENSIC_CHECKS = {
  // Claude Code: tool_result with is_error, or shell exit code != 0
  shellError(rec) {
    if (rec?.type === 'user' && Array.isArray(rec?.message?.content)) {
      for (const block of rec.message.content) {
        if (block?.type === 'tool_result' && block.is_error) return block;
      }
    }
    if (rec?.type === 'tool_result' && rec?.is_error) return rec;
    return null;
  },
  // Claude Code v2: permission-mode escalation records
  permissionMode(rec) {
    if (rec?.type !== 'permission-mode') return null;
    const raw = JSON.stringify(rec);
    if (/bypassPermissions|acceptEdits|"mode"\s*:\s*"(?:bypassPermissions|acceptEdits|dontAsk|plan)"/i.test(raw)) return raw;
    return null;
  },
  // Sub-agent sidechain records (activity hidden from the main timeline)
  sidechain(rec) {
    if (rec?.isSidechain === true) return rec;
    return null;
  },
};

// =============================================================================
// AGENT CLASS
// =============================================================================

export class AgentTelemetryAgent extends BaseAgent {
  constructor() {
    super(
      'AgentTelemetryAgent',
      'Audits AI agent session histories and telemetry logs for credentials, hazardous executions, injection trails, exfiltration signatures, and session forensics',
      'agentic-security'
    );
  }

  /**
   * Run telemetry analysis over codebase and agent session artifacts.
   */
  async analyze(context) {
    const findings = [];
    const { files = [] } = context;

    for (const filePath of files) {
      const lower = filePath.toLowerCase();
      const isAgentArtifact =
        lower.includes('.claude/') ||
        lower.includes('.cursor/') ||
        lower.includes('.codex/') ||
        lower.includes('.cline/') ||
        lower.includes('.warp/') ||
        lower.endsWith('.jsonl') ||
        lower.endsWith('.vscdb') ||
        lower.includes('agent') ||
        lower.includes('session');

      if (!isAgentArtifact && !lower.endsWith('.json') && !lower.endsWith('.log')) {
        continue;
      }

      let content = '';
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch {
        continue;
      }
      if (!content) continue;

      const lines = content.split(/\r?\n/);
      const push = (p, lineNo, matched) => {
        findings.push(createFinding({
          file: filePath,
          line: lineNo,
          column: 1,
          severity: p.severity,
          category: this.category,
          rule: p.rule,
          title: p.title,
          description: p.description,
          matched: String(matched).slice(0, 120),
          confidence: 'medium',
          cwe: p.cwe,
          owasp: p.owasp,
          fix: p.fix,
        }));
      };

      // ── Pass 1: line-scoped regex patterns ───────────────────────────────
      // A rule table's own prose/patterns would otherwise match the very rules
      // looking for them; `ruleTable` is null for anything that is not a table.
      const ruleTable = ruleTableLineMask(lines);
      for (const group of [SECRET_PATTERNS, HAZARDOUS_CMD_PATTERNS, PROMPT_INJECTION_PATTERNS, EXFIL_PATTERNS]) {
        for (const pattern of group) {
          for (let i = 0; i < lines.length; i++) {
            if (ruleTable && ruleTable.has(i)) continue;
            // This lane bypassed scanFileWithPatterns, so honour the documented
            // suppression comment here too — it was silently ignored before.
            if (this.isSuppressed(lines[i])) continue;
            pattern.regex.lastIndex = 0;
            let match;
            while ((match = pattern.regex.exec(lines[i])) !== null) {
              if (isDocumentedSecretExample(pattern.rule, match[0])) continue;
              // Skip placeholder credential values (docs/examples) for the
              // generic secret-kv rule only.
              if (pattern.rule === 'AGENT_LOG_SECRET_KV' && PLACEHOLDER_VALUE.test(match[1] || '')) break;
              push(pattern, i + 1, match[0]);
              if (!pattern.regex.global) break;
              if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++;
            }
          }
        }
      }

      // ── Pass 2: whole-file (multiline) patterns ──────────────────────────
      for (const pattern of WHOLE_FILE_PATTERNS) {
        pattern.regex.lastIndex = 0;
        let match;
        while ((match = pattern.regex.exec(content)) !== null) {
          const lineNo = content.slice(0, match.index).split('\n').length;
          push(pattern, lineNo, match[0].slice(0, 40));
          if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++;
        }
      }

      // ── Pass 3: structural JSONL forensics ───────────────────────────────
      if (lower.endsWith('.jsonl')) {
        let parseErrors = 0;
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (!line.trim()) continue;
          let rec;
          try {
            rec = JSON.parse(line);
          } catch {
            parseErrors++;
            continue;
          }

          if (FORENSIC_CHECKS.shellError(rec)) {
            findings.push(createFinding({
              file: filePath,
              line: i + 1,
              column: 1,
              severity: 'medium',
              category: this.category,
              rule: 'AGENT_LOG_SHELL_ERROR_EXIT',
              title: 'Failed Shell Execution in Agent Session',
              description: 'A tool result in the transcript records a shell error (is_error or non-zero exit). Failed executions are a key forensic signal — attacker recon and lateral-movement attempts typically leave a trail of failed commands.',
              matched: 'tool_result is_error=true',
              confidence: 'medium',
              cwe: 'CWE-248',
              owasp: 'ASI02',
              fix: 'Review the failed commands and their surrounding session context. Failed-then-succeeded command pairs deserve special scrutiny.',
            }));
          }

          if (FORENSIC_CHECKS.permissionMode(rec)) {
            findings.push(createFinding({
              file: filePath,
              line: i + 1,
              column: 1,
              severity: 'high',
              category: this.category,
              rule: 'AGENT_LOG_PERMISSION_ESCALATION',
              title: 'Permission-Mode Escalation in Agent Session',
              description: 'The session contains a permission-mode escalation record (bypassPermissions / acceptEdits / plan). An escalation mid-session before destructive tool runs is the strongest intent indicator in insider-threat triage.',
              matched: 'permission-mode escalation',
              confidence: 'high',
              cwe: 'CWE-862',
              owasp: 'ASI02',
              fix: 'Audit what the session did after the escalation. Prefer deny-by-default permission policies.',
            }));
          }

          if (FORENSIC_CHECKS.sidechain(rec)) {
            findings.push(createFinding({
              file: filePath,
              line: i + 1,
              column: 1,
              severity: 'low',
              category: this.category,
              rule: 'AGENT_LOG_SUBAGENT_SIDECHAIN',
              title: 'Sub-Agent Sidechain Activity in Session',
              description: 'The transcript contains sub-agent sidechain records — activity that runs outside the main conversation timeline and is easy to miss in review.',
              matched: 'isSidechain record',
              confidence: 'medium',
              cwe: 'CWE-250',
              owasp: 'ASI02',
              fix: 'Review sidechain threads (Task/Agent sub-agents) explicitly — they are a common obfuscation vector.',
            }));
          }
        }

        if (parseErrors > 0 && lines.length >= 5 && parseErrors >= Math.ceil(lines.length * 0.05)) {
          findings.push(createFinding({
            file: filePath,
            line: 1,
            column: 1,
            severity: 'medium',
            category: this.category,
            rule: 'AGENT_LOG_PARSE_ERRORS',
            title: 'Transcript Tampering or Corruption (Parse Errors)',
            description: `${parseErrors}/${lines.length} lines of this session transcript fail to parse as JSONL. Truncated or tampered transcripts are a forensic red flag — evidence may have been altered or deleted.`,
            matched: `${parseErrors} unparseable lines`,
            confidence: 'medium',
            cwe: 'CWE-506',
            owasp: 'ASI03',
            fix: 'Verify the transcript against retention/backup copies. Correlated parse errors with suspicious tool activity indicate tampering.',
          }));
        }
      }
    }

    return findings;
  }
}

export default AgentTelemetryAgent;
