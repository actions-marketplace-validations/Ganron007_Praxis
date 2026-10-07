/**
 * AI Infrastructure Inventory Agent
 * =================================
 *
 * Completes Praxis's view of the AI system beyond application code — the
 * three production layers where AI actually runs:
 *
 *   Lane 1  Model gateways     — LiteLLM / Portkey / Helicone / Cloudflare
 *                                AI Gateway / OpenRouter configs. The choke
 *                                point through which all LLM traffic flows.
 *   Lane 2  AI infrastructure  — self-hosted LLM runtimes (Ollama, vLLM, TGI,
 *                                SGLang, Triton, llama.cpp, NIM, ...) in
 *                                Docker/K8s/Helm/compose/Terraform, and
 *                                managed AI compute (Bedrock/SageMaker/Vertex).
 *   Lane 3  AI API endpoints   — OpenAPI specs + framework routes (FastAPI,
 *                                Flask, Express, Spring, Django) with auth-style
 *                                capture and {id}-path BOLA candidates.
 *   Lane 4  AI data pipelines  — dataset loaders that fetch/execute remote
 *                                content, template injection in dataset configs,
 *                                and eval-harness / agent-sandbox misconfigs
 *                                (the July 2026 OpenAI–Hugging Face incident
 *                                vectors: remote-code dataset loaders, template
 *                                injection, disabled safety gates, broad egress).
 *
 * Inventory findings are MEDIUM/LOW — they map the attack surface rather
 * than assert a vulnerability. Risk indicators (exposed keys, no-auth
 * runtimes) escalate to HIGH.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding, ruleTableLineMask } from './base-agent.js';

// =============================================================================
// LANE 1 — MODEL GATEWAYS
// =============================================================================

const GATEWAY_CHECKS = [
  {
    rule: 'AI_GATEWAY_LITELLM',
    title: 'LiteLLM Proxy Gateway Detected',
    glob: ['**/litellm*.yaml', '**/litellm*.yml', '**/config.yaml', '**/config.yml'],
    regex: /model_list\s*:/i,
    severity: 'medium',
    description: 'A LiteLLM proxy config with model_list routes LLM traffic. The proxy is the choke point: a misconfiguration (open admin, missing master key, unverified model routes) exposes every prompt and response passing through it.',
    fix: 'Review model_list entries and auth (master key, per-key budgets). Pin model versions and set egress controls.',
  },
  {
    rule: 'AI_GATEWAY_PORTKEY',
    title: 'Portkey Gateway Configuration Detected',
    glob: ['**/portkey-config.json', '**/.portkey*'],
    regex: /(?:provider|virtual_keys?|api_key)\s*:/i,
    severity: 'medium',
    description: 'Portkey gateway config found. Portkey configs commonly contain virtual API keys — treat as credential material.',
    fix: 'Never commit virtual keys. Move to secrets manager and rotate any committed value.',
  },
  {
    rule: 'AI_GATEWAY_HELICONE',
    title: 'Helicone Proxy Endpoint Detected',
    regex: /oai\.helicone\.ai|helicone\.ai\/v1/i,
    severity: 'medium',
    description: 'LLM calls route through the Helicone observability proxy — all prompt/response traffic transits a third party.',
    fix: 'Verify the Helicone account and data-retention settings; exclude sensitive prompts from logging.',
  },
  {
    rule: 'AI_GATEWAY_CLOUDFLARE_AI',
    title: 'Cloudflare AI Gateway Detected',
    regex: /gateway\.ai\.cloudflare\.com/i,
    severity: 'low',
    description: 'LLM traffic routes through Cloudflare AI Gateway.',
    fix: 'Review gateway logs retention and per-app egress policy.',
  },
  {
    rule: 'AI_GATEWAY_OPENROUTER',
    title: 'OpenRouter Usage Detected',
    regex: /openrouter\.ai\/api|OPENROUTER_API_KEY/i,
    severity: 'medium',
    description: 'OpenRouter (multi-model gateway) is configured. All prompts route through a third-party aggregator.',
    fix: 'Verify model routing policy and keep API keys out of committed files.',
  },
];

// =============================================================================
// LANE 2 — AI INFRASTRUCTURE / IaC
// =============================================================================

const RUNTIME_IMAGES = [
  'ollama', 'ghcr.io/ollama', 'vllm', 'vllm/vllm-openai',
  'text-generation-inference', 'ghcr.io/huggingface/text-generation-inference',
  'sglang', 'lmsysorg/sglang', 'triton', 'nvcr.io/nvidia/tritonserver',
  'nvidia-nim', 'nvcr.io/nvidia/nim', 'localai', 'llama.cpp',
  'ghcr.io/ggml-org/llama.cpp', 'lorax', 'aphrodite', 'openllm',
  'xinference', 'ray-llm', 'infinity', 'fastchat',
];
const RUNTIME_IMAGE_RE = new RegExp(`(?:FROM|image:)\\s*[\"']?(${RUNTIME_IMAGES.map(i => i.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'i');

const MANAGED_COMPUTE = [
  { rule: 'AI_MANAGED_BEDROCK', regex: /aws_bedrock_provisioned_model_throughput|aws_bedrock_custom_model/i, title: 'AWS Bedrock Provisioned Model', description: 'Terraform provisions AWS Bedrock model capacity — committed throughput is a billing + model-governance surface.' },
  { rule: 'AI_MANAGED_SAGEMAKER', regex: /aws_sagemaker_endpoint\s*["']?[a-zA-Z0-9_-]*(?:llm|model|inference|endpoint)/i, title: 'AWS SageMaker LLM Endpoint', description: 'Terraform provisions a SageMaker endpoint for an LLM — verify IAM scope and endpoint auth.' },
  { rule: 'AI_MANAGED_VERTEX', regex: /google_vertex_ai_endpoint/i, title: 'Google Vertex AI Endpoint', description: 'Terraform provisions a Vertex AI endpoint — verify network policy and model provenance.' },
];

// =============================================================================
// LANE 3 — AI API ENDPOINTS
// =============================================================================

const FRAMEWORK_ROUTE_RE = [
  { name: 'FastAPI/Starlette', regex: /@(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']/g },
  { name: 'Flask', regex: /@(?:app|bp)\.route\s*\(\s*["']([^"']+)["']/g },
  { name: 'Express', regex: /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']/g },
  { name: 'Spring', regex: /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g },
  { name: 'Django', regex: /(?:path|re_path)\s*\(\s*["']([^"']+)["']/g },
];

const BOLA_SEGMENT = /[\/{][^{}\/]*(?:\{|:)[a-zA-Z_][a-zA-Z0-9_]*[\}][^{}\/]*/;

// =============================================================================
// LANE 4 — AI DATA PIPELINES & EVAL HARNESSES
// =============================================================================
// Vectors from the July 2026 OpenAI–Hugging Face autonomous-agent incident:
// remote-code dataset loaders and dataset template injection (initial access),
// and eval-harness / agent-sandbox misconfigurations (OpenAI side).

// Remote-code dataset loader: fetch remote content then exec/eval/pickle-load it
const DATASET_REMOTE_LOADER = /(?:load_dataset|dataset_from_script|requests\.get|urllib\.request|httpx\.get|fetch\s*\(\s*["'`]https?:\/\/)[\s\S]{0,300}(?:\bexec\s*\(|\beval\s*\(|pickle\.loads|__import__\(|compile\s*\()/i;

// Unsafe dataset/model loading flags
const UNSAFE_DATASET_FLAG = /trust_remote_code\s*=\s*True|trust_remote_code\s*:\s*true/i;

// Template injection in dataset configs: template expressions invoking OS/module
const DATASET_TEMPLATE_INJECTION = /\{\{\s*(?:__import__|os\.|subprocess|exec|eval|__builtins__)[\s\S]{0,120}?\}\}|\$\{\s*(?:__import__|os\.|subprocess|exec|eval|process\.env)[\s\S]{0,120}?\}/i;

/**
 * First 1-based line where `re` matches something that is not a rule table
 * describing itself, or 0 when every match is rule-table prose.
 *
 * The lanes below run patterns against whole file contents, so on one of our own
 * rule tables the match is the table's `description:`/`title:` prose naming the
 * very risk being checked. Skipping only those lines keeps real configuration in
 * the same file reportable, and keeps the reported line honest.
 */
function realMatchLine(content, re) {
  const mask = ruleTableLineMask(content.split('\n'));
  if (!mask) {
    re.lastIndex = 0;
    const first = re.exec(content);
    return first ? content.slice(0, first.index).split('\n').length : 0;
  }
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(content)) !== null) {
    const lineIdx = content.slice(0, m.index).split('\n').length - 1;
    if (!mask.has(lineIdx)) return lineIdx + 1;
    if (!re.global) break;
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return 0;
}

// Eval-harness / agent-sandbox: disabled safety gates, broad tool scope, egress
const EVAL_HARNESS_RISK = [
  {
    rule: 'AI_EVAL_HARNESS_DISABLED_GUARDRAILS',
    title: 'Eval Harness Disables Safety Guardrails',
    regex: /(?:cyber_refusals|safety_refusals|refusals|guardrails|safety_gates|harm_belen|filters)\s*[:=]\s*(?:disabled|false|off|none|0)/i,
    severity: 'high',
    description: 'An evaluation harness or agent-sandbox config disables model safety guardrails. This is the configuration class behind the OpenAI–Hugging Face July 2026 incident (models evaluated with cyber refusals disabled), and enables unchecked autonomous behavior during evaluation.',
    fix: 'Keep safety guardrails enabled during evaluation, or gate their removal behind explicit containment controls (no internet, isolated egress).',
  },
  {
    rule: 'AI_EVAL_HARNESS_BROAD_TOOL_SCOPE',
    title: 'Eval Harness Grants Broad Tool/Shell Scope',
    regex: /(?:tools?|tool_scope|permissions|allowed_commands)\s*[:=]\s*[\[{][\s\S]{0,200}(?:shell|code_exec|exec_command|bash|subprocess|registry_proxy|all_tools)/i, // praxis-ignore AGENT_TOOL_SHELL_ACCESS — detector definition
    severity: 'medium',
    description: 'An eval harness or agent sandbox grants shell/code-execution tool scope. Combined with network egress this reproduces the sandbox-escape pattern that allowed the July 2026 autonomous agent to pivot from evaluation into production infrastructure.',
    fix: 'Scope evaluation tools to the minimum surface. Shell/code-execution tools should never coexist with internet access in the same sandbox.',
  },
  {
    rule: 'AI_EVAL_HARNESS_BROAD_EGRESS',
    title: 'Eval Harness Allows Unrestricted Network Egress',
    regex: /(?:internet_egress|egress|network_access|allow_remote_downloads|bypass_egress|no_network)\s*[:=]\s*(?:constrained|unrestricted|true|enabled|any|all|false)/i,
    severity: 'high',
    description: 'An eval harness or sandbox allows unrestricted network egress (or explicitly bypasses egress controls). The OpenAI models escaped their sealed evaluation only after finding an egress path — unrestricted egress removes that barrier entirely.',
    fix: 'Default evaluation environments to no-network. If egress is required, allowlist specific endpoints and proxy through a logging gateway.',
  },
];

// =============================================================================
// AGENT
// =============================================================================

export class AiInfraInventoryAgent extends BaseAgent {
  constructor() {
    super(
      'AiInfraInventoryAgent',
      'Maps the production AI system: model gateways, self-hosted/managed AI infrastructure, and AI API endpoints',
      'llm'
    );
  }

  shouldRun() {
    return true; // these layers exist in most modern AI-bearing repos
  }

  async analyze(context) {
    const { files = [], rootPath } = context;
    const findings = [];

    const read = (f) => {
      try { return fs.readFileSync(f, 'utf8'); } catch { return ''; }
    };

    // ── Lane 1: model gateways ─────────────────────────────────────────────
    for (const check of GATEWAY_CHECKS) {
      for (const file of files) {
        const rel = path.relative(rootPath, file).replace(/\\/g, '/');
        if (check.glob) {
          const matches = check.glob.some(g => {
            const parts = g.replace(/\*\*\//g, '').split('/');
            const last = parts[parts.length - 1];
            return (last.includes('*') ? new RegExp(`^${last.replace(/\*/g, '.*')}$`).test(path.basename(file)) : last === path.basename(file));
          });
          if (!matches) continue;
        }
        const content = read(file);
        if (!check.regex.test(content)) continue;
        const gwLine = realMatchLine(content, check.regex);
        if (gwLine === 0) continue;
        findings.push(createFinding({
          file,
          line: gwLine,
          severity: check.severity,
          category: this.category,
          rule: check.rule,
          title: check.title,
          description: check.description,
          matched: check.rule,
          confidence: 'high',
          cwe: 'CWE-1357',
          owasp: 'ASI10',
          fix: check.fix,
        }));
      }
    }

    // ── Lane 2: AI infrastructure ──────────────────────────────────────────
    for (const file of files) {
      const rel = path.relative(rootPath, file).replace(/\\/g, '/');
      const isIaC = /(?:Dockerfile|docker-compose[^/]*\.ya?ml|\.ya?ml|\.tf|k8s|helm|deployment)/i.test(rel);
      if (!isIaC) continue;
      const content = read(file);
      if (!content) continue;

      const runtimeMatch = RUNTIME_IMAGE_RE.exec(content);
      if (runtimeMatch) {
        findings.push(createFinding({
          file,
          line: 1,
          severity: 'medium',
          category: this.category,
          rule: 'AI_INFRA_RUNTIME_DEPLOYMENT',
          title: `Self-Hosted LLM Runtime (${runtimeMatch[1]})`,
          description: `The repo deploys ${runtimeMatch[1]}, a self-hosted LLM runtime. Operational responsibility: the deployment must enforce endpoint auth, egress limits, model provenance, and patching — a publicly reachable unauthenticated inference endpoint is a direct data/model theft surface.`,
          matched: runtimeMatch[1],
          confidence: 'high',
          cwe: 'CWE-306',
          owasp: 'ASI06',
          fix: 'Authenticate the inference endpoint, restrict network egress, pin runtime/model versions, and monitor inference logs.',
        }));
      }

      for (const mc of MANAGED_COMPUTE) {
        const mcLine = mc.regex.test(content) ? realMatchLine(content, mc.regex) : 0;
        if (mcLine) {
          findings.push(createFinding({
            file,
            line: mcLine,
            severity: 'medium',
            category: this.category,
            rule: mc.rule,
            title: mc.title,
            description: mc.description,
            matched: mc.rule,
            confidence: 'high',
            cwe: 'CWE-1357',
            owasp: 'ASI10',
            fix: 'Review IAM/network policies around the managed AI resource.',
          }));
        }
      }
    }

    // ── Lane 3: API endpoints ─────────────────────────────────────────────
    for (const file of files) {
      const rel = path.relative(rootPath, file).replace(/\\/g, '/');
      const isSpec = /openapi|swagger/i.test(rel) && /\.(json|ya?ml)$/.test(rel);
      if (isSpec) {
        const content = read(file);
        let spec = null;
        try { spec = JSON.parse(content); } catch { /* yaml specs not parsed — see FRAMEWORK_ROUTE_RE */ }
        if (spec) {
          const paths = spec.paths || {};
          const securitySchemes = spec.components?.securitySchemes || spec.securityDefinitions || {};
          const authStyles = Object.values(securitySchemes).map(s => s.type || s.scheme || 'unknown');
          const routeEntries = [];
          for (const [p, methods] of Object.entries(paths)) {
            for (const m of Object.keys(methods || {})) {
              if (['get', 'post', 'put', 'patch', 'delete'].includes(m.toLowerCase())) routeEntries.push({ path: p, method: m });
            }
          }
          if (routeEntries.length > 0) {
            const bola = routeEntries.filter(r => BOLA_SEGMENT.test(r.path));
            findings.push(createFinding({
              file,
              line: 1,
              severity: 'low',
              category: this.category,
              rule: 'AI_API_SPEC_INVENTORY',
              title: `API Spec: ${routeEntries.length} Routes (auth: ${authStyles.length ? authStyles.join(',') : 'none declared'})`,
              description: `OpenAPI/Swagger spec exposes ${routeEntries.length} routes. Auth styles declared: ${authStyles.length ? authStyles.join(', ') : 'NONE — every route may be unauthenticated'}. This is the attack-surface map for the AI service.`,
              matched: `${routeEntries.length} routes`,
              confidence: 'high',
              cwe: 'CWE-1059',
              owasp: 'ASI02',
              fix: 'Ensure every route has an explicit auth scheme; review the spec for admin/debug routes.',
            }));
            if (bola.length > 0) {
              findings.push(createFinding({
                file,
                line: 1,
                severity: 'medium',
                category: this.category,
                rule: 'AI_API_BOLA_CANDIDATE',
                title: `BOLA Candidates: ${bola.length} Object-ID Path Route(s)`,
                description: `Route(s) with object-id path segments (e.g. ${bola[0].path}) are classic Broken Object Level Authorization candidates — every object access must be ownership-checked.`,
                matched: bola.slice(0, 3).map(r => r.path).join(', '),
                confidence: 'medium',
                cwe: 'CWE-639',
                owasp: 'ASI02',
                fix: 'Verify per-object authorization checks (ownership/tenant scoping) on every flagged route.',
              }));
            }
          }
        }
        continue;
      }

      const ext = path.extname(file).toLowerCase();
      if (!['.py', '.js', '.ts', '.java'].includes(ext)) continue;
      const content = read(file);
      if (!content) continue;

      for (const fr of FRAMEWORK_ROUTE_RE) {
        fr.regex.lastIndex = 0;
        let m;
        let count = 0;
        const sample = [];
        while ((m = fr.regex.exec(content)) !== null) {
          count++;
          if (sample.length < 3) sample.push(m[1]);
        }
        if (count === 0) continue;
        const bolaCount = sample.filter(r => BOLA_SEGMENT.test(r)).length;
        findings.push(createFinding({
          file,
          line: 1,
          severity: 'low',
          category: this.category,
          rule: 'AI_API_FRAMEWORK_ROUTES',
          title: `${fr.name}: ${count} Route(s) Discovered${bolaCount ? `, ${bolaCount}+ with object-id segments` : ''}`,
          description: `Framework route discovery found ${count} routes (${sample.join(', ')}...). ${bolaCount ? 'Object-id segments present — check BOLA.' : ''}`,
          matched: sample.join(', '),
          confidence: 'high',
          cwe: 'CWE-1059',
          owasp: 'ASI02',
          fix: 'Map every route to an auth requirement. Flag admin/internal routes for review.',
        }));
      }
    }

    // ── Lane 4: AI data pipelines & eval harnesses ─────────────────────────
    const lane4Files = files.filter(f => {
      const rel = path.relative(rootPath, f).replace(/\\/g, '/');
      const isDataPipeline = /(?:dataset|loader|load_data|pipeline|hf_|hugging|train|preprocess|ingest)/i.test(rel)
        || /(?:dataset_infos\.json|config\.json|dataset\.py|\.py$|\.js$|\.json$|\.yaml$|\.yml$)/i.test(path.basename(f));
      const isEvalHarness = /(?:eval|harness|benchmark|sandbox|exploitgym|ctf|scaffold)/i.test(rel)
        || /eval.*\.(?:yaml|yml|json|py|toml|cfg)$/i.test(path.basename(f));
      return (isDataPipeline || isEvalHarness) && !/(?:node_modules|__tests__|test_|\.test\.)/i.test(rel);
    });

    for (const file of lane4Files) {
      const content = read(file);
      if (!content) continue;
      const rel = path.relative(rootPath, file).replace(/\\/g, '/');

      // Remote-code dataset loader
      const dataset_remote_loader_line = DATASET_REMOTE_LOADER.test(content) ? realMatchLine(content, DATASET_REMOTE_LOADER) : 0;
      if (dataset_remote_loader_line) {
        findings.push(createFinding({
          file,
          line: dataset_remote_loader_line,
          severity: 'critical',
          category: this.category,
          rule: 'AI_DATASET_REMOTE_LOADER',
          title: 'Dataset Loader Fetches and Executes Remote Content',
          description: `Dataset pipeline (${rel}) fetches remote content and executes it (exec/eval/pickle.loads). This is the exact initial-access vector used against Hugging Face in July 2026 — a malicious dataset abused the remote-code dataset loader path to run code on a processing worker. Loading an untrusted dataset is equivalent to running its code.`,
          matched: 'remote fetch → code execution',
          confidence: 'high',
          cwe: 'CWE-502',
          owasp: 'ASI05',
          fix: 'Never load datasets with trust_remote_code from unverified sources. Verify dataset provenance, pin revisions/commits, and load inside an isolated worker with no credentials.',
        }));
      }

      // Unsafe trust_remote_code flag (companion)
      const unsafe_dataset_flag_line = UNSAFE_DATASET_FLAG.test(content) ? realMatchLine(content, UNSAFE_DATASET_FLAG) : 0;
      if (unsafe_dataset_flag_line) {
        findings.push(createFinding({
          file,
          line: unsafe_dataset_flag_line,
          severity: 'high',
          category: this.category,
          rule: 'AI_DATASET_TRUST_REMOTE_CODE',
          title: 'Dataset/Model Loading with trust_remote_code',
          description: `Data pipeline enables trust_remote_code — executing arbitrary code shipped with a dataset/model repo. Multiple 2025-26 incidents (Hugging Face pickle malware, FaceHugger Diffusers bypass, the July 2026 HF breach) abuse this trust boundary for RCE.`,
          matched: 'trust_remote_code=True',
          confidence: 'high',
          cwe: 'CWE-502',
          owasp: 'ASI05',
          fix: 'Disable trust_remote_code by default. If required, pin the exact repo revision, verify provenance, and load in a sandboxed worker.',
        }));
      }

      // Template injection in dataset config
      const dataset_template_injection_line = DATASET_TEMPLATE_INJECTION.test(content) ? realMatchLine(content, DATASET_TEMPLATE_INJECTION) : 0;
      if (dataset_template_injection_line) {
        findings.push(createFinding({
          file,
          line: dataset_template_injection_line,
          severity: 'critical',
          category: this.category,
          rule: 'AI_DATASET_TEMPLATE_INJECTION',
          title: 'Template Injection in Dataset Configuration',
          description: `Dataset config (${rel}) contains a template expression invoking OS/module functions. Template injection in dataset configuration was the second initial-access vector in the July 2026 Hugging Face breach — a malicious dataset config executed code on a processing worker.`,
          matched: '{{ ... }} / ${ ... } with OS call',
          confidence: 'high',
          cwe: 'CWE-1336',
          owasp: 'ASI05',
          fix: 'Never render dataset config templates with expression evaluation. Treat config fields as plain data and reject template delimiters in untrusted inputs.',
        }));
      }

      // Eval-harness / sandbox misconfigurations
      for (const check of EVAL_HARNESS_RISK) {
        const harness_line = check.regex.test(content) ? realMatchLine(content, check.regex) : 0;
        if (harness_line) {
          const lines = content.split('\n');
          const lineText = lines[harness_line - 1] || '';
          if (lineText.includes('// praxis-ignore') || lineText.includes('# praxis-ignore')) continue;
          findings.push(createFinding({
            file,
            line: harness_line,
            severity: check.severity,
            category: this.category,
            rule: check.rule,
            title: check.title,
            description: check.description,
            matched: check.rule,
            confidence: 'high',
            cwe: 'CWE-284',
            owasp: 'ASI08',
            fix: check.fix,
          }));
        }
      }
    }

    return findings;
  }
}

export default AiInfraInventoryAgent;
