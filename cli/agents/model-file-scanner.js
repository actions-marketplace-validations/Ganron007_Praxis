/**
 * Model File Scanner
 * ===================
 *
 * Finds machine-learning model artifacts in the repository and flags risky
 * formats. Pickle-based formats (.pkl/.pt/.pth/.ckpt/pytorch_model.bin)
 * execute arbitrary code on load — adversaries embed `os.system` payloads
 * via `__reduce__` to gain RCE. SafeTensors and GGUF are safer but still
 * benefit from a model-card / origin check.
 *
 * Risk classes:
 *   - pickle-based (.pkl, .pt, .pth, .ckpt, pytorch_model.bin)  → critical/high
 *   - safetensors (.safetensors)                                → low/informational
 *   - gguf, onnx, h5, pb                                        → low
 *   - missing MODEL_CARD.md / README.md alongside weights       → low
 *
 * References: ProtectAI ModelScan, Trail of Bits "PyTorch Pickle Risks".
 *
 * Maps to: OWASP LLM03 / LLM04, MITRE ATLAS AML.T0010 / AML.T0018,
 *          OWASP ML Top 10 ML06 / ML10.
 */

import fs from 'fs';
import path from 'path';
import fg from '../core/glob.js';
import { BaseAgent, createFinding } from './base-agent.js';

const MODEL_GLOBS = [
  '**/*.pkl', '**/*.pickle',
  '**/*.pt', '**/*.pth',
  '**/*.ckpt',
  '**/*.safetensors',
  '**/*.gguf',
  '**/*.onnx',
  '**/*.h5', '**/*.hdf5',
  '**/*.pb',
  '**/pytorch_model.bin',
  '**/model.bin',
  '**/consolidated.*.bin',
];

const PICKLE_EXTS = new Set(['.pkl', '.pickle', '.pt', '.pth', '.ckpt']);
const SAFE_EXTS = new Set(['.safetensors']);
const NEUTRAL_EXTS = new Set(['.gguf', '.onnx', '.h5', '.hdf5', '.pb']);

// Strings that, when present in a pickle byte stream, indicate the file
// imports a dangerous module during deserialization. These are not
// definitive RCE proofs (Python's pickle stores module names as ASCII), but
// in practice their presence in a model artifact is anomalous.
const PICKLE_DANGEROUS_MODULES = [
  'posix', 'nt', 'os.system', 'os.popen', 'os.exec',
  'subprocess', 'subprocess.Popen', 'subprocess.call', 'subprocess.run',
  'commands.getoutput',
  'builtins.eval', 'builtins.exec', 'builtins.compile',
  '__builtin__.eval', '__builtin__.exec',
  'shutil.rmtree',
  'pty.spawn',
  'socket.socket',
  'requests.get', 'urllib.request',
  '__reduce__', '__reduce_ex__',
];

const PICKLE_OPCODE_GLOBAL = 0x63;   // 'c' — GLOBAL (push module.attr onto stack)
const PICKLE_OPCODE_REDUCE = 0x52;   // 'R' — call callable with args (the dangerous one)
const PICKLE_OPCODE_INST = 0x69;     // 'i' — INST (also reduce-like)
const PICKLE_OPCODE_STACK_GLOBAL = 0x93; // STACK_GLOBAL (proto 4)

const MAX_BYTES_TO_SCAN = 5 * 1024 * 1024; // 5MB head — more than enough to see opcodes

export class ModelFileScanner extends BaseAgent {
  constructor() {
    super(
      'ModelFileScanner',
      'Detects risky ML model artifacts (pickle, safetensors, gguf) and missing model cards',
      'llm'
    );
  }

  shouldRun(recon) {
    if (recon?.hasModelFiles) return true;
    const langs = recon?.languages;
    if (langs && (langs instanceof Set ? langs.has('python') : langs.includes?.('python'))) {
      return true;
    }
    return false;
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    let modelFiles = [];
    try {
      modelFiles = await fg(MODEL_GLOBS, {
        cwd: rootPath,
        absolute: true,
        onlyFiles: true,
        dot: false,
        ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**'],
      });
    } catch {
      return findings;
    }

    if (modelFiles.length === 0) return findings;

    const directoriesWithModels = new Set();

    for (const file of modelFiles) {
      directoriesWithModels.add(path.dirname(file));
      const ext = path.extname(file).toLowerCase();
      const relPath = path.relative(rootPath, file).replace(/\\/g, '/');

      if (PICKLE_EXTS.has(ext) || /pytorch_model\.bin$|consolidated\..*\.bin$|^model\.bin$/.test(path.basename(file))) {
        findings.push(...this._inspectPickle(file, relPath));
      } else if (SAFE_EXTS.has(ext)) {
        findings.push(this._informational(file, relPath, 'safetensors',
          'SafeTensors is the recommended safe format. Verify the file came from a trusted source and matches a published checksum.'));
      } else if (NEUTRAL_EXTS.has(ext)) {
        findings.push(this._informational(file, relPath, ext.replace('.', ''),
          'Non-pickle model artifact. Verify origin and checksums; some loaders (e.g. ONNX custom ops) can still execute attacker-controlled code.'));
      }
    }

    for (const dir of directoriesWithModels) {
      const sample = modelFiles.find(f => path.dirname(f) === dir);
      if (!sample) continue;
      if (!this._hasModelCard(dir)) {
        findings.push(createFinding({
          file: sample,
          line: 0,
          severity: 'low',
          category: 'llm',
          rule: 'MODEL_FILE_NO_CARD',
          title: 'Model artifact without a model card',
          description: 'No MODEL_CARD.md / README.md / model_card.* alongside the model artifact. Model cards document training data, intended use, and limitations.',
          matched: path.relative(rootPath, dir).replace(/\\/g, '/'),
          confidence: 'medium',
          owasp: 'ASI04',
          fix: 'Add a MODEL_CARD.md describing source, training data, intended use, license, and known limitations.',
        }));
      }
    }

    return findings;
  }

  _inspectPickle(filePath, relPath) {
    const findings = [];
    let buf;
    try {
      const fd = fs.openSync(filePath, 'r');
      const stat = fs.fstatSync(fd);
      const size = Math.min(stat.size, MAX_BYTES_TO_SCAN);
      buf = Buffer.alloc(size);
      fs.readSync(fd, buf, 0, size, 0);
      fs.closeSync(fd);
    } catch {
      return findings;
    }

    const isZip = buf.length >= 2 && buf[0] === 0x50 && buf[1] === 0x4B;

    findings.push(createFinding({
      file: filePath,
      line: 0,
      severity: 'high',
      category: 'llm',
      rule: 'MODEL_FILE_PICKLE_FORMAT',
      title: 'Pickle-based model format detected',
      description: 'Pickle-based model artifacts execute arbitrary Python on load via `__reduce__`. Loading a malicious file is equivalent to running its code. Treat any unverified pickle as untrusted.',
      matched: relPath,
      confidence: 'high',
      cwe: 'CWE-502',
      owasp: 'ASI04',
      fix: 'Convert to SafeTensors (`safetensors.torch.save_file`). If pickle is unavoidable, verify a SHA-256 you control before loading and load only inside a sandbox.',
    }));

    const text = buf.toString('binary');
    const hits = [];
    for (const mod of PICKLE_DANGEROUS_MODULES) {
      const idx = text.indexOf(mod);
      if (idx !== -1) hits.push({ mod, idx });
    }

    let hasReduce = false;
    let hasGlobal = false;
    if (!isZip) {
      for (let i = 0; i < buf.length; i++) {
        const b = buf[i];
        if (b === PICKLE_OPCODE_REDUCE) hasReduce = true;
        else if (b === PICKLE_OPCODE_GLOBAL || b === PICKLE_OPCODE_STACK_GLOBAL || b === PICKLE_OPCODE_INST) hasGlobal = true;
        if (hasReduce && hasGlobal) break;
      }
    }

    if (hits.length > 0) {
      findings.push(createFinding({
        file: filePath,
        line: 0,
        severity: 'critical',
        category: 'llm',
        rule: 'MODEL_FILE_PICKLE_DANGEROUS_IMPORT',
        title: 'Pickle artifact imports a dangerous module',
        description: `Pickle stream references known-dangerous symbols: ${hits.slice(0, 5).map(h => h.mod).join(', ')}. Loading this file with torch.load / pickle.load may execute code.`,
        matched: hits.slice(0, 5).map(h => h.mod).join(', '),
        confidence: 'high',
        cwe: 'CWE-502',
        owasp: 'ASI04',
        fix: 'Do not load this file. Re-source the model from a trusted publisher and verify checksums. Convert to SafeTensors before reuse.',
      }));
    } else if (hasReduce && hasGlobal) {
      findings.push(createFinding({
        file: filePath,
        line: 0,
        severity: 'medium',
        category: 'llm',
        rule: 'MODEL_FILE_PICKLE_REDUCE',
        title: 'Pickle artifact contains REDUCE opcodes',
        description: 'Pickle stream contains GLOBAL + REDUCE opcodes — typical for callable invocations during unpickling. Without a known-good source, this is the same shape malicious pickles use.',
        matched: 'pickle GLOBAL + REDUCE opcodes present',
        confidence: 'medium',
        cwe: 'CWE-502',
        owasp: 'ASI04',
        fix: 'Verify the artifact origin and checksum, or scan with a dedicated pickle scanner (picklescan / modelscan) before loading.',
      }));
    }

    return findings;
  }

  _informational(filePath, relPath, label, description) {
    return createFinding({
      file: filePath,
      line: 0,
      severity: 'low',
      category: 'llm',
      rule: `MODEL_FILE_${label.toUpperCase()}`,
      title: `Model artifact detected (${label})`,
      description,
      matched: relPath,
      confidence: 'high',
      owasp: 'ASI04',
      fix: 'Document the model origin and license. Pin a checksum in your repo so future loads can be verified.',
    });
  }

  _hasModelCard(dir) {
    const candidates = ['MODEL_CARD.md', 'model_card.md', 'modelcard.md', 'MODELCARD.md', 'README.md', 'README'];
    for (const name of candidates) {
      try {
        if (fs.existsSync(path.join(dir, name))) return true;
      } catch { /* ignore */ }
    }
    return false;
  }
}

export default ModelFileScanner;
