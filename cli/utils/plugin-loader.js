/**
 * Plugin Loader — Custom Agent Plugin System
 * ============================================
 *
 * Allows users to drop custom security agents into `.praxis/agents/` and
 * run them alongside the built-in agents after explicit local trust.
 *
 * HOW IT WORKS:
 *   1. With explicit trust, loadPlugins(rootPath) scans `.praxis/agents/*.js`
 *   2. Each file must export a default class that extends BaseAgent
 *   3. Validated plugins are instantiated and returned for registration
 *   4. buildOrchestrator() calls loadPlugins() and registers the results
 *
 * PLUGIN CONTRACT:
 *   A valid plugin must:
 *   - Export a default class (ES module)
 *   - Extend BaseAgent (from praxis's agent framework)
 *   - Implement `async analyze(context)` returning an array of findings
 *   - Set `this.name` and `this.category` in the constructor
 *
 * EXAMPLE PLUGIN:
 *
 *   // .praxis/agents/my-rule.js
 *   import { BaseAgent, createFinding } from 'praxis-sec';
 *
 *   export default class MyCustomRule extends BaseAgent {
 *     constructor() {
 *       super();
 *       this.name     = 'MyCustomRule';
 *       this.category = 'custom';
 *     }
 *
 *     async analyze({ rootPath, files }) {
 *       const findings = [];
 *       for (const file of files) {
 *         const content = fs.readFileSync(file, 'utf-8');
 *         if (content.includes('eval(')) { // praxis-ignore — JSDoc example, not real eval
 *           findings.push(createFinding({
 *             rule:        'CUSTOM_EVAL',
 *             severity:    'high',
 *             title:       'Dangerous eval() usage', // praxis-ignore — JSDoc string literal
 *             description: 'eval() can execute arbitrary code', // praxis-ignore — JSDoc string literal
 *             file,
 *             remediation: 'Replace eval() with safer alternatives', // praxis-ignore — JSDoc string literal
 *           }));
 *         }
 *       }
 *       return findings;
 *     }
 *   }
 *
 * PLUGIN ISOLATION:
 *   Trusted plugins run in the same process with full operator permissions.
 *   Agent promise timeouts are not a sandbox and cannot stop synchronous loops.
 *
 * SECURITY NOTE:
 *   Plugins are arbitrary code with full operator permissions. A normal scan
 *   never imports them; trusted local scans opt in with --trust-plugins.
 */

import fs from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';
import { BaseAgent, createFinding } from '../agents/base-agent.js';

const PLUGIN_DIR = '.praxis/agents';

/**
 * Load custom agent plugins from .praxis/agents/*.js
 *
 * @param {string} rootPath — project root directory
 * @param {object} options  — { verbose, quiet, trustPlugins }
 * @returns {Promise<object[]>} — array of instantiated agent objects
 */
export async function loadPlugins(rootPath, options = {}) {
  // Importing a module executes its top-level code before class validation.
  // Scanned repositories are data, never implicit authorization to run plugins.
  if (options.trustPlugins !== true) return [];
  const pluginDir = path.join(rootPath, PLUGIN_DIR);

  if (!fs.existsSync(pluginDir)) return [];

  let files;
  try {
    files = fs.readdirSync(pluginDir)
      .filter(f => f.endsWith('.js') || f.endsWith('.mjs'))
      .map(f => path.join(pluginDir, f));
  } catch {
    return [];
  }

  if (files.length === 0) return [];

  if (!options.quiet) {
    console.log(`  Loading ${files.length} plugin(s) from ${PLUGIN_DIR}...`);
  }

  // Expose the agent framework to plugins regardless of how praxis was
  // launched (source tree or installed package) — plugins read this first.
  globalThis.__praxisAgentFramework = { BaseAgent, createFinding };

  const plugins = [];

  for (const filePath of files) {
    try {
      const fileUrl = pathToFileURL(filePath).href;
      const mod     = await import(fileUrl);
      const PluginClass = mod.default;

      if (typeof PluginClass !== 'function') {
        if (options.verbose) console.warn(`  [plugin] ${path.basename(filePath)}: no default export class`);
        continue;
      }

      // Validate the plugin before instantiation
      const validation = validatePlugin(PluginClass, filePath);
      if (!validation.valid) {
        console.warn(`  [plugin] ${path.basename(filePath)} skipped: ${validation.reason}`);
        continue;
      }

      const instance = new PluginClass();

      // Ensure required fields are set after construction
      if (!instance.name) {
        instance.name = path.basename(filePath, '.js');
      }
      if (!instance.category) {
        instance.category = 'custom';
      }

      plugins.push(instance);

      if (!options.quiet) {
        console.log(`  [plugin] Loaded: ${instance.name} (${instance.category})`);
      }
    } catch (err) {
      console.warn(`  [plugin] Failed to load ${path.basename(filePath)}: ${err.message}`);
    }
  }

  return plugins;
}

/**
 * Validate a plugin class before instantiation.
 * Does static checks only — does not instantiate.
 */
function validatePlugin(PluginClass, filePath) {
  const name = path.basename(filePath);

  if (typeof PluginClass !== 'function') {
    return { valid: false, reason: 'default export is not a class/function' };
  }

  // Check prototype has analyze() — the required method
  const proto = PluginClass.prototype;
  if (typeof proto?.analyze !== 'function') {
    return { valid: false, reason: 'class does not implement analyze()' };
  }

  return { valid: true };
}

/**
 * List available plugins without loading them.
 * Used by `praxis doctor` and `praxis plugins list`.
 */
export function listPluginFiles(rootPath) {
  const pluginDir = path.join(rootPath, PLUGIN_DIR);
  if (!fs.existsSync(pluginDir)) return [];

  try {
    return fs.readdirSync(pluginDir)
      .filter(f => f.endsWith('.js') || f.endsWith('.mjs'))
      .map(f => ({
        name: path.basename(f, '.js'),
        path: path.join(pluginDir, f),
        size: fs.statSync(path.join(pluginDir, f)).size,
      }));
  } catch {
    return [];
  }
}

/**
 * Scaffold a new plugin file in .praxis/agents/
 */
export function scaffoldPlugin(rootPath, pluginName) {
  const pluginDir = path.join(rootPath, PLUGIN_DIR);
  if (!fs.existsSync(pluginDir)) {
    fs.mkdirSync(pluginDir, { recursive: true });
  }

  const safeName  = pluginName.replace(/[^a-zA-Z0-9_-]/g, '-');
  const className = safeName.replace(/-([a-z])/g, (_, c) => c.toUpperCase()).replace(/^[a-z]/, c => c.toUpperCase());
  const filePath  = path.join(pluginDir, `${safeName}.js`);

  if (fs.existsSync(filePath)) {
    throw new Error(`Plugin already exists: ${filePath}`);
  }

  const template = `/**
 * Custom Praxis Agent: ${className}
 *
 * Drop this file in .praxis/agents/ and explicitly opt in with
 * \`praxis scan full . --trust-plugins\` after reviewing its code.
 *
 * The \`analyze(context)\` method receives:
 *   context.rootPath   — absolute path to the project root
 *   context.files      — array of absolute file paths to scan
 *   context.recon      — recon data (frameworks, databases, auth patterns)
 *   context.options    — CLI options passed to the scan
 *
 * Return an array of findings using \`createFinding()\`.
 */

import fs from 'fs';

// BaseAgent and createFinding are injected by the plugin loader at runtime.
// Fallbacks cover standalone use: the installed package, then source layout.
let BaseAgent, createFinding;
if (globalThis.__praxisAgentFramework) {
  ({ BaseAgent, createFinding } = globalThis.__praxisAgentFramework);
} else {
  try {
    ({ BaseAgent, createFinding } = await import('praxis-sec'));
  } catch {
    ({ BaseAgent, createFinding } = await import('praxis-sec/cli/index.js'));
  }
}

export default class ${className} extends BaseAgent {
  constructor() {
    super();
    this.name     = '${className}';
    this.category = 'custom'; // or: secrets | injection | auth | config | api | llm
  }

  async analyze({ rootPath, files = [], recon, options }) {
    const findings = [];

    for (const file of files) {
      // Skip files you don't care about
      if (!/\\.(js|ts|jsx|tsx|py|rb|go|java)$/.test(file)) continue;

      let content;
      try {
        content = fs.readFileSync(file, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/praxis-ignore/i.test(line)) continue; // respect suppression comments

        // Example: flag dangerous eval calls // praxis-ignore
        if (/\\beval\\s*\\(/.test(line)) { // praxis-ignore — template example in plugin scaffold, not real eval
          findings.push(createFinding({
            rule:        '${safeName.toUpperCase().replace(/-/g, '_')}',
            severity:    'high',          // critical | high | medium | low
            title:       'Example finding from ${className}',
            description: 'Describe the security risk here.',
            file,
            line:        i + 1,
            matched:     line.trim().slice(0, 100),
            category:    this.category,
            remediation: 'Describe the fix here.',
            confidence:  'medium',        // high | medium | low
          }));
        }
      }
    }

    return findings;
  }
}
`;

  fs.writeFileSync(filePath, template, 'utf-8');
  return filePath;
}
