const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runCli } = require('../out/cli-runner.js');
const { escapeHtml, reportSeverity } = require('../out/report-utils.js');
const vm = require('node:vm');

test('current-file command scans the workspace and assigns only matching diagnostics', async () => {
  const root = path.resolve('workspace with spaces');
  const uri = { fsPath: path.join(root, 'src/app.js') };
  const registered = new Map();
  const diagnostics = [];
  let scanArgs;
  const disposable = { dispose() {} };
  const vscode = {
    languages: {
      createDiagnosticCollection: () => ({ ...disposable, set: (target, values) => diagnostics.push({ target, values }), delete() {} }),
      registerCodeActionsProvider: () => disposable,
    },
    window: {
      createStatusBarItem: () => ({ ...disposable, show() {} }),
      activeTextEditor: { document: { uri } },
    },
    commands: { registerCommand: (name, callback) => { registered.set(name, callback); return disposable; } },
    workspace: {
      getWorkspaceFolder: () => ({ uri: { fsPath: root } }),
      getConfiguration: () => ({ get: () => undefined }),
      onDidSaveTextDocument: () => disposable,
    },
    StatusBarAlignment: { Left: 1 }, DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 },
    CodeActionKind: { QuickFix: 'quickfix' },
    Range: class { constructor(start) { this.start = start; } },
    Diagnostic: class { constructor(range, message, severity) { Object.assign(this, { range, message, severity }); } },
  };
  const moduleExports = {};
  const source = fs.readFileSync(path.join(__dirname, '../out/extension.js'), 'utf8');
  vm.runInNewContext(source, {
    exports: moduleExports,
    require: name => name === 'vscode' ? vscode : name === './cli-runner' ? {
      runCli: async (_configured, args) => {
        scanArgs = args;
        return { stdout: JSON.stringify({ findings: [
          { file: 'src/app.js', line: 1, severity: 'high', title: 'unsafe eval', rule: 'INJ-EVAL' },
          { file: 'other.js', line: 1, severity: 'high', title: 'other issue', rule: 'OTHER' },
        ] }) };
      },
    } : require(name === './report-utils' ? '../out/report-utils.js' : name),
  });
  moduleExports.activate({ subscriptions: [] });
  await registered.get('praxis.scanFile')();
  assert.deepEqual(Array.from(scanArgs), ['scan', root, '--json', '--no-deps', '--no-ai']);
  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0].target, uri);
  assert.equal(diagnostics[0].values.length, 1);
  assert.equal(diagnostics[0].values[0].code, 'INJ-EVAL');
});

test('report content is escaped and severity cannot become an HTML attribute', () => {
  assert.equal(escapeHtml('<img src="https://attacker.invalid/?a=1&b=2">'), '&lt;img src=&quot;https://attacker.invalid/?a=1&amp;b=2&quot;&gt;');
  assert.equal(escapeHtml("'quoted'"), '&#39;quoted&#39;');
  assert.equal(reportSeverity('high'), 'high');
  assert.equal(reportSeverity('high" onclick="unsafe'), 'medium');
});

test('configured CLI receives shell-sensitive paths as literal arguments', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-editor-runner-'));
  try {
    const script = path.join(root, 'fake cli.js');
    fs.writeFileSync(script, 'console.log(JSON.stringify(process.argv.slice(2)));');
    const args = ['scan', 'workspace with spaces/$(echo injected)&literal%PATH%', '--json'];
    const { stdout } = await runCli(script, args, root, 10000, 1024 * 1024);
    assert.deepEqual(JSON.parse(stdout), args);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('configured Praxis CLI runs without shell parsing', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-editor-default-'));
  try {
    const cli = path.resolve(__dirname, '../../cli/bin/praxis.js');
    const { stdout } = await runCli(cli, ['--version'], root, 10000, 1024 * 1024);
    assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('configured Windows npm shims execute the Praxis JS entry point with literal argv', { skip: process.platform !== 'win32' }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-editor-shim-'));
  try {
    for (const global of [true, false]) {
      const directory = global ? root : path.join(root, 'project/node_modules/.bin');
      fs.mkdirSync(directory, { recursive: true });
      const shim = path.join(directory, 'praxis.cmd');
      fs.writeFileSync(shim, '@echo off\r\nexit /b 99\r\n');
      const script = global ? path.join(root, 'node_modules/praxis-sec/cli/bin/praxis.js')
        : path.join(root, 'project/node_modules/praxis-sec/cli/bin/praxis.js');
      fs.mkdirSync(path.dirname(script), { recursive: true });
      fs.writeFileSync(script, 'console.log(JSON.stringify(process.argv.slice(2)));');
      const args = ['scan', 'space & $literal %path%', '--json'];
      assert.deepEqual(JSON.parse((await runCli(shim, args, root, 10000, 1024 * 1024)).stdout), args);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('default npx receives literal argv and forbids automatic package installation', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-editor-npx-'));
  const previousPath = process.env.PATH;
  try {
    const source = 'console.log(JSON.stringify(process.argv.slice(2)));';
    if (process.platform === 'win32') {
      fs.writeFileSync(path.join(root, 'npx.cmd'), '@echo off\r\n');
      const script = path.join(root, 'node_modules/npm/bin/npx-cli.js');
      fs.mkdirSync(path.dirname(script), { recursive: true });
      fs.writeFileSync(script, source);
    } else {
      fs.writeFileSync(path.join(root, 'npx'), '#!/usr/bin/env node\n' + source, { mode: 0o755 });
    }
    process.env.PATH = root + path.delimiter + previousPath;
    const args = ['scan', 'space & $literal %path%', '--json'];
    const { stdout } = await runCli(undefined, args, root, 10000, 1024 * 1024);
    assert.deepEqual(JSON.parse(stdout), ['--no-install', 'praxis-sec', ...args]);
  } finally {
    process.env.PATH = previousPath;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
