/** Run with npm run release:check before creating a release tag. */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = process.env.npm_execpath;
if (!npmCli || !fs.existsSync(npmCli)) throw new Error('Run this gate with npm run release:check');
const npm = (args, cwd = root) => execFileSync(process.execPath, [npmCli, ...args], { cwd, stdio: 'inherit' });
const json = file => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
const version = json('package.json').version;
if (process.argv.includes('--publishing')) {
  const status = execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim();
  assert.equal(status, '', 'Commit the reviewed release files before publishing');
  const committed = JSON.parse(execFileSync('git', ['show', 'HEAD:package.json'], { cwd: root, encoding: 'utf8' }));
  assert.equal(committed.version, version, 'Publish the version recorded in the reviewed commit');
}
const lock = json('package-lock.json');
assert.equal(lock.version, version);
assert.equal(lock.packages[''].version, version);
const extensionVersion = json('vscode-extension/package.json').version;
assert.equal(json('vscode-extension/package-lock.json').packages[''].version, extensionVersion);
assert.ok(fs.existsSync(path.join(root, `docs/RELEASE-${version}.md`)), 'Release notes must exist');

npm(['test']);
npm(['run', 'lint']);
npm(['audit', '--omit=dev', '--audit-level=moderate']);
npm(['run', 'test:determinism']);
const report = JSON.parse(execFileSync(process.execPath,
  ['cli/bin/praxis.js', 'scan', '.', '--json', '--no-deps', '--no-ai', '--no-cache'],
  { cwd: root, encoding: 'utf8', maxBuffer: 64 << 20 }));
assert.equal(report.scanComplete, true, 'Self-scan must complete');
assert.equal(report.findings.filter(f => f.severity === 'critical').length, 0, 'Self-scan must have zero critical findings');

const extension = path.join(root, 'vscode-extension');
npm(['ci', '--ignore-scripts', '--no-audit', '--no-fund'], extension);
npm(['run', 'compile'], extension);
execFileSync(process.execPath, ['--test', 'tests/cli-runner.test.cjs'], { cwd: extension, stdio: 'inherit' });

// Prove the actual distribution works, rather than only its source checkout.
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-release-check-'));
try {
  const packed = JSON.parse(execFileSync(process.execPath,
    [npmCli, 'pack', '--json', '--pack-destination', temporary], { cwd: root, encoding: 'utf8' }))[0];
  assert.equal(packed.version, version);
  assert.equal(packed.filename, `praxis-sec-${version}.tgz`);
  assert.ok(packed.files.every(file => !/docs\/internal\/|cli\/__tests__\/|\.(?:exe|tgz)$/.test(file.path)));
  const installation = path.join(temporary, 'installation');
  npm(['install', '--prefix', installation, path.join(temporary, packed.filename), '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund']);
  const cli = path.join(installation, 'node_modules/praxis-sec/cli/bin/praxis.js');
  assert.equal(execFileSync(process.execPath, [cli, '--version'], { encoding: 'utf8' }).trim(), version);
  const fixture = path.join(temporary, 'fixture');
  fs.mkdirSync(fixture);
  const syntheticKey = 'AKIA' + 'IOSFODNN7EXAMPLF';
  fs.writeFileSync(path.join(fixture, 'app.js'), `const key = "${syntheticKey}";\neval(input);\n`);
  const args = [cli, 'scan', 'full', fixture, '--json', '--no-deps', '--no-ai'];
  const coldText = execFileSync(process.execPath, args, { encoding: 'utf8' });
  const cold = JSON.parse(coldText);
  assert.equal(cold.scanComplete, true);
  assert.ok(cold.findings.length > 0);
  assert.ok(!coldText.includes(syntheticKey), 'Installed reports must redact credentials');
  assert.deepEqual(JSON.parse(execFileSync(process.execPath, args, { encoding: 'utf8' })).findings, cold.findings);
  console.log(`Release checks passed for CLI ${version} and extension ${extensionVersion}.`);
} finally { fs.rmSync(temporary, { recursive: true, force: true }); }
