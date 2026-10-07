import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';

const execFileAsync = promisify(execFile);

/** Keep workspace paths and CLI arguments out of shell command text. */
export async function runCli(cliPath: string | undefined, args: string[], cwd: string, timeout: number, maxBuffer: number) {
  const options = { cwd, timeout, maxBuffer, encoding: 'utf8' as const };
  if (cliPath?.trim()) {
    if (/\.js$/i.test(cliPath)) return execFileAsync('node', [cliPath, ...args], options);
    let command = cliPath;
    if (process.platform === 'win32') {
      if (!/[\\/]/.test(command)) {
        const located = await execFileAsync('where.exe', [command], options);
        command = located.stdout.trim().split(/\r?\n/)[0];
      }
      if (/\.(?:cmd|bat)$/i.test(command)) {
        const launcherDir = path.dirname(path.resolve(cwd, command));
        const packageDir = path.basename(launcherDir) === '.bin'
          ? path.join(path.dirname(launcherDir), 'praxis-sec')
          : path.join(launcherDir, 'node_modules', 'praxis-sec');
        const script = path.join(packageDir, 'cli', 'bin', 'praxis.js');
        if (!fs.existsSync(script)) throw new Error('Configure praxis.cliPath with the Praxis JavaScript entry point or an executable');
        return execFileAsync('node', [script, ...args], options);
      }
    }
    return execFileAsync(command, args, options);
  }
  const npxArgs = ['--no-install', 'praxis-sec', ...args];
  if (process.platform !== 'win32') return execFileAsync('npx', npxArgs, options);

  // Windows .cmd launchers require a shell. Execute npm's JavaScript entry point
  // directly instead, so names containing %, &, or quotes remain argument data.
  const located = await execFileAsync('where.exe', ['npx.cmd'], options);
  const shim = located.stdout.trim().split(/\r?\n/)[0];
  const script = path.join(path.dirname(shim), 'node_modules', 'npm', 'bin', 'npx-cli.js');
  if (!fs.existsSync(script)) throw new Error('Cannot locate npx JavaScript entry point; configure praxis.cliPath');
  const bundledNode = path.join(path.dirname(shim), 'node.exe');
  return execFileAsync(fs.existsSync(bundledNode) ? bundledNode : 'node', [script, ...npxArgs], options);
}
