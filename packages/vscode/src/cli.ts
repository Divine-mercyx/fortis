import { spawn } from 'node:child_process';
import { posix, win32 } from 'node:path';

/*
 * Finds and runs the Fortis CLI. Nothing here imports vscode, so it can be tested on its own.
 */

/** The first CLI version with --paths-from and "root" in its JSON. */
export const MIN_CLI_VERSION = '0.1.0-beta.12';

export type Cli = {
  /** How it's described in the output panel. */
  label: string;
  /** How it's started. */
  kind: 'node-script' | 'executable' | 'windows-shim';
  path: string;
};

type Lookup = {
  platform: string;
  env: NodeJS.ProcessEnv;
  home: string;
  workspace: string;
  exists: (path: string) => boolean;
};

/** Every CLI to try, best first. The caller uses the first new enough to run, then the bundled one. */
export function cliCandidates(settingPath: string, look: Lookup): Cli[] {
  const windows = look.platform === 'win32';
  const path = windows ? win32 : posix;
  const out: Cli[] = [];
  const add = (label: string, kind: Cli['kind'], file: string) => {
    if (look.exists(file)) out.push({ label, kind, path: file });
  };
  const addCommand = (label: string, file: string) => {
    if (/\.(c|m)?js$/i.test(file)) add(label, 'node-script', file);
    else add(label, /\.(cmd|bat)$/i.test(file) ? 'windows-shim' : 'executable', file);
  };

  if (settingPath.trim()) addCommand('the path in fortis.cliPath', settingPath.trim());

  // The project's own version comes first, so the editor agrees with its git hook and CI.
  add('this project', 'node-script', path.join(look.workspace, 'node_modules', 'fortis-watchdog', 'dist', 'fortis.js'));
  for (const venv of ['.venv', 'venv']) {
    addCommand('this project', windows ? path.join(look.workspace, venv, 'Scripts', 'fortis.exe') : path.join(look.workspace, venv, 'bin', 'fortis'));
  }

  const dirs = (look.env.PATH ?? look.env.Path ?? '').split(windows ? ';' : ':').filter(Boolean);
  const names = windows ? ['fortis.exe', 'fortis.cmd'] : ['fortis'];
  for (const dir of [...dirs, path.join(look.home, '.fortis', 'bin')]) {
    for (const name of names) addCommand('your PATH', path.join(dir, name));
  }
  return out;
}

/** Compares CLI versions: pre-releases sort before their release, and beta.10 is after beta.9. */
export function versionAtLeast(version: string, minimum: string): boolean {
  const parse = (v: string) => {
    const [main = '', pre] = v.trim().replace(/^v/, '').split('-', 2);
    return { main: main.split('.').map(Number), pre: pre ? pre.split('.') : null };
  };
  const a = parse(version);
  const b = parse(minimum);
  for (let i = 0; i < 3; i++) {
    const d = (a.main[i] ?? 0) - (b.main[i] ?? 0);
    if (d) return d > 0;
  }
  if (!a.pre) return true;
  if (!b.pre) return false;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i];
    const y = b.pre[i];
    if (x === undefined) return false;
    if (y === undefined) return true;
    const numeric = /^\d+$/.test(x) && /^\d+$/.test(y);
    const d = numeric ? Number(x) - Number(y) : x.localeCompare(y);
    if (d) return d > 0;
  }
  return true;
}

export const scanArgs = (opts: { paths: boolean; offline: boolean }) => [
  'scan',
  '--json',
  // Always local: an editor save isn't a scan of the project, so it must not change the dashboard.
  '--no-upload',
  ...(opts.offline ? ['--offline'] : []),
  ...(opts.paths ? ['--paths-from', '-'] : []),
];

/** What to spawn. Node can't start a .cmd directly, so those go through cmd.exe. */
export function commandFor(cli: Cli, args: string[], execPath: string = process.execPath) {
  if (cli.kind === 'node-script') {
    // The editor's own runtime, so no separate Node install is needed.
    return { command: execPath, args: [cli.path, ...args], env: { ELECTRON_RUN_AS_NODE: '1' }, windowsVerbatimArguments: false };
  }
  if (cli.kind === 'windows-shim') {
    return { command: 'cmd.exe', args: ['/d', '/s', '/c', `""${cli.path}" ${args.join(' ')}"`], env: {}, windowsVerbatimArguments: true };
  }
  return { command: cli.path, args, env: {}, windowsVerbatimArguments: false };
}

export type CliResult = { code: number; stdout: string; stderr: string };

export function runCli(cli: Cli, args: string[], opts: { cwd: string; input?: string; timeoutMs?: number }): Promise<CliResult> {
  const { command, args: argv, env, windowsVerbatimArguments } = commandFor(cli, args);
  return new Promise((resolve, reject) => {
    const child = spawn(command, argv, {
      cwd: opts.cwd,
      env: { ...process.env, NO_COLOR: '1', ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      windowsVerbatimArguments,
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`The scan took longer than ${Math.round((opts.timeoutMs ?? 0) / 1000)} seconds and was stopped.`));
    }, opts.timeoutMs ?? 300_000);
    child.stdout.setEncoding('utf8').on('data', (d: string) => (stdout += d));
    child.stderr.setEncoding('utf8').on('data', (d: string) => (stderr += d));
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 2, stdout, stderr });
    });
    child.stdin.on('error', () => {
      /* it exited before reading its input; the exit code says why */
    });
    child.stdin.end(opts.input ?? '');
  });
}
