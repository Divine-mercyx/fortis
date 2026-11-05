import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';

import { RELEASE_REPO, VERSION } from './env';
import { compareVersions } from './rules/fix-version';

/*
 * `fortis update` for binary installs, and the once-a-day "a newer version is available" notice.
 * The check asks GitHub where the latest release redirects to, and sends nothing about the project.
 */

export type InstallKind = 'binary' | 'npm' | 'pip' | 'homebrew' | 'scoop' | 'winget' | 'docker';

type Exists = (path: string) => boolean;

/** How this copy was installed, from where it's running. Only `binary` can replace itself. */
export function installKind(opts: { execPath: string; isBinary: boolean; exists?: Exists }): InstallKind {
  if (!opts.isBinary) return 'npm';
  const exists = opts.exists ?? existsSync;
  const path = opts.execPath.replace(/\\/g, '/');
  if (/\/(Cellar|homebrew|linuxbrew)\//i.test(path)) return 'homebrew';
  if (/\/scoop\/(apps|shims)\//i.test(path)) return 'scoop';
  if (/\/WinGet\/(Packages|Links)\//i.test(path)) return 'winget';
  const dir = dirname(path);
  // A wheel puts the binary among a Python environment's scripts.
  if (/\/(pipx|uv\/tools|site-packages)\//i.test(path) || /\/python\d*\/scripts$/i.test(dir) || exists(`${dir}/activate`) || exists(`${dir}/activate.bat`)) return 'pip';
  if (exists('/.dockerenv') && path === '/usr/local/bin/fortis') return 'docker';
  return 'binary';
}

/** How to update when the CLI can't do it itself. */
export const UPDATE_HINT: Record<Exclude<InstallKind, 'binary'>, string> = {
  npm: 'npm install fortis-watchdog@latest (or your package manager\'s equivalent)',
  pip: 'pip install --upgrade fortis-watchdog (or pipx upgrade fortis-watchdog, uv tool upgrade fortis-watchdog)',
  homebrew: 'brew upgrade fortis',
  scoop: 'scoop update fortis',
  winget: 'winget upgrade DivineMercyx.Fortis',
  docker: 'docker pull ghcr.io/divine-mercyx/fortis',
};

const isNewer = (candidate: string, current: string) => compareVersions(candidate, current) > 0;

/** The latest release's version, from where GitHub redirects its "latest" page. Null if it can't tell. */
export async function latestVersion(opts: { fetchImpl?: typeof fetch; timeoutMs?: number; base?: string } = {}): Promise<string | null> {
  const url = `${opts.base ?? `https://github.com/${RELEASE_REPO}`}/releases/latest`;
  try {
    const res = await (opts.fetchImpl ?? fetch)(url, { method: 'HEAD', redirect: 'manual', headers: { 'user-agent': 'fortis-cli' }, signal: AbortSignal.timeout(opts.timeoutMs ?? 20_000) });
    return /\/tag\/cli-v([^/?#]+)$/.exec(res.headers.get('location') ?? '')?.[1] ?? null;
  } catch {
    return null;
  }
}

/** The release asset for this machine. Null when there's no build for it. */
export function assetName(platform: string, arch: string, musl: boolean): string | null {
  const cpu = arch === 'x64' ? 'x64' : arch === 'arm64' ? 'arm64' : null;
  if (!cpu) return null;
  if (platform === 'win32') return cpu === 'x64' ? 'fortis-windows-x64.zip' : null;
  if (platform === 'darwin') return `fortis-macos-${cpu}.tar.gz`;
  if (platform === 'linux') return `fortis-linux-${cpu}${musl ? '-musl' : ''}.tar.gz`;
  return null;
}

/** glibc reports its version here. musl doesn't. */
export const isMusl = () => process.platform === 'linux' && !(process.report?.getReport() as { header?: { glibcVersionRuntime?: string } } | undefined)?.header?.glibcVersionRuntime;

/** The expected hash of a file, from a SHA256SUMS listing. */
export function expectedHash(sums: string, asset: string): string | null {
  for (const line of sums.split(/\r?\n/)) {
    const m = /^([0-9a-f]{64})\s+\*?(.+)$/i.exec(line.trim());
    if (m && m[2] === asset) return m[1]!.toLowerCase();
  }
  return null;
}

/**
 * Puts a new binary in place. Unix can rename over a running file. Windows can't, but it can rename
 * the running file out of the way, so that's done first and undone if the second step fails.
 */
export function replaceBinary(target: string, fresh: string, platform: string = process.platform) {
  if (platform !== 'win32') {
    renameSync(fresh, target);
    return;
  }
  const old = `${target}.old`;
  rmSync(old, { force: true });
  renameSync(target, old);
  try {
    renameSync(fresh, target);
  } catch (e) {
    renameSync(old, target);
    throw e;
  }
  // Still running, so it can't be deleted yet. The next update removes it.
  try {
    rmSync(old, { force: true });
  } catch {
    /* expected on Windows */
  }
}

export type UpdateResult = { status: 'current' | 'updated'; from: string; to: string };

/** Downloads a release for this machine, checks it against the release's SHA256SUMS, and installs it. */
export async function selfUpdate(opts: {
  target: string;
  current?: string;
  /** A specific version, rather than the latest. */
  version?: string;
  fetchImpl?: typeof fetch;
  env?: NodeJS.ProcessEnv;
  platform?: string;
  arch?: string;
  musl?: boolean;
  onProgress?: (message: string) => void;
}): Promise<UpdateResult> {
  const env = opts.env ?? process.env;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const platform = opts.platform ?? process.platform;
  const current = opts.current ?? VERSION;
  const repo = env.FORTIS_REPO || RELEASE_REPO;
  const to = opts.version?.replace(/^cli-v|^v/, '') ?? (await latestVersion({ fetchImpl, base: `https://github.com/${repo}` }));
  if (!to) throw new Error('Could not find the latest version. Check your connection, or set HTTPS_PROXY if you use a proxy.');
  if (!opts.version && !isNewer(to, current)) return { status: 'current', from: current, to: current };

  const asset = assetName(platform, opts.arch ?? process.arch, opts.musl ?? isMusl());
  if (!asset) throw new Error(`There's no build for ${platform} ${opts.arch ?? process.arch}. Use npm: npm i -D fortis-watchdog`);
  // Same as the install scripts: a mirror, or a local folder in Fortis's own tests.
  const base = env.FORTIS_DOWNLOAD_BASE || `https://github.com/${repo}/releases/download/cli-v${to}`;
  const download = async (name: string) => {
    const res = await fetchImpl(`${base}/${name}`, { headers: { 'user-agent': 'fortis-cli' }, signal: AbortSignal.timeout(600_000) });
    if (!res.ok) throw new Error(`Could not download ${name} (HTTP ${res.status}).`);
    return Buffer.from(await res.arrayBuffer());
  };

  opts.onProgress?.(`Downloading ${asset} ...`);
  const [archive, sums] = await Promise.all([download(asset), download('SHA256SUMS')]);
  const expected = expectedHash(sums.toString('utf8'), asset);
  if (!expected) throw new Error(`${asset} isn't listed in SHA256SUMS. Not installing it.`);
  if (createHash('sha256').update(archive).digest('hex') !== expected) throw new Error(`Checksum mismatch for ${asset}. Not installing it.`);

  const dir = dirname(opts.target);
  const work = mkdtempSync(join(dir, '.fortis-update-'));
  try {
    const file = join(work, asset);
    writeFileSync(file, archive);
    extract(file, work, platform);
    const name = platform === 'win32' ? 'fortis.exe' : 'fortis';
    const fresh = join(work, name);
    if (!existsSync(fresh)) throw new Error(`${asset} has no ${name} in it.`);
    if (platform !== 'win32') chmodSync(fresh, 0o755);
    // Never swap in something that doesn't run here.
    const reported = execFileSync(fresh, ['--version'], { encoding: 'utf8', env: { ...env, FORTIS_NO_UPDATE_CHECK: '1' }, timeout: 60_000 }).trim();
    replaceBinary(opts.target, fresh, platform);
    return { status: 'updated', from: current, to: reported || to };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function extract(file: string, into: string, platform: string) {
  if (platform === 'win32') {
    // As install.ps1 does. A tar from Git for Windows on the PATH can't read zip files.
    const script = `Expand-Archive -LiteralPath '${file.replace(/'/g, "''")}' -DestinationPath '${into.replace(/'/g, "''")}' -Force`;
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { stdio: 'ignore' });
  } else {
    execFileSync('tar', ['-xzf', basename(file)], { cwd: into, stdio: 'ignore' });
  }
}

/* ---------- The once-a-day notice ---------- */

const DAY_MS = 24 * 60 * 60 * 1000;
type CheckState = { checkedAt?: number; notifiedAt?: number; latest?: string };

/** CI logs don't need it, and neither does anyone who turned it off. */
export function updateCheckEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.FORTIS_NO_UPDATE_CHECK === '1' || env.FORTIS_NO_UPDATE_CHECK === 'true') return false;
  return !['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILDKITE', 'CIRCLECI', 'JENKINS_URL', 'TF_BUILD', 'BITBUCKET_BUILD_NUMBER'].some((name) => env[name]);
}

/**
 * The message to show after a command, if any. Asks GitHub at most once a day, for at most a moment,
 * so a slow or blocked connection never holds up a push. It only prints from what it already knows.
 */
export async function updateNotice(opts: { stateFile?: string; now?: number; current?: string; fetchImpl?: typeof fetch; timeoutMs?: number; hint: string }): Promise<string | null> {
  const file = opts.stateFile ?? join(homedir(), '.fortis', 'update-check.json');
  const now = opts.now ?? Date.now();
  const current = opts.current ?? VERSION;
  let state: CheckState = {};
  try {
    state = JSON.parse(readFileSync(file, 'utf8')) as CheckState;
  } catch {
    /* first run, or an unreadable file: start again */
  }
  let changed = false;
  if (!state.checkedAt || now - state.checkedAt >= DAY_MS) {
    const latest = await latestVersion({ fetchImpl: opts.fetchImpl, timeoutMs: opts.timeoutMs ?? 1500 });
    // A failed check counts too: no retry on every command while offline.
    state.checkedAt = now;
    if (latest) state.latest = latest;
    changed = true;
  }
  let message: string | null = null;
  if (state.latest && isNewer(state.latest, current) && (!state.notifiedAt || now - state.notifiedAt >= DAY_MS)) {
    state.notifiedAt = now;
    changed = true;
    message = `A newer Fortis is available: ${current} → ${state.latest}. Update with: ${opts.hint}. Turn this off with FORTIS_NO_UPDATE_CHECK=1.`;
  }
  if (changed) {
    try {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, JSON.stringify(state));
    } catch {
      /* a read-only home folder: it just checks again next time */
    }
  }
  return message;
}
