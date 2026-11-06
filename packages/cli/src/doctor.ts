import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';

import { ApiError, client } from './api';
import { validateProjectConfig } from './config-schema';
import { PROJECT_CONFIG, resolveKey, type ProjectConfig } from './config';
import { dockerAvailable } from './dast';
import { apiUrl, RELEASE_REPO, VERSION } from './env';
import { allFiles, checkoutInfo, repoRoot } from './git';
import { hookStatus } from './hook';
import { redact } from './net';
import { readPackages } from './rules/dependencies';
import { compareVersions } from './rules/fix-version';
import { findLockfiles } from './rules/lockfiles';

/*
 * `fortis doctor`: finds why Fortis isn't working, and says what to do about it.
 *  ok:   fine.
 *  note: worth knowing, but nothing is broken (no key on the free plan, no Docker if you never run fortis test).
 *  fail: Fortis can't do its job here. The command exits 1.
 */

export type CheckStatus = 'ok' | 'note' | 'fail';
export type Check = { id: string; status: CheckStatus; message: string; fix?: string };

export type DoctorOptions = {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  platform?: string;
  execPath?: string;
  home?: string;
  /** Skip every check that needs the network. */
  offline?: boolean;
  target?: string;
  fetchImpl?: typeof fetch;
  gitVersion?: () => string | null;
  docker?: () => { ok: true } | { ok: false; reason: string };
};

const inCi = (env: NodeJS.ProcessEnv) => Boolean(env.CI);

function networkFix(error: unknown, env: NodeJS.ProcessEnv): string {
  const e = error as { message?: string; cause?: { code?: string; message?: string } };
  const text = `${e.message ?? ''} ${e.cause?.code ?? ''} ${e.cause?.message ?? ''}`;
  if (/cert|self.signed|UNABLE_TO_VERIFY|SSL|TLS/i.test(text)) return 'Your network may inspect TLS with its own certificate. Give Fortis the CA: set NODE_EXTRA_CA_CERTS=/path/ca.pem, or pass --ca /path/ca.pem.';
  const proxy = env.HTTPS_PROXY ?? env.https_proxy ?? env.HTTP_PROXY ?? env.http_proxy;
  if (proxy) return `Check the proxy (${redact(proxy)}), or set NO_PROXY for this host.`;
  return 'Allow this host through your firewall. Behind a company proxy, set HTTPS_PROXY.';
}

const describeError = (error: unknown) => {
  const e = error as { message?: string; cause?: { code?: string } };
  return e.cause?.code ?? e.message ?? 'unknown error';
};

function checkVersion(latest: string | null): Check {
  if (!latest) return { id: 'version', status: 'note', message: `Fortis ${VERSION}. Couldn't check for a newer version.` };
  if (compareVersions(latest, VERSION) > 0) {
    return { id: 'version', status: 'note', message: `Fortis ${VERSION}. A newer version exists: ${latest}.`, fix: 'Update it the way you installed it. The Install section of the docs has each method.' };
  }
  return { id: 'version', status: 'ok', message: `Fortis ${VERSION} is up to date.` };
}

async function latestRelease(fetchImpl: typeof fetch): Promise<string | null> {
  try {
    const res = await fetchImpl(`https://github.com/${RELEASE_REPO}/releases/latest`, { method: 'HEAD', redirect: 'manual', headers: { 'user-agent': 'fortis-cli' }, signal: AbortSignal.timeout(10_000) });
    return /\/tag\/cli-v([^/?#]+)$/.exec(res.headers.get('location') ?? '')?.[1] ?? null;
  } catch {
    return null;
  }
}

/** Where the git hook would find the CLI, in the same order the hook looks. Null if nowhere. */
export function cliForHook(root: string, opts: { env: NodeJS.ProcessEnv; platform: string; home: string; exists?: (p: string) => boolean }): string | null {
  const exists = opts.exists ?? existsSync;
  const windows = opts.platform === 'win32';
  const inProject = [
    'node_modules/.bin/fortis',
    'node_modules/.bin/fortis.exe',
    '.pnp.cjs',
    '.venv/bin/fortis',
    'venv/bin/fortis',
    '.venv/Scripts/fortis.exe',
    'venv/Scripts/fortis.exe',
  ];
  for (const rel of inProject) if (exists(join(root, rel))) return rel;
  const names = windows ? ['fortis.exe', 'fortis.cmd', 'fortis'] : ['fortis'];
  for (const dir of (opts.env.PATH ?? opts.env.Path ?? '').split(windows ? ';' : ':').filter(Boolean)) {
    for (const name of names) if (exists(join(dir, name))) return join(dir, name);
  }
  for (const name of names) {
    const path = join(opts.home, '.fortis', 'bin', name);
    if (exists(path)) return path;
  }
  for (const lock of ['uv.lock', 'poetry.lock']) if (exists(join(root, lock))) return `${lock === 'uv.lock' ? 'uv' : 'poetry'} run fortis`;
  return null;
}

function checkInstall(root: string | null, o: Required<Pick<DoctorOptions, 'env' | 'platform' | 'execPath' | 'home'>> & Pick<DoctorOptions, 'cwd'>): Check[] {
  const asBinary = /^fortis(\.exe)?$/i.test(basename(o.execPath));
  const where = asBinary ? o.execPath : (process.argv[1] ?? o.execPath);
  const method = asBinary ? 'as a standalone binary' : `as a script on Node ${process.versions.node}`;
  const checks: Check[] = [{ id: 'install', status: 'ok', message: `Running ${method}: ${where}` }];
  if (!asBinary) {
    const [major = 0, minor = 0] = process.versions.node.split('.').map(Number);
    if (major < 18 || (major === 18 && minor < 17)) checks.push({ id: 'node', status: 'fail', message: `Node ${process.versions.node} is too old. Fortis needs 18.17 or newer.`, fix: 'Upgrade Node, or use the standalone binary, which needs no Node.' });
  }
  const found = cliForHook(root ?? o.cwd, { env: o.env, platform: o.platform, home: o.home });
  if (found) checks.push({ id: 'path', status: 'ok', message: `Git hooks can find the CLI: ${found}` });
  else {
    checks.push({
      id: 'path',
      status: 'fail',
      message: 'The git hook can\'t find the CLI, so pushes will be stopped with "the CLI isn\'t installed in this repo".',
      fix: 'Install it in the project (npm i -D fortis-watchdog, or pip install fortis-watchdog), or add its folder to your PATH.',
    });
  }
  return checks;
}

function checkHook(root: string, env: NodeJS.ProcessEnv, platform: string): Check {
  const hook = hookStatus(root, platform);
  const at = hook.path ? ` (${hook.path})` : '';
  switch (hook.state) {
    case 'current':
      return { id: 'hook', status: 'ok', message: `The pre-push hook is installed and current${at}.` };
    case 'managed':
      return { id: 'hook', status: 'ok', message: `${hook.manager} runs Fortis on push${at}.` };
    case 'generated':
      return { id: 'hook', status: 'note', message: `The hook is in Husky's generated folder${at}, and Husky can overwrite it.`, fix: 'Add this line to .husky/pre-push: npx --no-install fortis scan --pre-push --stdin' };
    case 'husky-without-fortis':
      return { id: 'hook', status: 'fail', message: 'This repository uses Husky, and .husky/pre-push doesn\'t run Fortis.', fix: 'Add this line to .husky/pre-push: npx --no-install fortis scan --pre-push --stdin' };
    case 'outdated':
      return { id: 'hook', status: 'fail', message: `The pre-push hook is from an older version${at}.`, fix: 'Run: fortis init' };
    case 'not-executable':
      return { id: 'hook', status: 'fail', message: `The pre-push hook isn't executable, so git skips it${at}.`, fix: `Run: chmod +x ${hook.path}` };
    case 'foreign':
      return { id: 'hook', status: 'fail', message: `A pre-push hook exists${at}, but it doesn't run Fortis.`, fix: 'Run: fortis init. It adds Fortis and keeps your own lines.' };
    default:
      // CI checks with a scan step, not a hook.
      if (inCi(env)) return { id: 'hook', status: 'note', message: 'No pre-push hook. That\'s normal in CI, where a scan step does the checking.' };
      return { id: 'hook', status: 'fail', message: `No pre-push hook, so pushes aren't checked${at}.`, fix: 'Run: fortis init' };
  }
}

function checkConfig(root: string): Check {
  const path = join(root, PROJECT_CONFIG);
  if (!existsSync(path)) return { id: 'config', status: 'note', message: `No ${PROJECT_CONFIG} yet, so the defaults apply.`, fix: 'Run: fortis init' };
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
  } catch (e) {
    return { id: 'config', status: 'fail', message: `${PROJECT_CONFIG} isn't valid JSON: ${(e as Error).message}`, fix: `Fix the JSON in ${PROJECT_CONFIG}.` };
  }
  const issues = validateProjectConfig(raw);
  if (!issues.length) return { id: 'config', status: 'ok', message: `${PROJECT_CONFIG} is valid.` };
  return { id: 'config', status: 'fail', message: `${PROJECT_CONFIG}: ${issues.map((i) => i.message).join(' ')}`, fix: `Correct ${issues.length === 1 ? 'that setting' : 'those settings'} in ${PROJECT_CONFIG}.` };
}

function checkGit(o: DoctorOptions, root: string | null): Check[] {
  const run = o.gitVersion ?? (() => {
    try {
      return execFileSync('git', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      return null;
    }
  });
  const output = run();
  if (!output) return [{ id: 'git', status: 'fail', message: 'git isn\'t installed, or isn\'t on your PATH. Scans and hooks need it.', fix: 'Install git from https://git-scm.com/downloads.' }];
  const version = /(\d+\.\d+(?:\.\d+)?)/.exec(output)?.[1] ?? output;
  const checks: Check[] = [];
  if (compareVersions(version, '2.31') < 0) checks.push({ id: 'git', status: 'note', message: `git ${version} is old. Hooks in worktrees need 2.31 or newer.`, fix: 'Upgrade git.' });
  else checks.push({ id: 'git', status: 'ok', message: `git ${version}.` });
  if (!root) {
    checks.push({ id: 'repository', status: 'note', message: 'This folder isn\'t a git repository, so the hook, config and lockfile checks were skipped.', fix: 'Run fortis doctor inside your repository.' });
    return checks;
  }
  if (checkoutInfo(root).shallow) checks.push({ id: 'shallow', status: 'note', message: 'This is a shallow clone, so --history and branch comparisons only see part of it.', fix: 'In CI, set fetch-depth: 0 on actions/checkout, or GIT_DEPTH: 0 on GitLab.' });
  return checks;
}

function checkLockfiles(root: string, config: ProjectConfig): Check[] {
  const paths = allFiles(root);
  const files = findLockfiles(paths, config.ignore);
  const { notes } = readPackages(root, files, { allPaths: paths, ignore: config.ignore });
  const checks: Check[] = [];
  if (files.length) checks.push({ id: 'lockfiles', status: 'ok', message: `Found ${files.length} lockfile${files.length === 1 ? '' : 's'}: ${files.slice(0, 5).join(', ')}${files.length > 5 ? ` and ${files.length - 5} more` : ''}.` });
  else if (!notes.length) checks.push({ id: 'lockfiles', status: 'note', message: 'No lockfiles here, so there are no dependencies to check.' });
  for (const note of notes) {
    if (/found but no lockfile/.test(note)) checks.push({ id: 'lockfiles', status: 'fail', message: note, fix: 'Commit the lockfile it names. If your tool has none, pass --sbom with a CycloneDX file.' });
    else if (/^pom\.xml:/.test(note)) checks.push({ id: 'pom', status: 'note', message: note, fix: 'Generate a CycloneDX SBOM with Maven, and pass --sbom target/bom.json. fortis ci init adds this step on GitHub Actions.' });
    else checks.push({ id: 'dependencies', status: 'note', message: note });
  }
  return checks;
}

async function checkOsv(fetchImpl: typeof fetch, env: NodeJS.ProcessEnv): Promise<Check> {
  try {
    const res = await fetchImpl('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'fortis-cli' },
      // One public package that has nothing to do with this project.
      body: JSON.stringify({ package: { ecosystem: 'npm', name: 'left-pad' }, version: '1.3.0' }),
      signal: AbortSignal.timeout(20_000),
    });
    if (res.ok) return { id: 'osv', status: 'ok', message: 'OSV can be reached, so dependency checks will work.' };
    return { id: 'osv', status: 'fail', message: `OSV answered HTTP ${res.status}, so dependency checks will be skipped.`, fix: 'Allow https://api.osv.dev through your proxy or firewall. With no internet at all, use --osv-db.' };
  } catch (e) {
    return { id: 'osv', status: 'fail', message: `Could not reach api.osv.dev (${describeError(e)}), so dependency checks will be skipped.`, fix: `${networkFix(e, env)} With no internet at all, use --osv-db.` };
  }
}

async function checkApi(api: string, hasKey: boolean, fetchImpl: typeof fetch, env: NodeJS.ProcessEnv): Promise<Check> {
  const trouble = (message: string, fix: string): Check => (hasKey ? { id: 'api', status: 'fail', message, fix } : { id: 'api', status: 'note', message: `${message} You have no key, so nothing needs it yet.` });
  try {
    // A long wait, because a server on a free plan can take a minute to wake up.
    const res = await fetchImpl(`${api}/health`, { headers: { 'user-agent': 'fortis-cli' }, signal: AbortSignal.timeout(75_000) });
    if (res.ok) return { id: 'api', status: 'ok', message: `The Fortis API can be reached: ${api}` };
    return trouble(`The Fortis API at ${api} answered HTTP ${res.status}.`, 'Try again in a minute. If you set apiUrl or FORTIS_API_URL, check that address.');
  } catch (e) {
    return trouble(`Could not reach the Fortis API at ${api} (${describeError(e)}).`, networkFix(e, env));
  }
}

async function checkKey(api: string, key: string | undefined, config: ProjectConfig, fetchImpl: typeof fetch): Promise<Check> {
  if (!key) {
    return {
      id: 'key',
      status: config.projectId ? 'fail' : 'note',
      message: config.projectId ? `This repository is linked to a Fortis project, but no key was found, so only the free checks will run.` : 'No Fortis key found, so only the free secrets and dependency checks run.',
      fix: 'Run: fortis login fts_…, or set FORTIS_KEY.',
    };
  }
  try {
    const who = await client(api, key, fetchImpl).whoami();
    if (config.projectId && who.project.id !== config.projectId) {
      return { id: 'key', status: 'fail', message: `This key is for the project "${who.project.name}", but ${PROJECT_CONFIG} names a different one.`, fix: 'Use a key from the right project, or run: fortis init' };
    }
    return { id: 'key', status: 'ok', message: `Key for ${who.project.name} in ${who.org.name}, on the ${who.plan.name} plan.` };
  } catch (e) {
    if ((e as ApiError).status === 401) return { id: 'key', status: 'fail', message: 'The Fortis key was refused.', fix: 'Create a new key in the dashboard, then run: fortis login fts_…' };
    return { id: 'key', status: 'fail', message: `Couldn't check the key: ${(e as Error).message}`, fix: 'Fix the connection to the Fortis API first.' };
  }
}

async function checkTarget(api: string, key: string, rawTarget: string, fetchImpl: typeof fetch): Promise<Check> {
  let origin: string;
  try {
    origin = new URL(rawTarget).origin;
  } catch {
    return { id: 'target', status: 'fail', message: `"${rawTarget}" isn't a URL.`, fix: 'Use a full address, like https://staging.yourapp.com.' };
  }
  try {
    const target = (await client(api, key, fetchImpl).targets(origin)).targets[0];
    if (!target) return { id: 'target', status: 'fail', message: `${origin} is not a target on this project.`, fix: 'Add it under Project → Staging targets, add the TXT record, check it, and have an admin authorise testing.' };
    if (target.blocker) return { id: 'target', status: 'fail', message: `${origin}: ${target.blocker}`, fix: 'Finish its setup under Project → Staging targets.' };
    return { id: 'target', status: 'ok', message: `${origin} is ready to test.` };
  } catch (e) {
    return { id: 'target', status: 'note', message: `Couldn't check ${origin}: ${(e as Error).message}` };
  }
}

function checkDocker(docker: NonNullable<DoctorOptions['docker']>): Check {
  const result = docker();
  if (result.ok) return { id: 'docker', status: 'ok', message: 'Docker is running, so fortis test can run ZAP.' };
  return { id: 'docker', status: 'note', message: `${result.reason} Only fortis test needs it.`, fix: 'Install or start Docker, or run ZAP yourself and pass --zap-report report.json.' };
}

const readRaw = (root: string): ProjectConfig => {
  try {
    const raw = JSON.parse(readFileSync(join(root, PROJECT_CONFIG), 'utf8').replace(/^﻿/, '')) as ProjectConfig;
    return raw && typeof raw === 'object' ? { ...raw, ignore: Array.isArray(raw.ignore) ? raw.ignore : undefined } : {};
  } catch {
    return {};
  }
};

export async function runDoctor(options: DoctorOptions): Promise<Check[]> {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const execPath = options.execPath ?? process.execPath;
  const home = options.home ?? homedir();
  const fetchImpl = options.fetchImpl ?? fetch;
  const root = repoRoot(options.cwd);
  const config = root ? readRaw(root) : {};
  const api = apiUrl(typeof config.apiUrl === 'string' ? config.apiUrl : undefined);
  const key = resolveKey(api);

  const checks: Check[] = [];
  checks.push(options.offline ? { id: 'version', status: 'ok', message: `Fortis ${VERSION}.` } : checkVersion(await latestRelease(fetchImpl)));
  checks.push(...checkInstall(root, { cwd: options.cwd, env, platform, execPath, home }));
  checks.push(...checkGit(options, root));
  if (root) {
    checks.push(checkConfig(root));
    checks.push(checkHook(root, env, platform));
    checks.push(...checkLockfiles(root, config));
  }
  if (!options.offline) {
    const proxy = env.HTTPS_PROXY ?? env.https_proxy ?? env.HTTP_PROXY ?? env.http_proxy;
    if (proxy) checks.push({ id: 'proxy', status: 'ok', message: `Using the proxy ${redact(proxy)}.` });
    checks.push(await checkOsv(fetchImpl, env));
    const reachable = await checkApi(api, Boolean(key), fetchImpl, env);
    checks.push(reachable);
    // A key can't be checked with no connection, and that's already been reported.
    if (reachable.status === 'ok' || !key) {
      checks.push(await checkKey(api, key, config, fetchImpl));
      const target = options.target ?? (typeof config.target === 'string' ? config.target : undefined);
      if (key && target && reachable.status === 'ok') checks.push(await checkTarget(api, key, target, fetchImpl));
    }
  }
  checks.push(checkDocker(options.docker ?? dockerAvailable));
  return checks;
}
