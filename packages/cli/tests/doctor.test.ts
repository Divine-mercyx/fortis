import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import { CONFIG_JSON_SCHEMA, didYouMean, validateProjectConfig } from '../src/config-schema';
import { readProjectConfig } from '../src/config';
import { cliForHook, runDoctor, type Check, type DoctorOptions } from '../src/doctor';
import { hookStatus, installHook } from '../src/hook';

const dirs: string[] = [];
const temp = () => {
  const d = mkdtempSync(join(tmpdir(), 'fortis-doctor-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function repo() {
  const dir = temp();
  execFileSync('git', ['init', '-q', dir]);
  return dir;
}

const up = () => ({ ok: true as const });

/** A network where everything answers. Each test breaks the part it's about. */
function network(over: { osv?: () => Response | never; health?: () => Response | never; latest?: string; whoami?: () => Response; targets?: () => Response } = {}) {
  return (async (url: string | URL) => {
    const u = String(url);
    if (u.includes('/releases/latest')) return new Response(null, { status: 302, headers: { location: `https://github.com/o/r/releases/tag/cli-v${over.latest ?? '0.0.0-dev'}` } });
    if (u.includes('api.osv.dev')) return over.osv ? over.osv() : new Response('{}');
    if (u.endsWith('/health')) return over.health ? over.health() : new Response('{}');
    if (u.includes('/v1/cli/whoami')) return over.whoami ? over.whoami() : new Response(JSON.stringify({ project: { id: 'p1', name: 'Paywave' }, org: { name: 'Acme' }, plan: { name: 'Core' } }));
    if (u.includes('/v1/cli/targets')) return over.targets ? over.targets() : new Response(JSON.stringify({ plan: {}, targets: [{ id: 't', blocker: null }] }));
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;
}

/** Options for a healthy machine, with the CLI on the PATH. */
function healthy(cwd: string, over: Partial<DoctorOptions> = {}): DoctorOptions {
  const bin = temp();
  writeFileSync(join(bin, 'fortis'), '');
  writeFileSync(join(bin, 'fortis.exe'), '');
  return { cwd, env: { PATH: bin, Path: bin }, home: temp(), fetchImpl: network(), docker: up, gitVersion: () => 'git version 2.50.0', ...over };
}

const byId = (checks: Check[], id: string) => checks.filter((c) => c.id === id);
const one = (checks: Check[], id: string) => {
  const found = byId(checks, id);
  expect(found, id).toHaveLength(1);
  return found[0]!;
};
const failures = (checks: Check[]) => checks.filter((c) => c.status === 'fail');

/** A key in the environment for the length of a test. */
async function withKey<T>(key: string | undefined, run: () => Promise<T>): Promise<T> {
  const before = process.env.FORTIS_KEY;
  if (key) process.env.FORTIS_KEY = key;
  else process.env.FORTIS_KEY = '';
  try {
    return await run();
  } finally {
    if (before === undefined) delete process.env.FORTIS_KEY;
    else process.env.FORTIS_KEY = before;
  }
}

describe('a healthy repository', () => {
  it('has no failures', async () => {
    const dir = repo();
    installHook(dir);
    writeFileSync(join(dir, '.fortis.json'), '{ "failOn": "high" }');
    const checks = await withKey('fts_x', () => runDoctor(healthy(dir)));
    expect(failures(checks)).toEqual([]);
    expect(one(checks, 'key').message).toContain('Paywave');
    expect(one(checks, 'key').message).toContain('Core');
  });
});

/*
 * Every entry in the Troubleshooting section of the docs (apps/web/src/app/docs/page.tsx), except
 * "A finding is wrong", which is about a result and not something broken on the machine.
 */
describe('every troubleshooting entry in the docs', () => {
  it('"No Fortis key found": shows the fix', async () => {
    const dir = repo();
    installHook(dir);
    const check = one(await withKey(undefined, () => runDoctor(healthy(dir))), 'key');
    expect(check.status).toBe('note');
    expect(check.message).toContain('No Fortis key found');
    expect(check.fix).toContain('fortis login');
  });

  it('"found but no lockfile": fails and names it', async () => {
    const dir = repo();
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { express: '^4.0.0' } }));
    execFileSync('git', ['add', '-A'], { cwd: dir });
    const check = byId(await withKey(undefined, () => runDoctor(healthy(dir, { offline: true }))), 'lockfiles').find((c) => c.status === 'fail');
    expect(check?.message).toContain('found but no lockfile');
    expect(check?.fix).toContain('Commit the lockfile');
  });

  it('"pom.xml: checked 3 of 28 declared dependencies": shows the SBOM fix', async () => {
    const dir = repo();
    writeFileSync(join(dir, 'pom.xml'), '<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0.0</version></dependency><dependency><groupId>c</groupId><artifactId>d</artifactId></dependency></dependencies></project>');
    execFileSync('git', ['add', '-A'], { cwd: dir });
    const check = one(await withKey(undefined, () => runDoctor(healthy(dir, { offline: true }))), 'pom');
    expect(check.message).toMatch(/pom\.xml: checked 1 of 2/);
    expect(check.fix).toContain('--sbom target/bom.json');
  });

  it('"could not reach api.osv.dev": fails, proxy aware', async () => {
    const dir = repo();
    const fail = () => {
      throw Object.assign(new Error('fetch failed'), { cause: { code: 'ENOTFOUND' } });
    };
    const bare = one(await withKey(undefined, () => runDoctor(healthy(dir, { fetchImpl: network({ osv: fail }) }))), 'osv');
    expect(bare.status).toBe('fail');
    expect(bare.message).toContain('api.osv.dev');
    expect(bare.message).toContain('ENOTFOUND');
    expect(bare.fix).toContain('HTTPS_PROXY');
    expect(bare.fix).toContain('--osv-db');

    const options = healthy(dir, { fetchImpl: network({ osv: fail }) });
    options.env = { ...options.env, HTTPS_PROXY: 'http://user:hunter2@proxy.bank.local:8080' };
    const checks = await withKey(undefined, () => runDoctor(options));
    expect(one(checks, 'osv').fix).toContain('proxy.bank.local');
    expect(JSON.stringify(checks)).not.toContain('hunter2');
  });

  it('a proxy that inspects TLS: suggests the CA', async () => {
    const dir = repo();
    const fail = () => {
      throw Object.assign(new Error('fetch failed'), { cause: { code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' } });
    };
    const check = one(await withKey(undefined, () => runDoctor(healthy(dir, { fetchImpl: network({ osv: fail }) }))), 'osv');
    expect(check.fix).toContain('NODE_EXTRA_CA_CERTS');
  });

  it('"Docker is installed but not running": shows the fix without failing', async () => {
    const check = one(await withKey(undefined, () => runDoctor(healthy(repo(), { offline: true, docker: () => ({ ok: false, reason: 'Docker is installed but not running.' }) }))), 'docker');
    expect(check.status).toBe('note');
    expect(check.message).toContain('Docker is installed but not running');
    expect(check.fix).toContain('--zap-report');
  });

  it('"is not a target on this project" and "verify the domain": fail', async () => {
    const dir = repo();
    const missing = one(await withKey('fts_x', () => runDoctor(healthy(dir, { target: 'https://staging.x.ng', fetchImpl: network({ targets: () => new Response(JSON.stringify({ plan: {}, targets: [] })) }) }))), 'target');
    expect(missing.status).toBe('fail');
    expect(missing.message).toContain('is not a target on this project');
    expect(missing.fix).toContain('Staging targets');

    const blocked = one(await withKey('fts_x', () => runDoctor(healthy(dir, { target: 'https://staging.x.ng', fetchImpl: network({ targets: () => new Response(JSON.stringify({ plan: {}, targets: [{ id: 't', blocker: 'Verify the domain first.' }] })) }) }))), 'target');
    expect(blocked.status).toBe('fail');
    expect(blocked.message).toContain('Verify the domain');
  });

  it('"the CLI isn\'t installed in this repo": fails', async () => {
    const check = one(await withKey(undefined, () => runDoctor(healthy(repo(), { offline: true, env: { PATH: temp() } }))), 'path');
    expect(check.status).toBe('fail');
    expect(check.message).toContain("the CLI isn't installed in this repo");
    expect(check.fix).toContain('npm i -D fortis-watchdog');
  });

  it('"the hook didn\'t run": fails when it is missing', async () => {
    const check = one(await withKey(undefined, () => runDoctor(healthy(repo(), { offline: true }))), 'hook');
    expect(check.status).toBe('fail');
    expect(check.fix).toBe('Run: fortis init');
  });
});

describe('the other problems the issue names', () => {
  it('a newer version: shows it without failing', async () => {
    const check = one(await withKey(undefined, () => runDoctor(healthy(repo(), { fetchImpl: network({ latest: '99.0.0' }) }))), 'version');
    expect(check.status).toBe('note');
    expect(check.message).toContain('99.0.0');
  });

  it('a refused key: fails', async () => {
    const dir = repo();
    const check = one(await withKey('fts_x', () => runDoctor(healthy(dir, { fetchImpl: network({ whoami: () => new Response(JSON.stringify({ error: { code: 'X', message: 'bad' } }), { status: 401 }) }) }))), 'key');
    expect(check.status).toBe('fail');
    expect(check.fix).toContain('new key');
  });

  it('a linked project with no key, or the wrong key: fails', async () => {
    const dir = repo();
    writeFileSync(join(dir, '.fortis.json'), '{ "projectId": "other" }');
    const none = one(await withKey(undefined, () => runDoctor(healthy(dir))), 'key');
    expect(none.status).toBe('fail');
    const wrong = one(await withKey('fts_x', () => runDoctor(healthy(dir))), 'key');
    expect(wrong.status).toBe('fail');
    expect(wrong.message).toContain('Paywave');
  });

  it('an unreachable API: only a problem with a key', async () => {
    const fail = () => {
      throw new Error('down');
    };
    const dir = repo();
    expect(one(await withKey(undefined, () => runDoctor(healthy(dir, { fetchImpl: network({ health: fail }) }))), 'api').status).toBe('note');
    const withOne = await withKey('fts_x', () => runDoctor(healthy(dir, { fetchImpl: network({ health: fail }) })));
    expect(one(withOne, 'api').status).toBe('fail');
    expect(byId(withOne, 'key')).toEqual([]);
  });

  it('a broken or mistyped config: fails with a suggestion', async () => {
    const dir = repo();
    writeFileSync(join(dir, '.fortis.json'), '{ "failon": "high" }');
    let check = one(await withKey(undefined, () => runDoctor(healthy(dir, { offline: true }))), 'config');
    expect(check.status).toBe('fail');
    expect(check.message).toContain('Did you mean "failOn"?');
    writeFileSync(join(dir, '.fortis.json'), '{ not json');
    check = one(await withKey(undefined, () => runDoctor(healthy(dir, { offline: true }))), 'config');
    expect(check.status).toBe('fail');
    expect(check.message).toContain("isn't valid JSON");
  });

  it('no git, an old git, a shallow clone and no repository', async () => {
    const dir = repo();
    const none = await withKey(undefined, () => runDoctor(healthy(dir, { offline: true, gitVersion: () => null })));
    expect(one(none, 'git').status).toBe('fail');
    const old = await withKey(undefined, () => runDoctor(healthy(dir, { offline: true, gitVersion: () => 'git version 2.20.1' })));
    expect(one(old, 'git').status).toBe('note');

    const outside = await withKey(undefined, () => runDoctor(healthy(temp(), { offline: true })));
    expect(one(outside, 'repository').status).toBe('note');
    expect(byId(outside, 'hook')).toEqual([]);
  });

  it('skips the network when offline', async () => {
    const checks = await withKey('fts_x', () => runDoctor(healthy(repo(), { offline: true, fetchImpl: (async () => { throw new Error('no network calls'); }) as unknown as typeof fetch })));
    for (const id of ['osv', 'api', 'key', 'target']) expect(byId(checks, id), id).toEqual([]);
  });

  it('expects no hook in CI', async () => {
    const options = healthy(repo(), { offline: true });
    options.env = { ...options.env, CI: 'true' };
    expect(one(await withKey(undefined, () => runDoctor(options)), 'hook').status).toBe('note');
  });
});

describe('the hook git will run', () => {
  const hookFile = (dir: string) => join(dir, '.git', 'hooks', 'pre-push');

  it('is missing, then current', () => {
    const dir = repo();
    expect(hookStatus(dir).state).toBe('missing');
    installHook(dir);
    expect(hookStatus(dir).state).toBe('current');
  });

  it('is outdated when an earlier version wrote it', () => {
    const dir = repo();
    writeFileSync(hookFile(dir), '#!/bin/sh\n# fortis-pre-push\nnpx --no-install fortis scan --pre-push\n');
    expect(hookStatus(dir).state).toBe('outdated');
  });

  it("is someone else's when it never mentions Fortis", () => {
    const dir = repo();
    writeFileSync(hookFile(dir), '#!/bin/sh\necho mine\n');
    expect(hookStatus(dir).state).toBe('foreign');
  });

  it('is not executable, except on Windows where that means nothing', () => {
    const dir = repo();
    installHook(dir);
    chmodSync(hookFile(dir), 0o644);
    if (process.platform !== 'win32') expect(hookStatus(dir, 'linux').state).toBe('not-executable');
    expect(hookStatus(dir, 'win32').state).toBe('current');
  });

  it('follows core.hooksPath', () => {
    const dir = repo();
    execFileSync('git', ['config', 'core.hooksPath', 'custom-hooks'], { cwd: dir });
    expect(hookStatus(dir).state).toBe('missing');
    expect(hookStatus(dir).path).toContain('custom-hooks');
    installHook(dir);
    expect(hookStatus(dir).state).toBe('current');
  });

  it('recognises Husky, with and without Fortis', () => {
    const dir = repo();
    mkdirSync(join(dir, '.husky', '_'), { recursive: true });
    execFileSync('git', ['config', 'core.hooksPath', '.husky/_'], { cwd: dir });
    expect(hookStatus(dir).state).toBe('husky-without-fortis');
    installHook(dir);
    expect(hookStatus(dir).state).toBe('generated');
    writeFileSync(join(dir, '.husky', 'pre-push'), 'npx --no-install fortis scan --pre-push --stdin\n');
    expect(hookStatus(dir)).toMatchObject({ state: 'managed', manager: 'Husky' });
  });

  it('recognises lefthook and pre-commit when they run Fortis', () => {
    const dir = repo();
    writeFileSync(hookFile(dir), '#!/bin/sh\ncall_lefthook run pre-push\n');
    expect(hookStatus(dir).state).toBe('foreign');
    writeFileSync(join(dir, 'lefthook.yml'), 'pre-push:\n  commands:\n    fortis:\n      run: fortis scan --pre-push --stdin\n');
    expect(hookStatus(dir)).toMatchObject({ state: 'managed', manager: 'lefthook' });

    const other = repo();
    writeFileSync(hookFile(other), '#!/bin/sh\nexec pre-commit hook-impl\n');
    writeFileSync(join(other, '.pre-commit-config.yaml'), 'repos:\n  - hooks:\n      - id: fortis\n');
    expect(hookStatus(other)).toMatchObject({ state: 'managed', manager: 'pre-commit' });
  });
});

describe('where the hook finds the CLI', () => {
  const find = (exists: string[], over: { platform?: string; env?: NodeJS.ProcessEnv } = {}) =>
    cliForHook('/r', { env: over.env ?? {}, platform: over.platform ?? 'linux', home: '/h', exists: (p) => exists.includes(p.replace(/\\/g, '/')) });

  it('looks in the project, then PATH, then ~/.fortis/bin, then uv and Poetry', () => {
    expect(find(['/r/node_modules/.bin/fortis', '/p/fortis'], { env: { PATH: '/p' } })).toBe('node_modules/.bin/fortis');
    expect(find(['/r/.venv/bin/fortis'])).toBe('.venv/bin/fortis');
    expect(find(['/r/.pnp.cjs'])).toBe('.pnp.cjs');
    expect(find(['/p/fortis'], { env: { PATH: '/p' } })?.replace(/\\/g, '/')).toBe('/p/fortis');
    expect(find(['/h/.fortis/bin/fortis'])?.replace(/\\/g, '/')).toBe('/h/.fortis/bin/fortis');
    expect(find(['/r/uv.lock'])).toBe('uv run fortis');
    expect(find([])).toBeNull();
  });
});

describe('.fortis.json validation', () => {
  it('accepts every documented setting', () => {
    expect(validateProjectConfig({ $schema: 'x', projectId: 'p', failOn: 'high', ignore: ['a/**'], apiUrl: 'https://a.ng', target: 'http://s.ng' })).toEqual([]);
    expect(validateProjectConfig({})).toEqual([]);
  });

  it('flags unknown settings, with a suggestion when one is close', () => {
    expect(validateProjectConfig({ failon: 'high' })[0]!.message).toContain('Did you mean "failOn"?');
    expect(validateProjectConfig({ ignored: [] })[0]!.message).toContain('Did you mean "ignore"?');
    expect(validateProjectConfig({ traget: 'https://a.ng' })[0]!.message).toContain('Did you mean "target"?');
    expect(validateProjectConfig({ somethingElse: 1 })[0]!.message).not.toContain('Did you mean');
  });

  it('flags wrong types and values', () => {
    expect(validateProjectConfig({ failOn: 'hgih' })[0]!.message).toContain('Did you mean "high"?');
    expect(validateProjectConfig({ failOn: 3 })[0]!.message).toContain('must be one of');
    expect(validateProjectConfig({ ignore: 'fixtures/**' })[0]!.message).toContain('a list of paths');
    expect(validateProjectConfig({ ignore: [1] })[0]!.message).toContain('a list of paths');
    expect(validateProjectConfig({ apiUrl: 'not a url' })[0]!.message).toContain('http(s) URL');
    expect(validateProjectConfig({ target: 'ftp://a.ng' })[0]!.message).toContain('http(s) URL');
    expect(validateProjectConfig({ projectId: 3 })[0]!.message).toContain('must be text');
    expect(validateProjectConfig([])[0]!.message).toContain('JSON object');
    expect(validateProjectConfig(null)[0]!.message).toContain('JSON object');
  });

  it('suggests only what is close', () => {
    expect(didYouMean('FAILON', ['failOn', 'ignore'])).toBe('failOn');
    expect(didYouMean('zzzzzzzzzz', ['failOn', 'ignore'])).toBeNull();
  });

  it('publishes the same schema it checks with, in the npm package', () => {
    const cli = join(__dirname, '..');
    expect(JSON.parse(readFileSync(join(cli, 'fortis.schema.json'), 'utf8'))).toEqual(JSON.parse(JSON.stringify(CONFIG_JSON_SCHEMA)));
    expect((JSON.parse(readFileSync(join(cli, 'package.json'), 'utf8')) as { files: string[] }).files).toContain('fortis.schema.json');
  });

  it('drops an ignore that is not a list, rather than reading it letter by letter', () => {
    const dir = repo();
    writeFileSync(join(dir, '.fortis.json'), '{ "ignore": "fixtures/**" }');
    expect(readProjectConfig(dir).ignore).toBeUndefined();
  });
});

describe('fortis doctor on the command line', () => {
  const cli = join(__dirname, '..', 'src', 'index.ts');
  const tsx = join(__dirname, '..', 'node_modules', 'tsx', 'dist', 'cli.mjs');
  const fortis = (cwd: string, ...args: string[]) => spawnSync(process.execPath, [tsx, cli, ...args], { cwd, encoding: 'utf8', env: { ...process.env, FORTIS_KEY: '', CI: '', HOME: cwd, USERPROFILE: cwd, NO_COLOR: '1' } });

  it('exits 1 and prints the fix when there is a problem', () => {
    const dir = repo();
    const r = fortis(dir, 'doctor', '--offline');
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('No pre-push hook');
    expect(r.stdout).toContain('Run: fortis init');
    expect(r.stdout).toMatch(/\d+ problems? to fix/);
  }, 60_000);

  it('gives machine-readable results with --json', () => {
    const dir = repo();
    const r = fortis(dir, 'doctor', '--offline', '--json');
    const out = JSON.parse(r.stdout) as { problems: number; checks: Check[] };
    expect(r.status).toBe(1);
    expect(out.problems).toBeGreaterThan(0);
    expect(out.checks.find((c) => c.id === 'hook')?.status).toBe('fail');
  }, 60_000);

  it('warns about a typo on stderr, and keeps --json clean', () => {
    const dir = repo();
    writeFileSync(join(dir, '.fortis.json'), '{ "failon": "high" }');
    writeFileSync(join(dir, 'a.js'), 'const a = 1;\n');
    execFileSync('git', ['add', '-A'], { cwd: dir });
    const r = fortis(dir, 'scan', '--offline', '--no-upload', '--json');
    expect(r.stderr).toContain('Did you mean "failOn"?');
    expect(() => JSON.parse(r.stdout) as unknown).not.toThrow();
  }, 60_000);

  it('adds the schema line when fortis init writes the config', () => {
    const dir = repo();
    expect(fortis(dir, 'init', '--no-hook').status).toBe(0);
    expect((JSON.parse(readFileSync(join(dir, '.fortis.json'), 'utf8')) as { $schema: string }).$schema).toContain('fortis.schema.json');
  }, 60_000);
});
