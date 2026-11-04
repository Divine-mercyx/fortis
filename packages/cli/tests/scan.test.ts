import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { toUpload } from '../src/api';
import { installHook } from '../src/hook';
import { changedFiles, parsePushRefs } from '../src/git';
import { missingLockfileNote, runScan } from '../src/scan';

const PAYSTACK_LIVE = ['sk', 'live', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4'].join('_');
const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));

function repo(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'fortis-cli-'));
  dirs.push(dir);
  const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  g('init', '-q', '-b', 'main');
  g('config', 'user.email', 't@example.com');
  g('config', 'user.name', 'Test');
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), text);
  }
  g('add', '-A');
  g('commit', '-q', '-m', 'init');
  return { dir, g };
}

const VULN = {
  'src/config.ts': `export const PAYSTACK = '${PAYSTACK_LIVE}';\n`,
  'src/routes/transfers.ts': `router.get('/transfers/:id', async (req, res) => {\n  res.json(await Transfer.findById(req.params.id));\n});\n`,
  'node_modules/lib/index.js': `const k = '${PAYSTACK_LIVE}';\n`,
  'logo.png': 'not really an image',
};

describe('runScan', () => {
  it('finds issues across the repo, skipping node_modules and binaries, sorted by severity', async () => {
    const { dir } = repo(VULN);
    const r = await runScan({ root: dir, scope: 'full', packs: ['secrets', 'dependencies', 'fintech'], offline: true });
    expect(r.detections.map((d) => `${d.ruleId}@${d.file}:${d.line}`)).toEqual([
      'FX-SEC-001@src/config.ts:1',
      'FX-OWN-001@src/routes/transfers.ts:2',
    ]);
    expect(r.filesScanned).toBe(2);
  });

  it('runs only the packs the plan allows', async () => {
    const { dir } = repo(VULN);
    const r = await runScan({ root: dir, scope: 'full', packs: ['secrets', 'dependencies'], offline: true });
    // Free plan: leaked payment keys are secrets, so they are caught; fintech code rules are not run.
    expect(r.detections.map((d) => d.ruleId)).toEqual(['FX-SEC-001']);
  });

  it('says when the dependency check could not run instead of reporting a clean result', () => {
    const none = repo({ 'package.json': '{}' }).dir;
    expect(missingLockfileNote(none)).toMatch(/no lockfile/);
    const pnpm = repo({ 'package.json': '{}', 'pnpm-lock.yaml': "lockfileVersion: '9.0'\n" }).dir;
    expect(missingLockfileNote(pnpm)).toBeNull();
    const bun = repo({ 'package.json': '{}', 'bun.lockb': 'x' }).dir;
    expect(missingLockfileNote(bun)).toMatch(/bun\.lockb is not supported/);
    const npm = repo({ 'package.json': '{}', 'package-lock.json': '{}' }).dir;
    expect(missingLockfileNote(npm)).toBeNull();
    expect(missingLockfileNote(repo({ 'main.go': 'package main\n' }).dir)).toBeNull();
  });

  it('pre-push scope skips files already on the remote', async () => {
    const { dir, g } = repo({ 'src/old.ts': `const k = '${PAYSTACK_LIVE}';\n` });
    const remote = mkdtempSync(join(tmpdir(), 'fortis-remote-'));
    dirs.push(remote);
    execFileSync('git', ['init', '-q', '--bare', remote]);
    g('remote', 'add', 'origin', remote);
    g('push', '-q', '--no-verify', '-u', 'origin', 'main');
    writeFileSync(join(dir, 'src/new.ts'), `logger.info({ bvn: customer.bvn });\n`);
    g('add', '-A');
    g('commit', '-q', '-m', 'add');
    const r = await runScan({ root: dir, scope: 'changed', packs: ['fintech', 'secrets'], offline: true });
    expect(r.detections.map((d) => d.file)).toEqual(['src/new.ts']);
  });

  it('respects ignore globs from .fortis.json', async () => {
    const { dir } = repo(VULN);
    const r = await runScan({ root: dir, scope: 'full', packs: ['secrets', 'fintech'], ignore: ['src/routes/**'], offline: true });
    expect(r.detections.map((d) => d.ruleId)).toEqual(['FX-SEC-001']);
  });

  it('checks dependencies with OSV and maps severity', async () => {
    const { dir } = repo({
      'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/axios': { version: '0.21.1' }, 'node_modules/left-pad': { version: '1.3.0' } } }),
    });
    const fake: typeof fetch = async (url) => {
      const u = String(url);
      if (u.endsWith('/v1/querybatch')) return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-xxxx' }] }, {}] }));
      return new Response(JSON.stringify({ id: 'GHSA-xxxx', summary: 'SSRF in axios', aliases: ['CVE-2021-3749'], database_specific: { severity: 'HIGH' } }));
    };
    const r = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], fetchImpl: fake });
    expect(r.packagesChecked).toBe(2);
    expect(r.detections).toHaveLength(1);
    expect(r.detections[0]).toMatchObject({ ruleId: 'DEP-OSV', severity: 'high', file: 'package-lock.json' });
    expect(r.detections[0]!.snippet).toContain('CVE-2021-3749');
  });
});

describe('test files', () => {
  it('skips fintech checks in tests but still catches real secrets there', async () => {
    const { dir } = repo({
      'tests/device.test.ts': `await request(app).post('/api/v1/wallet/transfer').send({});\nconst k = '${PAYSTACK_LIVE}';\n`,
    });
    const r = await runScan({ root: dir, scope: 'full', packs: ['fintech', 'secrets'], offline: true });
    expect(r.detections.map((d) => d.ruleId)).toEqual(['FX-SEC-001']);
  });
});

describe('upload payload and hook', () => {
  it('does not mask ordinary URL paths', () => {
    const p = toUpload({ ruleId: 'FX-IDEM-001', severity: 'high', title: 't', file: 'a.ts', line: 1, snippet: "router.post('/api/v1/wallet/transfer-to-beneficiary', handler)" });
    expect(p.snippet).toContain('/api/v1/wallet/transfer-to-beneficiary');
  });

  it('masks the secret before anything leaves the machine', () => {
    const p = toUpload({ ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live key', file: 'a.ts', line: 1, snippet: `const k = '${PAYSTACK_LIVE}'` });
    expect(p.snippet).not.toContain(PAYSTACK_LIVE);
    expect(p.snippet).toContain('sk_live_••••••••');
  });

  it('installs the pre-push hook once and appends to an existing hook', () => {
    const { dir } = repo({ 'a.txt': 'x' });
    expect(installHook(dir).status).toBe('installed');
    expect(installHook(dir).status).toBe('already');
    const hook = readFileSync(join(dir, '.git/hooks/pre-push'), 'utf8');
    expect(hook).toContain('fortis scan --pre-push');

    const { dir: other } = repo({ 'a.txt': 'x' });
    writeFileSync(join(other, '.git/hooks/pre-push'), '#!/bin/sh\nnpm test\n');
    expect(installHook(other).status).toBe('appended');
    expect(readFileSync(join(other, '.git/hooks/pre-push'), 'utf8')).toMatch(/npm test[\s\S]*fortis scan --pre-push/);
  });

  it('upgrades hooks from earlier versions to pass the pushed refs, keeping the user\'s own lines', () => {
    const OLD_RUN = 'if [ -x ./node_modules/.bin/fortis ]; then ./node_modules/.bin/fortis scan --pre-push\nelif command -v fortis >/dev/null 2>&1; then fortis scan --pre-push\nelse npx --no-install fortis scan --pre-push; fi';
    const { dir } = repo({ 'a.txt': 'x' });
    writeFileSync(join(dir, '.git/hooks/pre-push'), `#!/bin/sh\n# fortis-pre-push\n# Installed by Fortis.\n${OLD_RUN}\n`);
    expect(installHook(dir).status).toBe('updated');
    expect(readFileSync(join(dir, '.git/hooks/pre-push'), 'utf8')).toContain('scan --pre-push --stdin');
    expect(installHook(dir).status).toBe('already');

    const { dir: other } = repo({ 'a.txt': 'x' });
    writeFileSync(join(other, '.git/hooks/pre-push'), `#!/bin/sh\nnpm test\n\n# fortis-pre-push\n( ${OLD_RUN.replace(/\n/g, '\n  ')} ) || exit 1\necho after\n`);
    expect(installHook(other).status).toBe('updated');
    const hook = readFileSync(join(other, '.git/hooks/pre-push'), 'utf8');
    expect(hook).toMatch(/^#!\/bin\/sh\nnpm test\n[\s\S]*scan --pre-push --stdin[\s\S]*\) \|\| exit 1\necho after\n$/);
    expect(hook.match(/fortis-pre-push/g)).toHaveLength(1);

    // A beta.8 hook (has --stdin, no Plug'n'Play line) is upgraded too.
    const { dir: third } = repo({ 'a.txt': 'x' });
    writeFileSync(join(third, '.git/hooks/pre-push'), `#!/bin/sh\n# fortis-pre-push\n${OLD_RUN.replace(/--pre-push/g, '--pre-push --stdin')}\n`);
    expect(installHook(third).status).toBe('updated');
    expect(readFileSync(join(third, '.git/hooks/pre-push'), 'utf8')).toContain('.pnp.cjs');
  });

  it('hook says clearly when the CLI is not installed instead of failing with an npm error', () => {
    const { dir } = repo({ 'a.txt': 'x' });
    installHook(dir);
    const r = spawnSync('sh', [join(dir, '.git/hooks/pre-push')], { cwd: dir, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' }, input: '' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Fortis: the CLI isn't installed in this repo");
  });
});

describe('first push of a new repository or branch', () => {
  // Two commits, nothing on any remote: the key is in the FIRST commit.
  function newRepo() {
    const { dir, g } = repo({ 'src/config.ts': `export const k = '${PAYSTACK_LIVE}';\n` });
    writeFileSync(join(dir, 'README.md'), 'hello\n');
    g('add', '-A');
    g('commit', '-q', '-m', 'docs');
    const sha = (ref: string) => execFileSync('git', ['rev-parse', ref], { cwd: dir, encoding: 'utf8' }).trim();
    return { dir, g, sha };
  }

  it('run by hand: checks every commit not on a remote, not just the last one', () => {
    const { dir } = newRepo();
    expect(changedFiles(dir).sort()).toEqual(['README.md', 'src/config.ts']);
  });

  it('from the hook: a push to an empty remote covers every commit being pushed', async () => {
    const { dir, sha } = newRepo();
    const pushed = parsePushRefs(`refs/heads/main ${sha('HEAD')} refs/heads/main ${'0'.repeat(40)}\n`);
    const r = await runScan({ root: dir, scope: 'changed', packs: ['secrets'], offline: true, pushed });
    expect(r.detections.map((d) => `${d.ruleId}@${d.file}`)).toEqual(['FX-SEC-001@src/config.ts']);
  });

  it('from the hook: an update push covers only the commits the remote does not have', () => {
    const { dir, g, sha } = newRepo();
    const remoteHad = sha('HEAD');
    writeFileSync(join(dir, 'b.ts'), 'export const b = 1;\n');
    g('add', '-A');
    g('commit', '-q', '-m', 'b');
    const pushed = parsePushRefs(`refs/heads/main ${sha('HEAD')} refs/heads/main ${remoteHad}\n`);
    expect(changedFiles(dir, pushed)).toEqual(['b.ts']);
  });

  it('ignores branch deletions', () => {
    expect(parsePushRefs(`(delete) ${'0'.repeat(40)} refs/heads/old ${'a'.repeat(40)}\n`)).toEqual([]);
  });
});
