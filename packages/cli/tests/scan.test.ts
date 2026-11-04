import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { toUpload } from '../src/api';
import { installHook } from '../src/hook';
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

  it('pre-push scope checks only files changed since the last commit', async () => {
    const { dir, g } = repo({ 'src/old.ts': `const k = '${PAYSTACK_LIVE}';\n` });
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
    expect(r.incompleteChecks).toEqual([]);
  });

  /** OSV stand-in: every package is vulnerable, and it records what was asked. */
  const fakeOsv = (asked: { name: string; ecosystem: string }[]): typeof fetch => async (url, init) => {
    if (!String(url).endsWith('/v1/querybatch')) return new Response(JSON.stringify({ id: 'GHSA-1', summary: 'bad', database_specific: { severity: 'CRITICAL' } }));
    const { queries } = JSON.parse(String(init!.body)) as { queries: { package: { name: string; ecosystem: string } }[] };
    asked.push(...queries.map((q) => q.package));
    return new Response(JSON.stringify({ results: queries.map(() => ({ vulns: [{ id: 'GHSA-1' }] })) }));
  };

  it('asks OSV with the right ecosystem and reports each lockfile that has the package', async () => {
    const asked: { name: string; ecosystem: string }[] = [];
    const { dir } = repo({
      'api/composer.lock': JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: '7.4.0' }] }),
      'pay/go.mod': 'module x\n\nrequire golang.org/x/text v0.3.5\n',
      'web/requirements.txt': 'django==3.2.0\n',
      'admin/requirements.txt': 'django==3.2.0\n',
    });
    const r = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], fetchImpl: fakeOsv(asked) });
    expect(asked).toEqual(expect.arrayContaining([
      { name: 'guzzlehttp/guzzle', ecosystem: 'Packagist' },
      { name: 'golang.org/x/text', ecosystem: 'Go' },
      { name: 'django', ecosystem: 'PyPI' },
    ]));
    expect(asked).toHaveLength(3);
    expect(r.detections.map((d) => d.file).sort()).toEqual(['admin/requirements.txt', 'api/composer.lock', 'pay/go.mod', 'web/requirements.txt']);
    expect(r.detections[0]!.severity).toBe('critical');
  });

  it('looks up severity past the old 60-advisory limit', async () => {
    const ids = Array.from({ length: 80 }, (_, i) => `GHSA-${i}`);
    const looked: string[] = [];
    const fake: typeof fetch = async (url) => {
      const u = String(url);
      if (u.endsWith('/v1/querybatch')) return new Response(JSON.stringify({ results: [{ vulns: ids.map((id) => ({ id })) }] }));
      looked.push(u);
      return new Response(JSON.stringify({ id: u, database_specific: { severity: u.endsWith('GHSA-79') ? 'CRITICAL' : 'LOW' } }));
    };
    const { dir } = repo({ 'requirements.txt': 'django==3.2.0\n' });
    const r = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], fetchImpl: fake });
    expect(looked).toHaveLength(80);
    expect(r.detections[0]!.severity).toBe('critical');
  });

  it('marks the check incomplete when OSV is down, so its findings stay open', async () => {
    const { dir } = repo({ 'requirements.txt': 'django==3.2.0\n' });
    const down: typeof fetch = async () => new Response('nope', { status: 503 });
    const r = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], fetchImpl: down });
    expect(r.detections).toEqual([]);
    expect(r.incompleteChecks).toEqual(['dependencies']);
    expect(r.notes.join()).toContain('OSV responded 503');
  });

  it('survives a malformed lockfile and still checks the others', async () => {
    const asked: { name: string; ecosystem: string }[] = [];
    const { dir } = repo({ 'composer.lock': '{ not json', 'requirements.txt': 'django==3.2.0\n' });
    const r = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], fetchImpl: fakeOsv(asked) });
    expect(asked).toHaveLength(1);
    expect(r.detections).toHaveLength(1);
    expect(r.incompleteChecks).toEqual(['dependencies']);
    expect(r.notes.join()).toContain('Could not read composer.lock');
  });

  it('says what pom.xml could not cover, and uses the SBOM instead when given one', async () => {
    const pom = '<project><dependencies><dependency><groupId>a</groupId><artifactId>direct</artifactId><version>1.0</version></dependency><dependency><groupId>b</groupId><artifactId>from-bom</artifactId></dependency></dependencies></project>';
    const bom = JSON.stringify({ bomFormat: 'CycloneDX', components: [{ purl: 'pkg:maven/a/direct@1.0' }, { purl: 'pkg:maven/c/transitive@2.0' }] });
    const { dir } = repo({ 'pom.xml': pom, 'target-bom.json': bom });

    const plain = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], fetchImpl: fakeOsv([]) });
    expect(plain.packagesChecked).toBe(1);
    expect(plain.notes.join()).toContain('checked 1 of 2 declared dependencies');

    const withSbom = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], sbom: 'target-bom.json', fetchImpl: fakeOsv([]) });
    expect(withSbom.packagesChecked).toBe(2);
    expect(withSbom.detections.map((d) => d.file)).toEqual(['target-bom.json', 'target-bom.json']);
    expect(withSbom.notes.join()).not.toContain('pom.xml');
    expect(withSbom.incompleteChecks).toEqual([]);
  });

  it('treats a missing SBOM as an incomplete check, not a failure', async () => {
    const { dir } = repo({ 'requirements.txt': 'django==3.2.0\n' });
    const r = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], sbom: 'nope.json', fetchImpl: fakeOsv([]) });
    expect(r.detections).toHaveLength(1);
    expect(r.incompleteChecks).toEqual(['dependencies']);
    expect(r.notes.join()).toContain('Could not read the SBOM nope.json');
  });

  it('notes a project with no lockfile, and keeps its findings open', async () => {
    const { dir } = repo({ 'composer.json': '{}', 'index.php': '<?php\n' });
    const r = await runScan({ root: dir, scope: 'full', packs: ['dependencies'], fetchImpl: fakeOsv([]) });
    expect(r.notes.join()).toContain('commit composer.lock');
    expect(r.incompleteChecks).toEqual(['dependencies']);
  });

  it('pre-push checks a lockfile in any language only when it changed', async () => {
    const asked: { name: string; ecosystem: string }[] = [];
    const { dir, g } = repo({ 'composer.lock': JSON.stringify({ packages: [{ name: 'a/b', version: '1.0.0' }] }), 'src/app.php': '<?php\n' });
    writeFileSync(join(dir, 'src/app.php'), '<?php echo 1;\n');
    g('add', '-A');
    g('commit', '-q', '-m', 'code only');
    await runScan({ root: dir, scope: 'changed', packs: ['dependencies'], fetchImpl: fakeOsv(asked) });
    expect(asked).toHaveLength(0);

    writeFileSync(join(dir, 'composer.lock'), JSON.stringify({ packages: [{ name: 'a/b', version: '2.0.0' }] }));
    g('add', '-A');
    g('commit', '-q', '-m', 'upgrade');
    await runScan({ root: dir, scope: 'changed', packs: ['dependencies'], fetchImpl: fakeOsv(asked) });
    expect(asked).toEqual([{ name: 'a/b', ecosystem: 'Packagist' }]);
  });

  it('says which languages the fintech rules skipped, on full scans only', async () => {
    const { dir, g } = repo({ 'src/Wallet.java': 'class Wallet {}\n', 'src/Pay.java': 'class Pay {}\n', 'api/pay.php': '<?php\n', 'src/test/WalletTest.java': 'class T {}\n', 'web/app.ts': 'export {};\n' });
    const full = await runScan({ root: dir, scope: 'full', packs: ['fintech'], offline: true });
    expect(full.notes.join()).toContain('2 Java/Kotlin, 1 PHP files had secrets and dependency checks only');
    writeFileSync(join(dir, 'src/Pay.java'), 'class Pay { }\n');
    g('add', '-A');
    g('commit', '-q', '-m', 'edit');
    const push = await runScan({ root: dir, scope: 'changed', packs: ['fintech'], offline: true });
    expect(push.notes.join()).not.toContain('Fintech code rules');
  });

  it('skips build output and vendored code in other languages', async () => {
    const { dir } = repo({
      'target/classes/application.yml': `k: '${PAYSTACK_LIVE}'\n`,
      'api/vendor/lib/x.php': `<?php $k = '${PAYSTACK_LIVE}';\n`,
      '.venv/lib/x.py': `k = '${PAYSTACK_LIVE}'\n`,
      'src/config.py': `k = '${PAYSTACK_LIVE}'\n`,
    });
    const r = await runScan({ root: dir, scope: 'full', packs: ['fintech'], offline: true });
    expect(r.detections.map((d) => d.file)).toEqual(['src/config.py']);
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

  it('writes a hook that needs no Node: the local copy first, then the installed binary', () => {
    const { dir } = repo({ 'a.txt': 'x' });
    installHook(dir);
    const hook = readFileSync(join(dir, '.git/hooks/pre-push'), 'utf8');
    expect(hook).not.toContain('npx');
    expect(hook.indexOf('node_modules/.bin/fortis')).toBeLessThan(hook.indexOf('command -v fortis'));
  });

  it('upgrades hooks that older versions wrote with npx, keeping anything else in them', () => {
    const { dir } = repo({ 'a.txt': 'x' });
    writeFileSync(join(dir, '.git/hooks/pre-push'), '#!/bin/sh\nnpm test\n\n# fortis-pre-push\nnpx --no-install fortis scan --pre-push || exit 1\n');
    expect(installHook(dir).status).toBe('upgraded');
    const hook = readFileSync(join(dir, '.git/hooks/pre-push'), 'utf8');
    expect(hook).toContain('npm test');
    expect(hook).not.toContain('npx');
    expect(hook).toContain('command -v fortis');
    expect(installHook(dir).status).toBe('already');
  });

  it('the hook runs the installed binary, and a missing CLI stops the push with instructions', () => {
    const { dir } = repo({ 'a.txt': 'x' });
    installHook(dir);
    const hookPath = join(dir, '.git/hooks/pre-push');
    const sh = (path: string) => spawnSync('sh', [hookPath], { cwd: dir, encoding: 'utf8', env: { ...process.env, PATH: path } });
    const shDir = dirname(execFileSync(process.platform === 'win32' ? 'where' : 'which', ['sh'], { encoding: 'utf8' }).split(/\r?\n/)[0]!);

    const missing = sh(shDir);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain('install.sh');

    const bin = join(dir, 'fake-bin');
    mkdirSync(bin);
    writeFileSync(join(bin, 'fortis'), '#!/bin/sh\necho "ran: $*"\n', { mode: 0o755 });
    const found = sh(`${bin}${delimiter}${shDir}`);
    expect(found.stdout).toContain('ran: scan --pre-push');
    expect(found.status).toBe(0);
  });
});
