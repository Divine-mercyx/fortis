import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { checksFromOpenApi, extractIds } from '../src/access';
import { githubWorkflow, gitlabJobs, writeCi } from '../src/ci';
import { installHook } from '../src/hook';
import { runScan } from '../src/scan';

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));

function repo(files: Record<string, string> = { 'a.txt': 'x' }) {
  const dir = mkdtempSync(join(tmpdir(), 'fortis-py-'));
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
  return dir;
}

const shDir = () => dirname(execFileSync(process.platform === 'win32' ? 'where' : 'which', ['sh'], { encoding: 'utf8' }).split(/\r?\n/)[0]!);

function fakeCli(path: string) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, '#!/bin/sh\necho "ran $0: $*"\n');
  chmodSync(path, 0o755);
}

describe('the hook on a Python project', () => {
  const run = (dir: string, extraPath = '') => spawnSync('sh', [join(dir, '.git/hooks/pre-push')], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, PATH: `${extraPath ? `${extraPath}${delimiter}` : ''}${shDir()}` },
    input: '',
  });

  for (const venv of ['.venv/bin/fortis', 'venv/bin/fortis', '.venv/Scripts/fortis.exe', 'venv/Scripts/fortis.exe']) {
    it(`finds ${venv} when the virtual environment isn't active`, () => {
      const dir = repo();
      installHook(dir);
      fakeCli(join(dir, venv));
      const r = run(dir);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain(`scan --pre-push --stdin`);
    });
  }

  it('uses uv run and poetry run when the CLI is a dev dependency there', () => {
    for (const [lock, tool] of [['uv.lock', 'uv'], ['poetry.lock', 'poetry']] as const) {
      const dir = repo({ [lock]: '' });
      installHook(dir);
      const bin = join(dir, 'tools');
      fakeCli(join(bin, tool));
      const r = run(dir, bin);
      expect(r.status, tool).toBe(0);
      expect(r.stdout, tool).toContain('scan --pre-push --stdin');
    }
  });

  it('prefers the virtual environment over a different copy on PATH', () => {
    const dir = repo();
    installHook(dir);
    fakeCli(join(dir, '.venv/bin/fortis'));
    const bin = join(dir, 'elsewhere');
    fakeCli(join(bin, 'fortis'));
    expect(run(dir, bin).stdout).toContain('.venv/bin/fortis');
  });

  it('says how to install it for Python when nothing is found', () => {
    const dir = repo();
    installHook(dir);
    const r = run(dir);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('pip install fortis-watchdog');
  });
});

describe('fortis ci init on a Python project', () => {
  const init = (files: Record<string, string>) => {
    const dir = repo(files);
    return readFileSync(join(dir, writeCi(dir, 'github', { stagingBranch: 'staging' }).path), 'utf8');
  };

  it('adds an SBOM step for a hand-written requirements.txt', () => {
    const yml = init({ 'requirements.txt': 'django==4.2.0\n' });
    expect(yml).toContain('cyclonedx-py environment');
    expect(yml).toContain('continue-on-error: true');
    expect(yml).toContain('--sbom bom.json');
    expect(yml).not.toContain('setup-node');
  });

  it('adds nothing when a lockfile already lists everything', () => {
    const lockedProjects: Record<string, string>[] = [
      { 'requirements.txt': 'django==4.2.0\n', 'uv.lock': '' },
      { 'requirements.txt': 'django==4.2.0 \\\n    --hash=sha256:abc\n' },
      { 'pyproject.toml': '[project]\nname = "x"\n', 'poetry.lock': '' },
    ];
    for (const files of lockedProjects) {
      const yml = init(files);
      expect(yml).not.toContain('cyclonedx-py');
      expect(yml).not.toContain('--sbom');
    }
  });

  it('explains the SBOM for GitLab', () => {
    expect(gitlabJobs({ stagingBranch: 'dev', pythonSbom: true })).toContain('cyclonedx-py');
    expect(githubWorkflow({ stagingBranch: 'dev', pythonSbom: true })).toContain('actions/setup-python');
  });
});

describe('access checks on Python APIs', () => {
  const spec = (...paths: string[]) => ({ paths: Object.fromEntries(paths.map((p) => [p, { get: {} }])) });

  it('reads Django REST paths, which end in a slash', () => {
    expect(checksFromOpenApi(spec('/api/wallets/', '/api/wallets/{id}/'))).toEqual([{ name: 'Wallet', list: '/api/wallets/', get: '/api/wallets/{id}/' }]);
  });

  it('reads FastAPI paths, with or without a slash on the list', () => {
    expect(checksFromOpenApi(spec('/wallets', '/wallets/{wallet_id}'))).toEqual([{ name: 'Wallet', list: '/wallets', get: '/wallets/{id}' }]);
    expect(checksFromOpenApi(spec('/wallets/', '/wallets/{wallet_id}'))).toEqual([{ name: 'Wallet', list: '/wallets/', get: '/wallets/{id}' }]);
  });

  it("finds IDs in Django REST's paginated lists", () => {
    expect(extractIds(JSON.stringify({ count: 2, next: null, results: [{ id: 7 }, { id: 8 }] }))).toEqual(['7', '8']);
  });
});

describe('a Python project, end to end', () => {
  const VIEW = `def transfer_detail(request, pk):
    return Transfer.objects.get(pk=pk)


def debit(wallet, amount):
    wallet.balance -= amount
    wallet.save()
`;

  it('runs the fintech rules, and no longer lists Python as skipped', async () => {
    const dir = repo({ 'app/views.py': VIEW, 'app/test_views.py': VIEW, 'app/migrations/0001_initial.py': VIEW });
    const r = await runScan({ root: dir, scope: 'full', packs: ['fintech'], offline: true });
    expect(r.detections.map((d) => `${d.ruleId}@${d.file}:${d.line}`)).toEqual(['FX-OWN-001@app/views.py:2', 'FX-TXN-001@app/views.py:6']);
    expect(r.notes.join()).not.toContain('Fintech code rules');
  });

  // Every labelled Python case, as one project through the real scan: right findings, right lines, nothing else.
  it('reports exactly the labelled findings across Django, Flask and FastAPI', async () => {
    const cases = join(__dirname, '..', 'bench', 'cases');
    const files: Record<string, string> = {};
    const expected: string[] = [];
    for (const rule of ['FX-OWN-001', 'FX-TXN-001', 'FX-PII-002', 'FX-OTP-001']) {
      for (const name of readdirSync(join(cases, rule)).filter((n) => n.endsWith('.py'))) {
        const path = `app/${rule}/${name}`;
        const text = readFileSync(join(cases, rule, name), 'utf8');
        files[path] = text;
        text.split(/\r?\n/).forEach((line, i) => {
          if (line.includes('@hit')) expected.push(`${rule}@${path}:${i + 1}`);
        });
      }
    }
    const r = await runScan({ root: repo(files), scope: 'full', packs: ['fintech'], offline: true });
    const found = r.detections.filter((d) => d.file.split('/')[1] === d.ruleId).map((d) => `${d.ruleId}@${d.file}:${d.line}`);
    expect(found.sort()).toEqual(expected.sort());
  });

  it('honours # fortis-ignore', async () => {
    const dir = repo({ 'app/views.py': 'def transfer_detail(request, pk):\n    return Transfer.objects.get(pk=pk)  # fortis-ignore\n' });
    const r = await runScan({ root: dir, scope: 'full', packs: ['fintech'], offline: true });
    expect(r.detections).toEqual([]);
  });

  it('leaves the rules out of the free plan, but still catches secrets', async () => {
    const key = ['sk', 'live', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4'].join('_');
    const dir = repo({ 'app/views.py': `${VIEW}\nKEY = "${key}"\n` });
    const r = await runScan({ root: dir, scope: 'full', packs: ['secrets', 'dependencies'], offline: true });
    expect(r.detections.map((d) => d.ruleId)).toEqual(['FX-SEC-001']);
  });
});
