import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

const LIVE = ['sk', 'live', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4'].join('_');
const dir = mkdtempSync(join(tmpdir(), 'fortis-json-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('fortis scan --json', () => {
  it('masks secrets (the output usually lands in CI logs) and blocks on a free plan', () => {
    const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
    g('init', '-q', '-b', 'main');
    g('config', 'user.email', 't@example.com');
    g('config', 'user.name', 'Test');
    writeFileSync(join(dir, 'pay.js'), `const PAYSTACK = "${LIVE}";\n`);
    g('add', '-A');
    g('commit', '-q', '-m', 'init');

    const cli = join(__dirname, '..', 'src', 'index.ts');
    const tsx = join(__dirname, '..', 'node_modules', '.bin', 'tsx');
    const r = spawnSync(tsx, [cli, 'scan', '--json', '--offline', '--no-upload'], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, FORTIS_KEY: '', HOME: dir },
    });
    expect(r.stdout).not.toContain(LIVE);
    const out = JSON.parse(r.stdout) as { detections: { ruleId: string; snippet: string }[] };
    expect(out.detections.map((d) => d.ruleId)).toEqual(['FX-SEC-001']);
    expect(out.detections[0]!.snippet).toContain('••••');
    expect(r.status).toBe(1);
  }, 30_000);
});
