import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { allFiles, checkoutInfo, currentBranch } from '../src/git';
import { installHook } from '../src/hook';
import { runScan } from '../src/scan';

// An AWS-format key, built at runtime so this file isn't flagged.
const KEY = `AKIA${'ABCD2345'.repeat(2)}`;
const git = (cwd: string, ...args: string[]) =>
  execFileSync('git', ['-c', 'protocol.file.allow=always', '-c', 'user.email=t@example.com', '-c', 'user.name=T', ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

function repo(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'fortis-layout-'));
  git(dir, 'init', '-q', '-b', 'main');
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), text);
  }
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'first');
  return dir;
}
const scan = (root: string, extra: Partial<Parameters<typeof runScan>[0]> = {}) => runScan({ root, scope: 'full', packs: ['secrets'], offline: true, ...extra });

describe('git layouts', () => {
  it('shallow clone: detected, and a branch comparison says it may cover too little', async () => {
    const origin = repo({ 'a.ts': 'export const a = 1;\n' });
    writeFileSync(join(origin, 'b.ts'), 'export const b = 2;\n');
    git(origin, 'add', '-A');
    git(origin, 'commit', '-qm', 'second');
    const dir = mkdtempSync(join(tmpdir(), 'fortis-shallow-'));
    git(dir, 'clone', '-q', '--depth', '1', `file://${origin}`, 'c');
    const clone = join(dir, 'c');
    expect(checkoutInfo(clone).shallow).toBe(true);
    expect(checkoutInfo(origin).shallow).toBe(false);
    const r = await scan(clone, { scope: 'changed' });
    expect(r.notes.join(' ')).toMatch(/shallow clone/);
  });

  it('submodules: skipped with a note by default, scanned with --submodules', async () => {
    const sub = repo({ 'secret.ts': `export const k = '${KEY}';\n` });
    const main = repo({ 'app.ts': 'export const ok = true;\n' });
    git(main, 'submodule', '-q', 'add', sub, 'libs/vendored');
    git(main, 'commit', '-qm', 'add submodule');
    expect(checkoutInfo(main).submodules).toEqual(['libs/vendored']);
    expect(allFiles(main)).not.toContain('libs/vendored');

    const skipped = await scan(main);
    expect(skipped.detections).toEqual([]);
    expect(skipped.notes.join(' ')).toMatch(/Skipped a submodule \(libs\/vendored\)/);

    const included = await scan(main, { submodules: true });
    expect(included.detections.map((d) => d.file)).toEqual(['libs/vendored/secret.ts']);
  });

  it('worktree: the hook goes in the shared hooks folder, and scanning works', async () => {
    const main = repo({ 'app.ts': `export const k = '${KEY}';\n` });
    const wt = join(mkdtempSync(join(tmpdir(), 'fortis-wt-')), 'feature');
    git(main, 'worktree', 'add', '-q', '-b', 'feature', wt);
    expect(existsSync(join(wt, '.git'))).toBe(true); // a file, not a folder
    const { path } = installHook(wt);
    expect(path).toBe(join(main, '.git', 'hooks', 'pre-push'));
    const r = await scan(wt);
    expect(r.detections.map((d) => d.file)).toEqual(['app.ts']);
  });

  it('detached HEAD: no branch name is reported, and scanning works', async () => {
    const dir = repo({ 'app.ts': `export const k = '${KEY}';\n` });
    git(dir, 'checkout', '-q', '--detach');
    expect(currentBranch(dir)).toBeUndefined();
    expect((await scan(dir)).detections).toHaveLength(1);
  });

  it('sparse checkout: files off disk are counted, and the scan is marked partial', async () => {
    const dir = repo({ 'web/app.ts': 'export const ok = 1;\n', 'api/keys.ts': `export const k = '${KEY}';\n` });
    git(dir, 'sparse-checkout', 'set', 'web');
    expect(checkoutInfo(dir).notCheckedOut).toBe(1);
    const r = await scan(dir);
    expect(r.detections).toEqual([]);
    expect(r.partial).toEqual(['sparse checkout']);
    expect(r.notes.join(' ')).toMatch(/Sparse checkout: 1 tracked files/);
  });

  it('time budget: stops reading, says so, and marks the scan partial', async () => {
    const dir = repo({ 'a.ts': 'export const a = 1;\n', 'b.ts': 'export const b = 1;\n' });
    const r = await scan(dir, { budgetMs: -1 });
    expect(r.filesScanned).toBe(0);
    expect(r.partial).toEqual(['time budget']);
    expect(r.notes.join(' ')).toMatch(/checked 0 of 2 files/);
  });
});
