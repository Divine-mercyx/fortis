import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { installHook } from '../src/hook';
import { INSTALL_URL } from '../src/env';

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'fortis-hook-'));
  execFileSync('git', ['init', '-q', dir]);
  return dir;
}
const hookOf = (dir: string) => readFileSync(join(dir, '.git', 'hooks', 'pre-push'), 'utf8');

/** The Fortis lines written by beta.10 and beta.11, before the Windows and GUI-client lookups. */
const BETA_11 = `if [ -x ./node_modules/.bin/fortis ]; then ./node_modules/.bin/fortis scan --pre-push --stdin
elif [ -f ./.pnp.cjs ] && command -v yarn >/dev/null 2>&1; then yarn fortis scan --pre-push --stdin
elif command -v fortis >/dev/null 2>&1; then fortis scan --pre-push --stdin
elif npx --no-install fortis --version >/dev/null 2>&1; then npx --no-install fortis scan --pre-push --stdin
else
  echo "Fortis: the CLI isn't installed in this repo, so this push wasn't checked and has been stopped." >&2
  echo "Install it: npm i -D fortis-watchdog" >&2
  echo "Without Node: curl -fsSL ${INSTALL_URL}/install.sh | sh" >&2
  echo "On Windows: irm ${INSTALL_URL}/install.ps1 | iex" >&2
  echo "Or skip once: git push --no-verify" >&2
  exit 1
fi`;

describe('pre-push hook', () => {
  it('installs once and then leaves it alone', () => {
    const dir = repo();
    expect(installHook(dir).status).toBe('installed');
    expect(installHook(dir).status).toBe('already');
    expect(hookOf(dir)).toContain('.fortis/bin/fortis.exe');
  });

  it.each([
    ['beta.4', 'npx --no-install fortis scan --pre-push'],
    ['beta.5', 'npx --no-install fortis scan --pre-push --stdin'],
    ['beta.6, in a hook with other commands', 'npx --no-install fortis scan --pre-push || exit 1'],
    ['beta.11', BETA_11],
    ['beta.11, in a hook with other commands', `( ${BETA_11.replace(/\n/g, '\n  ')} ) || exit 1`],
  ])('upgrades the %s lines in place and keeps the user’s own', (_v, old) => {
    const dir = repo();
    writeFileSync(join(dir, '.git', 'hooks', 'pre-push'), `#!/bin/sh\necho "lint first"\n# fortis-pre-push\n${old}\necho "after"\n`);
    expect(installHook(dir).status).toBe('updated');
    const hook = hookOf(dir);
    expect(hook.indexOf('lint first')).toBeLessThan(hook.indexOf('fortis scan'));
    expect(hook.indexOf('echo "after"')).toBeGreaterThan(hook.lastIndexOf('fortis scan'));
    expect(hook).toContain('.fortis/bin/fortis.exe');
    expect(hook.match(/# fortis-pre-push/g)).toHaveLength(1);
    expect(hook.match(/^\s*(?:\( )?if \[ -x \.\/node_modules/gm)).toHaveLength(1);
    expect(installHook(dir).status).toBe('already');
    expect(spawnSync('sh', ['-n', join(dir, '.git', 'hooks', 'pre-push')]).status).toBe(0);
  });

  it('finds the standalone install in ~/.fortis/bin when PATH does not have it (GUI git clients)', () => {
    const dir = repo();
    installHook(dir);
    const home = mkdtempSync(join(tmpdir(), 'fortis-home-'));
    mkdirSync(join(home, '.fortis', 'bin'), { recursive: true });
    const stub = join(home, '.fortis', 'bin', 'fortis');
    writeFileSync(stub, '#!/bin/sh\necho "ran: $*"\n');
    chmodSync(stub, 0o755);
    // A PATH with git and sh only: no fortis, no npx.
    const r = spawnSync('sh', [join(dir, '.git', 'hooks', 'pre-push')], { cwd: dir, env: { HOME: home, PATH: '/usr/bin:/bin' }, encoding: 'utf8', input: '' });
    expect(r.stdout).toContain('ran: scan --pre-push --stdin');
  });
});

describe('Windows files and settings', () => {
  it('counts CRLF line endings as one break: line numbers and snippets match LF files', async () => {
    const { loadFiles } = await import('../src/files');
    const { genericSecretRule } = await import('../src/rules/secrets');
    const { emptyContext } = await import('../src/rules/types');
    const dir = mkdtempSync(join(tmpdir(), 'fortis-crlf-'));
    const key = `AKIA${'ABCD2345'.repeat(2)}`;
    const body = ['// config', '', `export const key = '${key}';`, ''];
    writeFileSync(join(dir, 'lf.ts'), body.join('\n'));
    writeFileSync(join(dir, 'crlf.ts'), body.join('\r\n'));
    const [lf, crlf] = loadFiles(dir, ['lf.ts', 'crlf.ts']).map((f) => genericSecretRule.run(f, emptyContext()));
    expect(crlf).toHaveLength(1);
    expect(crlf!.map((d) => [d.line, d.snippet])).toEqual(lf!.map((d) => [d.line, d.snippet]));
    expect(crlf![0]!.snippet).not.toMatch(/\r/);
  });

  it('reads .fortis.json saved with a byte-order mark and Windows-style ignore globs', async () => {
    const { readProjectConfig } = await import('../src/config');
    const { makeFilter } = await import('../src/files');
    const dir = mkdtempSync(join(tmpdir(), 'fortis-bom-'));
    writeFileSync(join(dir, '.fortis.json'), '﻿{ "ignore": ["src\\\\legacy\\\\**"] }');
    const cfg = readProjectConfig(dir);
    expect(cfg.ignore).toEqual(['src/legacy/**']);
    const keep = makeFilter(cfg.ignore);
    expect(keep('src/legacy/old.ts')).toBe(false);
    expect(keep('src\\legacy\\old.ts')).toBe(false);
    expect(keep('src/app.ts')).toBe(true);
  });

  it('gives a Windows path the same baseline fingerprint as a Mac path', async () => {
    const { fingerprintOf } = await import('../src/baseline');
    const d = { ruleId: 'SEC-GEN-001', snippet: "const k = 'x';", line: 3 };
    expect(fingerprintOf({ ...d, file: 'src\\config\\keys.ts' })).toBe(fingerprintOf({ ...d, file: 'src/config/keys.ts' }));
  });
});
