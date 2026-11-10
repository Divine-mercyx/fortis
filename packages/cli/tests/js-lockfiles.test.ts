import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { scanDependencies } from '../src/rules/dependencies';
import { parseBunLock, parsePnpmLock, parseYarnLock, readLockfile, splitPnpmKey } from '../src/rules/js-lockfiles';

/*
 * Fixtures are real lockfiles generated from the same package.json by npm 10, pnpm 10
 * (lockfile v9), pnpm 8 (v6), yarn 1.22, yarn 4.5 and Bun 1.4.4 (bun.lock, which `bun install` migrated
 * from the npm fixture's package-lock.json, so every version matches): prod deps lodash, react, react-dom
 * (peer dep on react), @babel/code-frame; dev deps minimist, @types/node.
 */
const FIXTURES = join(__dirname, 'fixtures', 'lockfiles');
const FORMATS = ['npm', 'pnpm9', 'pnpm8', 'yarn1', 'berry', 'bun'] as const;

const summary = (dir: string) => {
  const lock = readLockfile(join(FIXTURES, dir))!;
  const list = (dev: boolean) => lock.packages.filter((p) => p.dev === dev).map((p) => `${p.name}@${p.version}`).sort();
  return { file: lock.file, prod: list(false), dev: list(true) };
};

describe('lockfile readers', () => {
  const reference = summary('npm');

  it('npm reference: 17 production packages, 2 dev-only', () => {
    expect(reference.prod).toHaveLength(17);
    expect(reference.prod).toContain('lodash@4.17.15');
    expect(reference.prod).toContain('js-tokens@4.0.0'); // transitive, reached from two places
    expect(reference.dev).toEqual(['@types/node@20.0.0', 'minimist@1.2.5']);
  });

  for (const f of FORMATS.slice(1)) {
    it(`${f} gives exactly the same packages and dev split as npm`, () => {
      const s = summary(f);
      expect(s.prod).toEqual(reference.prod);
      expect(s.dev).toEqual(reference.dev);
    });
  }

  it('points findings at the line of the package in the lockfile', () => {
    for (const f of ['pnpm9', 'pnpm8', 'yarn1', 'berry', 'bun']) {
      const lodash = readLockfile(join(FIXTURES, f))!.packages.find((p) => p.name === 'lodash')!;
      expect(lodash.line, f).toBeGreaterThan(1);
    }
  });

  it('reads pnpm v5 keys (/name/version_peers)', () => {
    const v5 = [
      'lockfileVersion: 5.4',
      '',
      'packages:',
      '',
      '  /lodash/4.17.15:',
      '    resolution: {integrity: sha512-x}',
      '    dev: false',
      '',
      '  /@babel/core/7.0.0_react@18.2.0:',
      '    resolution: {integrity: sha512-y}',
      '    dev: true',
      '',
    ].join('\n');
    expect(parsePnpmLock(v5)).toEqual([
      { name: 'lodash', version: '4.17.15', dev: false, line: 5 },
      { name: '@babel/core', version: '7.0.0', dev: true, line: 9 },
    ]);
    expect(splitPnpmKey('/@scope/pkg@1.2.3(react@18.2.0)', false)).toEqual(['@scope/pkg', '1.2.3']);
  });
});

describe('dependency check on pnpm, yarn and Bun projects', () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

  // OSV stub: lodash@4.17.15 is vulnerable, everything else is clean.
  const osv: typeof fetch = async (url, init) => {
    const u = String(url);
    if (u.endsWith('/v1/querybatch')) {
      const body = JSON.parse(String(init?.body)) as { queries: { package: { name: string }; version: string }[] };
      return new Response(JSON.stringify({ results: body.queries.map((q) => (q.package.name === 'lodash' && q.version === '4.17.15' ? { vulns: [{ id: 'GHSA-p6mc-m468-83gw' }] } : {})) }));
    }
    return new Response(JSON.stringify({ id: 'GHSA-p6mc-m468-83gw', summary: 'Prototype Pollution in lodash', aliases: ['CVE-2020-8203'], database_specific: { severity: 'HIGH' } }));
  };

  const LOCKFILE = { pnpm9: 'pnpm-lock.yaml', yarn1: 'yarn.lock', berry: 'yarn.lock', bun: 'bun.lock' } as const;
  for (const f of ['pnpm9', 'yarn1', 'berry', 'bun'] as const) {
    it(`${f}: finds the vulnerable package and reports the lockfile it came from`, async () => {
      const lockfile = LOCKFILE[f];
      const r = await scanDependencies(join(FIXTURES, f), [lockfile, 'package.json'], { fetchImpl: osv });
      expect(r.error).toBeUndefined();
      expect(r.checked).toBe(17); // dev-only packages are not checked by default
      expect(r.detections).toHaveLength(1);
      expect(r.detections[0]).toMatchObject({
        ruleId: 'DEP-OSV',
        severity: 'high',
        file: lockfile,
        snippet: 'lodash@4.17.15 · CVE-2020-8203',
      });
      expect(r.detections[0]!.line).toBeGreaterThan(1);
    });
  }

  it('treats every package as production when the graph walk finds no roots', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-lock-'));
    dirs.push(dir);
    // A workspace root with no dependencies of its own.
    writeFileSync(join(dir, 'package.json'), '{"private":true,"workspaces":["apps/*"]}');
    writeFileSync(join(dir, 'yarn.lock'), '# yarn lockfile v1\n\nlodash@^4.17.0:\n  version "4.17.15"\n');
    expect(readLockfile(dir)!.packages).toEqual([{ name: 'lodash', version: '4.17.15', dev: false, line: 3 }]);
  });
});

describe('direct and indirect dependencies', () => {
  for (const f of ['pnpm9', 'yarn1', 'berry', 'bun'] as const) {
    it(`${f}: names the direct dependency an indirect one comes through`, () => {
      const dir = join(FIXTURES, f);
      const lock = readFileSync(join(dir, { pnpm9: 'pnpm-lock.yaml', yarn1: 'yarn.lock', berry: 'yarn.lock', bun: 'bun.lock' }[f]), 'utf8');
      const list = f === 'pnpm9' ? parsePnpmLock(lock) : f === 'bun' ? parseBunLock(lock) : parseYarnLock(lock, JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')));
      expect(list.find((p) => p.name === '@babel/code-frame')).toMatchObject({ direct: true });
      expect(list.find((p) => p.name === 'chalk')).toMatchObject({ direct: false, via: '@babel/code-frame' });
    });
  }
});
