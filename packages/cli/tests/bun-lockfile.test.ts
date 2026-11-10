import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { chooseJsLockfiles, scanDependencies } from '../src/rules/dependencies';
import { parseBunLock, parseJsonc } from '../src/rules/js-lockfiles';
import { parseLockfile } from '../src/rules/lockfiles';

/*
 * bun.lock cases the shared fixture doesn't have, in real lockfiles from `bun install --lockfile-only`
 * on the project in fixtures/lockfiles/bun-workspaces: a workspace with its own copy of react
 * (keyed under the workspace's name), ms nested under debug, an alias (old-lodash → lodash), and
 * packages from git, a tarball URL and a local folder. bun.lock is from Bun 1.4.4 (lockfileVersion 2),
 * bun-1.2.lock from Bun 1.2.23 (lockfileVersion 1, no integrity on git and tarball entries).
 */
const DIR = join(__dirname, 'fixtures', 'lockfiles', 'bun-workspaces');
const LOCKS = { 'Bun 1.4': readFileSync(join(DIR, 'bun.lock'), 'utf8'), 'Bun 1.2': readFileSync(join(DIR, 'bun-1.2.lock'), 'utf8') };
const MONOREPO = LOCKS['Bun 1.4'];

/** The line a package key is on, counting from 1. */
const lineOf = (text: string, key: string) => text.split(/\r?\n/).findIndex((l) => l.startsWith(`    "${key}": [`)) + 1;
const find = (list: ReturnType<typeof parseBunLock>, name: string, version?: string) => list.filter((p) => p.name === name && (version === undefined || p.version === version));

describe.each(Object.entries(LOCKS))('bun.lock from %s', (_bun, text) => {
  const list = parseBunLock(text);

  it("reads an alias as the real package, under the alias's line", () => {
    expect(find(list, 'old-lodash')).toEqual([]);
    expect(find(list, 'lodash')).toEqual([{ name: 'lodash', version: '4.17.15', dev: false, line: lineOf(text, 'old-lodash'), direct: true }]);
  });

  it("counts every workspace's dependencies, finding a workspace's own copy under its name", () => {
    expect(find(list, 'react', '18.2.0')[0]).toMatchObject({ dev: false, direct: true, line: lineOf(text, 'react') });
    expect(find(list, 'react', '17.0.2')[0]).toMatchObject({ dev: false, direct: true, line: lineOf(text, '@acme/web/react') });
    // Only the workspace's own react 17 needs object-assign.
    expect(find(list, 'object-assign')[0]).toMatchObject({ dev: false, direct: false, via: 'react' });
    expect(find(list, '@acme/web')).toEqual([]);
  });

  it('marks what only devDependencies need as dev, in a workspace too', () => {
    expect(find(list, 'minimist')[0]).toMatchObject({ dev: true, direct: true });
    expect(find(list, 'debug')[0]).toMatchObject({ dev: true, direct: true });
    // debug needs ms 2.0.0, nested under it; the top-level ms 2.1.3 is the workspace's own.
    expect(find(list, 'ms', '2.0.0')[0]).toMatchObject({ dev: true, direct: false, via: 'debug', line: lineOf(text, 'debug/ms') });
    expect(find(list, 'ms', '2.1.3')[0]).toMatchObject({ dev: false, direct: true });
    expect(find(list, 'loose-envify')[0]).toMatchObject({ dev: false });
  });

  it('names packages from git, a tarball or a local folder instead of checking them', () => {
    const parsed = parseLockfile('bun.lock', text);
    expect(parsed.skippedNames?.sort()).toEqual(['is-number (tarball)', 'isarray (git)', 'local-lib (local folder)']);
    expect(parsed.packages.every((p) => p.ecosystem === 'npm' && /^\d/.test(p.version))).toBe(true);
    // Two copies each of react and ms.
    expect(parsed.packages.map((p) => `${p.name}@${p.version}`).sort()).toEqual(['debug@2.6.8', 'js-tokens@4.0.0', 'lodash@4.17.15', 'loose-envify@1.4.0', 'minimist@1.2.5', 'ms@2.0.0', 'ms@2.1.3', 'object-assign@4.1.1', 'react@17.0.2', 'react@18.2.0']);
  });

  it('puts every package on the line Bun wrote it on', () => {
    const lines = text.split(/\r?\n/);
    for (const p of list.filter((p) => !p.source)) expect(lines[p.line - 1], p.name).toContain(`"${p.name}@${p.version}"`);
  });
});

describe('bun.lock reader', () => {
  it('treats every package as production when no workspace lists dependencies', () => {
    const bare = '{\n  "lockfileVersion": 1,\n  "workspaces": { "": { "name": "x" } },\n  "packages": {\n    "lodash": ["lodash@4.17.15", "", {}, "sha512-a"],\n  }\n}\n';
    expect(parseBunLock(bare)).toEqual([{ name: 'lodash', version: '4.17.15', dev: false, line: 5 }]);
  });

  it('reads JSONC: trailing commas and comments, with neither touched inside strings', () => {
    expect(parseJsonc('{\n  // a comment\n  "a": "x, }", /* b */ "b": [1, 2,],\n}')).toEqual({ a: 'x, }', b: [1, 2] });
    expect(parseJsonc('{ "url": "https://example.com/a", "q": "say \\"hi\\"", }')).toEqual({ url: 'https://example.com/a', q: 'say "hi"' });
  });
});

describe('bun.lock in the dependency check', () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));
  const project = (files: Record<string, string>) => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-bun-'));
    dirs.push(dir);
    for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
    return dir;
  };

  it('checks bun.lock over a leftover package-lock.json, and follows packageManager when it says bun', () => {
    const leftover = project({ 'package.json': '{}', 'bun.lock': MONOREPO, 'package-lock.json': '{}' });
    const notes: string[] = [];
    expect(chooseJsLockfiles(leftover, ['bun.lock', 'package-lock.json'], notes)).toEqual(['bun.lock']);
    expect(notes[0]).toMatch(/checked bun\.lock/);

    const declared = project({ 'package.json': '{"packageManager":"bun@1.2.5"}', 'bun.lock': MONOREPO, 'yarn.lock': '' });
    const why: string[] = [];
    expect(chooseJsLockfiles(declared, ['bun.lock', 'yarn.lock'], why)).toEqual(['bun.lock']);
    expect(why[0]).toMatch(/packageManager says bun/);
  });

  it('finds a vulnerable package through its alias and points at its line', async () => {
    const osv: typeof fetch = async (url, init) => {
      if (String(url).endsWith('/v1/querybatch')) {
        const body = JSON.parse(String(init?.body)) as { queries: { package: { name: string }; version: string }[] };
        return new Response(JSON.stringify({ results: body.queries.map((q) => (q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-p6mc-m468-83gw' }] } : {})) }));
      }
      return new Response(JSON.stringify({ id: 'GHSA-p6mc-m468-83gw', summary: 'Prototype Pollution in lodash', aliases: ['CVE-2020-8203'], database_specific: { severity: 'HIGH' } }));
    };
    const r = await scanDependencies(DIR, ['bun.lock', 'package.json', 'packages/web/package.json'], { fetchImpl: osv });
    expect(r.detections).toHaveLength(1);
    expect(r.detections[0]).toMatchObject({ file: 'bun.lock', line: lineOf(MONOREPO, 'old-lodash'), snippet: 'lodash@4.17.15 · CVE-2020-8203' });
    expect(r.notes.join(' ')).toMatch(/isarray \(git\)/);
  });
});
