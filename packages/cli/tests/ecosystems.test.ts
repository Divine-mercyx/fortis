import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { readPackages, scanDependencies } from '../src/rules/dependencies';
import { upgradeCommand } from '../src/rules/fix-version';
import { missingLockfiles } from '../src/rules/lockfiles';

/*
 * Real lockfiles from public projects: mix.lock from Plug, rebar.lock from hackney,
 * cabal.project.freeze from elm-format, stack.yaml.lock from bulletproofs, renv.lock from
 * connect-usage. OSV's ecosystem names were checked against its current list: Hex, Hackage and
 * CRAN are there; ConanCenter and vcpkg aren't, so those get a "not checked" note instead.
 */
const DIR = join(__dirname, 'fixtures', 'lockfiles', 'ecosystems');
const read = (file: string) => readPackages(DIR, [file]);
const some = (file: string, n = 3) => read(file).packages.slice(0, n).map((p) => `${p.ecosystem} ${p.name}@${p.version}:${p.line}`);

describe('Elixir and Erlang (Hex)', () => {
  it('mix.lock: reads every Hex package with its line', () => {
    const r = read('mix.lock');
    expect(r.packages).toHaveLength(9);
    expect(some('mix.lock')).toEqual(['Hex earmark_parser@1.4.45:2', 'Hex ex_doc@0.40.3:3', 'Hex makeup@1.2.1:4']);
    expect(r.packages.map((p) => p.name)).toContain('telemetry'); // a rebar3 package used from mix
  });

  it('mix.lock: names git dependencies instead of checking them', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-mix-'));
    writeFileSync(join(dir, 'mix.lock'), '%{\n  "fork": {:git, "https://github.com/acme/fork.git", "abc123", []},\n  "jason": {:hex, :jason, "1.4.1", "x", [:mix], [], "hexpm", "y"},\n}\n');
    const r = readPackages(dir, ['mix.lock']);
    rmSync(dir, { recursive: true, force: true });
    expect(r.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['jason@1.4.1']);
    expect(r.notes.join('\n')).toContain('mix.lock: fork (git). Git dependencies have no Hex or Hackage release to check');
  });

  it('rebar.lock: reads the packages, not the hashes that follow them', () => {
    const r = read('rebar.lock');
    expect(r.packages).toHaveLength(8);
    expect(some('rebar.lock')).toEqual(['Hex certifi@2.18.0:2', 'Hex h2@0.15.0:3', 'Hex idna@7.1.0:4']);
  });
});

describe('Haskell (Hackage)', () => {
  it('cabal.project.freeze: reads every constraint', () => {
    const r = read('cabal.project.freeze');
    expect(r.packages).toHaveLength(118);
    expect(some('cabal.project.freeze')).toEqual(['Hackage Glob@0.10.2:2', 'Hackage HUnit@1.6.2.0:3', 'Hackage OneTuple@0.4.2:4']);
  });

  it("stack.yaml.lock: reads the extra packages, once each, and says the snapshot's weren't checked", () => {
    const r = read('stack.yaml.lock');
    expect(r.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['galois-field@1.0.0', 'elliptic-curve@0.3.0', 'poly@0.3.2.0', 'semirings@0.5.1']);
    expect(r.notes).toContain("stack.yaml.lock lists only packages from outside the lts-13.26 snapshot, so the snapshot's packages weren't checked. cabal freeze writes cabal.project.freeze with every package.");
  });
});

describe('R (CRAN)', () => {
  it("renv.lock: counts Posit's CRAN mirror as CRAN, and names GitHub packages", () => {
    const r = read('renv.lock');
    expect(r.packages).toHaveLength(106);
    expect(some('renv.lock')).toEqual(['CRAN BH@1.72.0-3:12', 'CRAN DT@0.20:20', 'CRAN MASS@7.3-51.5:36']);
    expect(r.notes.join('\n')).toContain('renv.lock: connectViz (GitHub), connectapi (GitHub).');
  });
});

describe('checked against OSV under its own ecosystem names', () => {
  it('asks for Hex, Hackage and CRAN packages, and reports the hit', async () => {
    const asked = new Set<string>();
    const osv: typeof fetch = async (url, init) => {
      if (String(url).endsWith('/v1/querybatch')) {
        const { queries } = JSON.parse(String(init!.body)) as { queries: { package: { name: string; ecosystem: string }; version: string }[] };
        for (const q of queries) asked.add(q.package.ecosystem);
        return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === 'telemetry' ? { vulns: [{ id: 'EEF-1' }] } : {})) }));
      }
      return new Response(JSON.stringify({ id: 'EEF-1', summary: 'telemetry advisory', database_specific: { severity: 'HIGH' } }));
    };
    const r = await scanDependencies(DIR, ['mix.lock', 'rebar.lock', 'cabal.project.freeze', 'stack.yaml.lock', 'renv.lock'], { fetchImpl: osv });
    expect([...asked].sort()).toEqual(['CRAN', 'Hackage', 'Hex']);
    expect(r.detections.map((d) => `${d.file}:${d.line} ${d.snippet.split(' ·')[0]}`)).toEqual(['mix.lock:10 telemetry@0.4.3']);
  });

  it('says how to upgrade in each tool', () => {
    expect(upgradeCommand('mix.lock', 'Hex', 'plug', '1.3.5')).toBe('raise plug to 1.3.5 in mix.exs, then mix deps.update plug');
    expect(upgradeCommand('rebar.lock', 'Hex', 'cowboy', '2.10.0')).toBe('raise cowboy to 2.10.0 in rebar.config, then rebar3 upgrade cowboy');
    expect(upgradeCommand('stack.yaml.lock', 'Hackage', 'aeson', '2.0.1.0')).toBe("set aeson-2.0.1.0 in stack.yaml's extra-deps");
    expect(upgradeCommand('renv.lock', 'CRAN', 'commonmark', '1.8')).toBe('renv::install("commonmark@1.8") then renv::snapshot()');
  });
});

describe('a project without its lockfile is reported, never a clean pass', () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

  it.each([
    ['mix.exs', 'mix.exs found but no lockfile'],
    ['rebar.config', 'rebar.config found but no lockfile'],
    ['stack.yaml', 'Haskell project files found but no lockfile'],
    ['payments.cabal', 'Haskell project files found but no lockfile'],
    ['DESCRIPTION', 'R project files found but no lockfile'],
    ['analysis.Rproj', 'R project files found but no lockfile'],
    ['conanfile.txt', "C and C++ packages from Conan aren't checked"],
    ['vcpkg.json', "C and C++ packages from vcpkg aren't checked"],
  ])('%s', async (file, note) => {
    expect(missingLockfiles([file], [], new Set()).join('\n')).toContain(note);
    const dir = mkdtempSync(join(tmpdir(), 'fortis-eco-'));
    dirs.push(dir);
    writeFileSync(join(dir, file), '');
    // A full scan marks the dependency check incomplete, so it can't close findings either.
    const r = await scanDependencies(dir, [file], { allPaths: [file], fetchImpl: async () => new Response('{}') });
    expect(r.incomplete).toBe(true);
  });

  it("doesn't nag once the lockfile is there", () => {
    expect(missingLockfiles(['mix.exs', 'mix.lock'], [], new Set(['Hex']))).toEqual([]);
    expect(missingLockfiles(['DESCRIPTION', 'renv.lock'], [], new Set(['CRAN']))).toEqual([]);
  });
});
