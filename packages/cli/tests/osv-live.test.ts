import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { runScan } from '../src/scan';

/*
 * Asks the real OSV API about one known-vulnerable package per ecosystem, to catch a name or
 * version format OSV doesn't recognise. Normal test runs stay offline; turn it on with
 * FORTIS_LIVE_OSV=1 pnpm --filter fortis-watchdog exec vitest run tests/osv-live.test.ts
 */
const CASES: [string, string, string][] = [
  ['npm', 'package-lock.json', JSON.stringify({ packages: { '': {}, 'node_modules/axios': { version: '0.21.1' } } })],
  ['Packagist', 'composer.lock', JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: 'v7.4.0' }] })],
  ['PyPI', 'requirements.txt', 'Django==3.2.0\n'],
  ['PyPI (uv.lock)', 'uv.lock', '[[package]]\nname = "app"\nversion = "1.0"\nsource = { virtual = "." }\ndependencies = [\n    { name = "django" },\n]\n\n[[package]]\nname = "django"\nversion = "3.2.0"\nsource = { registry = "https://pypi.org/simple" }\n'],
  ['PyPI (poetry.lock)', 'poetry.lock', '[[package]]\nname = "Pillow"\nversion = "8.0.0"\ngroups = ["main"]\n'],
  ['PyPI (pdm.lock)', 'pdm.lock', '[[package]]\nname = "flask"\nversion = "0.12"\ngroups = ["default"]\n'],
  ['PyPI (pylock.toml)', 'pylock.toml', '[[packages]]\nname = "requests"\nversion = "2.19.0"\n'],
  ['Maven (pom.xml)', 'pom.xml', '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>'],
  ['Maven (Gradle)', 'gradle.lockfile', 'org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\n'],
  ['Go', 'go.mod', 'module x\n\nrequire golang.org/x/text v0.3.5\n'],
  ['NuGet', 'packages.lock.json', JSON.stringify({ version: 1, dependencies: { 'net8.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.1' } } } })],
  ['RubyGems', 'Gemfile.lock', 'GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n'],
  ['Hex (mix.lock)', 'mix.lock', '%{\n  "plug": {:hex, :plug, "1.3.0", "abc", [:mix], [], "hexpm", "def"},\n}\n'],
  ['Hex (rebar.lock)', 'rebar.lock', '{"1.2.0",\n[{<<"plug">>,{pkg,<<"plug">>,<<"1.3.0">>},0}]}.\n'],
  ['Hackage', 'cabal.project.freeze', 'constraints: any.aeson ==2.0.0.0\n'],
  ['CRAN', 'renv.lock', JSON.stringify({ R: { Version: '4.3.0' }, Packages: { commonmark: { Package: 'commonmark', Version: '1.7', Source: 'Repository', Repository: 'CRAN' } } })],
  ['SwiftURL', 'Package.resolved', JSON.stringify({ pins: [{ identity: 'vapor', kind: 'remoteSourceControl', location: 'https://github.com/vapor/vapor.git', state: { revision: 'x', version: '4.0.0' } }], version: 2 })],
];

describe.skipIf(!process.env.FORTIS_LIVE_OSV)('real OSV', () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

  it.each(CASES)('%s: finds the known vulnerability in %s', async (_name, file, text) => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-osv-'));
    dirs.push(dir);
    execFileSync('git', ['init', '-q'], { cwd: dir });
    writeFileSync(join(dir, file), text);
    const r = await runScan({ root: dir, scope: 'full', packs: ['dependencies'] });
    expect(r.notes.filter((n) => n.includes('skipped'))).toEqual([]);
    expect(r.detections.length).toBeGreaterThan(0);
    expect(r.detections[0]).toMatchObject({ ruleId: 'DEP-OSV', file });
    expect(['critical', 'high', 'medium', 'low']).toContain(r.detections[0]!.severity);
  }, 60_000);
});
