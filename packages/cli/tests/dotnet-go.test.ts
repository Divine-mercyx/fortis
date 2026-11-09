import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { readPackages, scanDependencies } from '../src/rules/dependencies';
import { compareSemver, fixedVersion } from '../src/rules/fix-version';
import { findLockfiles } from '../src/rules/lockfiles';
import { inRange } from '../src/rules/osv-db';

const FIXTURES = join(__dirname, 'fixtures', 'lockfiles');
const listed = (dir: string, files: string[]) => {
  const r = readPackages(join(FIXTURES, dir), files);
  return { packages: r.packages.map((p) => `${p.file}:${p.line ?? 0} ${p.name}@${p.version}${p.dev ? ' (dev)' : ''}`), notes: r.notes };
};

/*
 * dotnet-solution: a .NET solution without lockfiles, hand-written as .NET projects are. Central
 * package management in Directory.Packages.props (with a property and a GlobalPackageReference), a
 * C# project with versions from there, a VersionOverride, a <Version> element, a PrivateAssets="all"
 * tool and a floating version; an F# project with a pinned [x] version; a legacy packages.config;
 * and one project that does have packages.lock.json.
 */
const DOTNET_FILES = [
  'Directory.Packages.props',
  'src/Payments.Api/Payments.Api.csproj',
  'src/Payments.Core/Payments.Core.fsproj',
  'src/Payments.Locked/Payments.Locked.csproj',
  'src/Payments.Locked/packages.lock.json',
  'legacy/Payments.Reports/packages.config',
];

describe('.NET without a lockfile', () => {
  it('reads PackageReference versions, central versions and packages.config, and prefers a lockfile where there is one', () => {
    const { packages, notes } = listed('dotnet-solution', DOTNET_FILES);
    expect(packages).toEqual([
      'Directory.Packages.props:14 StyleCop.Analyzers@1.1.118 (dev)',
      'src/Payments.Api/Payments.Api.csproj:9 Newtonsoft.Json@12.0.1',
      'src/Payments.Api/Payments.Api.csproj:10 Serilog@3.1.1',
      'src/Payments.Api/Payments.Api.csproj:11 Microsoft.Extensions.Http@8.0.1',
      'src/Payments.Api/Payments.Api.csproj:12 Swashbuckle.AspNetCore@6.5.0',
      'src/Payments.Api/Payments.Api.csproj:15 Microsoft.SourceLink.GitHub@8.0.0 (dev)',
      'src/Payments.Core/Payments.Core.fsproj:12 FSharp.Core@8.0.400',
      'src/Payments.Core/Payments.Core.fsproj:13 Dapper@2.1.35',
      'src/Payments.Locked/packages.lock.json:0 Newtonsoft.Json@12.0.1',
      'src/Payments.Locked/packages.lock.json:0 System.Text.Encodings.Web@4.7.1',
      'legacy/Payments.Reports/packages.config:3 log4net@2.0.8',
      'legacy/Payments.Reports/packages.config:4 Newtonsoft.Json@9.0.1',
      'legacy/Payments.Reports/packages.config:5 NUnit@3.13.3 (dev)',
    ]);
    // Transitive packages need the lockfile, and the floating version can't be checked: both are said.
    expect(notes[0]).toMatch(/^\.NET project files: only the packages they reference were checked \(2 projects\)\. Transitive packages need the lockfile/);
    expect(notes.join('\n')).toContain('src/Payments.Api/Payments.Api.csproj: Polly. Floating versions and ranges');
    // A project file used to mean "no lockfile, nothing checked".
    expect(notes.join('\n')).not.toContain('found but no lockfile');
  });

  it('reports a vulnerable package at the line that references it', async () => {
    const osv: typeof fetch = async (url, init) => {
      if (String(url).endsWith('/v1/querybatch')) {
        const { queries } = JSON.parse(String(init!.body)) as { queries: { package: { name: string }; version: string }[] };
        return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === 'Newtonsoft.Json' && q.version === '9.0.1' ? { vulns: [{ id: 'GHSA-5crp-9r3c-p9vr' }] } : {})) }));
      }
      return new Response(JSON.stringify({ id: 'GHSA-5crp-9r3c-p9vr', summary: 'Improper handling of exceptional conditions in Newtonsoft.Json', database_specific: { severity: 'HIGH' } }));
    };
    const r = await scanDependencies(join(FIXTURES, 'dotnet-solution'), DOTNET_FILES, { fetchImpl: osv });
    expect(r.detections.map((d) => `${d.file}:${d.line} ${d.snippet.split(' ·')[0]}`)).toEqual(['legacy/Payments.Reports/packages.config:4 Newtonsoft.Json@9.0.1']);
  });
});

/*
 * go-workspace: a real Go workspace from `go work init ./api ./worker`. api requires uuid v1.6.0, a
 * pseudo-version of pkg/errors, and example.com/shared replaced by ../shared; worker requires uuid
 * v1.3.0, which go.work replaces with v1.3.1. go-vendored: a module with `go mod vendor` run.
 */
describe('Go workspaces and vendored modules', () => {
  const WORKSPACE = [
    'api/go.mod:6 github.com/google/uuid@v1.6.0',
    'api/go.mod:7 github.com/pkg/errors@v0.9.2-0.20201214064552-5dd12d0cfe7f',
    'worker/go.mod:5 github.com/google/uuid@v1.3.1',
  ];

  it("checks both modules, with go.work's replacements and the module's own", () => {
    const { packages, notes } = listed('go-workspace', ['go.work', 'api/go.mod', 'worker/go.mod', 'shared/go.mod']);
    expect(packages).toEqual(WORKSPACE);
    expect(notes.join('\n')).toContain('api/go.mod: example.com/shared (local folder). A module replaced by a local folder has no release to check.');
  });

  it('follows go.work to each module, even when only go.work changed', () => {
    expect(listed('go-workspace', ['go.work']).packages).toEqual(WORKSPACE);
  });

  it('reads vendor/modules.txt, what is actually built, instead of go.mod', () => {
    expect(listed('go-vendored', ['go.mod', 'vendor/modules.txt']).packages).toEqual(['vendor/modules.txt:1 github.com/google/uuid@v1.3.0']);
    expect(findLockfiles(['go.mod', 'vendor/modules.txt', 'vendor/github.com/x/y/vendor/modules.txt', 'node_modules/z/vendor/modules.txt'])).toEqual(['vendor/modules.txt']);
  });

  it('orders pseudo-versions as OSV does: before the release they lead up to', () => {
    expect(compareSemver('v1.2.4-0.20240101120000-abcdef123456', 'v1.2.4')).toBeLessThan(0);
    expect(compareSemver('v1.2.4-0.20240101120000-abcdef123456', 'v1.2.3')).toBeGreaterThan(0);
    expect(compareSemver('v0.0.0-20210220032938-85be41e4509f', '0.3.7')).toBeLessThan(0);
    expect(compareSemver('v1.10.0', 'v1.9.0')).toBeGreaterThan(0);
    expect(compareSemver('1.0.0-rc.1', '1.0.0-rc.2')).toBeLessThan(0);
    const events = [{ introduced: '0' }, { fixed: '1.2.4' }];
    expect(inRange('1.2.4-0.20240101120000-abcdef123456', events, compareSemver)).toBe(true);
    const advisory = { id: 'GO-1', affected: [{ package: { name: 'example.com/m', ecosystem: 'Go' }, ranges: [{ type: 'SEMVER', events }] }] };
    expect(fixedVersion([advisory], 'Go', 'example.com/m', 'v1.2.4-0.20240101120000-abcdef123456').version).toBe('1.2.4');
  });
});
