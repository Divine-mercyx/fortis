import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { readPackages, scanDependencies } from '../src/rules/dependencies';
import { missingLockfiles, podsIn, swiftUrlName } from '../src/rules/lockfiles';

/*
 * Real lockfiles: Package.resolved version 1 from gitignore.io (which pins vapor 3.1.0 and
 * swift-nio 1.10.0, both with advisories), version 2 from SwiftLint, version 3 from Vapor's
 * toolbox, and a Podfile.lock from a public iOS app. OSV has a SwiftURL ecosystem and no CocoaPods.
 */
const SWIFT = join(__dirname, 'fixtures', 'lockfiles', 'swift');
const pins = (version: string) => readPackages(join(SWIFT, version), ['Package.resolved']);

describe('Package.resolved', () => {
  it('reads version 1, 2 and 3 files, naming packages as OSV does', () => {
    const v1 = pins('v1');
    expect(v1.packages).toHaveLength(20);
    expect(v1.packages.find((p) => p.name === 'github.com/vapor/vapor')).toMatchObject({ ecosystem: 'SwiftURL', version: '3.1.0', line: 168 });
    const v2 = pins('v2');
    expect(v2.packages.slice(0, 2).map((p) => `${p.name}@${p.version}:${p.line}`)).toEqual(['github.com/JohnSundell/CollectionConcurrencyKit@0.2.0:6', 'github.com/krzyzanowskim/CryptoSwift@1.10.0:15']);
    const v3 = pins('v3');
    expect(v3.packages).toHaveLength(11);
    expect(v3.packages[0]).toMatchObject({ name: 'github.com/vapor/console-kit', version: '5.0.0-beta.2', line: 7 });
  });

  it('turns repository URLs into SwiftURL names, keeping the case OSV matches on', () => {
    expect(swiftUrlName('https://github.com/vapor/vapor.git')).toBe('github.com/vapor/vapor');
    expect(swiftUrlName('git@github.com:apple/swift-nio.git')).toBe('github.com/apple/swift-nio');
    expect(swiftUrlName('ssh://git@GitHub.com/Alamofire/Alamofire')).toBe('github.com/Alamofire/Alamofire');
    expect(swiftUrlName('https://gitlab.com/acme/payments-kit/')).toBe('gitlab.com/acme/payments-kit');
  });

  it('names pins to a branch or commit, local packages and registry packages instead of checking them', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-swift-'));
    const pin = (identity: string, kind: string, state: object, location = `https://github.com/acme/${identity}.git`) => ({ identity, kind, location, state });
    writeFileSync(join(dir, 'Package.resolved'), JSON.stringify({
      pins: [
        pin('released', 'remoteSourceControl', { revision: 'a', version: '1.2.3' }),
        pin('edge', 'remoteSourceControl', { branch: 'main', revision: 'b' }),
        pin('fork', 'remoteSourceControl', { revision: 'c' }),
        pin('shared', 'localSourceControl', { revision: 'd' }, '/Users/me/shared'),
        { identity: 'acme.ledger', kind: 'registry', location: '', state: { version: '2.0.0' } },
      ],
      version: 2,
    }, null, 2));
    const r = readPackages(dir, ['Package.resolved']);
    rmSync(dir, { recursive: true, force: true });
    expect(r.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['github.com/acme/released@1.2.3']);
    expect(r.notes.join('\n')).toContain('Package.resolved: edge (branch main), fork (commit), shared (local folder), acme.ledger (registry).');
  });

  it('reports a known-vulnerable Swift package at its line, asking OSV by its SwiftURL name', async () => {
    const asked: { name: string; ecosystem: string }[] = [];
    const osv: typeof fetch = async (url, init) => {
      if (String(url).endsWith('/v1/querybatch')) {
        const { queries } = JSON.parse(String(init!.body)) as { queries: { package: { name: string; ecosystem: string }; version: string }[] };
        asked.push(...queries.map((q) => q.package));
        return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === 'github.com/vapor/vapor' && q.version === '3.1.0' ? { vulns: [{ id: 'GHSA-gcj9-jj38-hwmc' }] } : {})) }));
      }
      return new Response(JSON.stringify({
        id: 'GHSA-gcj9-jj38-hwmc',
        summary: "Vapor's Metrics integration could cause a system drain",
        aliases: ['CVE-2021-21328'],
        database_specific: { severity: 'HIGH' },
        affected: [{ package: { name: 'github.com/vapor/vapor', ecosystem: 'SwiftURL' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.40.1' }] }] }],
      }));
    };
    const r = await scanDependencies(join(SWIFT, 'v1'), ['Package.resolved'], { fetchImpl: osv });
    expect(asked.every((p) => p.ecosystem === 'SwiftURL')).toBe(true);
    expect(asked.map((p) => p.name)).toContain('github.com/vapor/vapor');
    expect(r.detections).toHaveLength(1);
    expect(r.detections[0]).toMatchObject({ ruleId: 'DEP-OSV', severity: 'high', file: 'Package.resolved', line: 168, snippet: 'github.com/vapor/vapor@3.1.0 · CVE-2021-21328', fixedVersion: '4.40.1' });
    expect(r.detections[0]!.fix).toContain('swift package update vapor');
  });
});

describe('CocoaPods', () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

  it('reads the pods a Podfile.lock installs, leaving out subspecs', () => {
    expect(podsIn(readFileSync(join(SWIFT, 'cocoapods', 'Podfile.lock'), 'utf8'))).toEqual(['Alamofire', 'SDWebImage', 'SwiftyJSON']);
  });

  it("says CocoaPods aren't checked and names the pods, so it's never a clean pass", async () => {
    const r = await scanDependencies(join(SWIFT, 'cocoapods'), ['Podfile.lock'], { allPaths: ['Podfile', 'Podfile.lock'], fetchImpl: async () => new Response('{}') });
    expect(r.incomplete).toBe(true);
    expect(r.notes[0]).toMatch(/^CocoaPods aren't checked for vulnerabilities yet: OSV, where Fortis gets its advisories, has no CocoaPods data/);
    expect(r.notes).toContain('  Podfile.lock: Alamofire, SDWebImage, SwiftyJSON.');
  });

  it('asks for Package.resolved when a Swift package has none', () => {
    expect(missingLockfiles(['Package.swift'], [], new Set()).join('\n')).toContain('Package.swift found but no lockfile, so those dependencies weren\'t checked: commit Package.resolved');
    expect(missingLockfiles(['Package.swift', 'Package.resolved'], [], new Set(['SwiftURL']))).toEqual([]);
  });
});
