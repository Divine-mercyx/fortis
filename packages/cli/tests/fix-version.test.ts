import { describe, expect, it } from 'vitest';

import { compareVersions, fixedVersion, fixMessage, upgradeCommand, type OsvAffected } from '../src/rules/fix-version';
import { scanDependencies } from '../src/rules/dependencies';
import type { Ecosystem } from '../src/rules/lockfiles';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/*
 * OSV-shaped advisories (only the fields the CLI reads), with the ranges the real advisories publish.
 * api.osv.dev isn't reachable from every test environment, so these are written out rather than fetched.
 */
const range = (...events: Record<string, string>[]) => ({ type: 'ECOSYSTEM', events });
const adv = (id: string, ecosystem: Ecosystem, name: string, ...ranges: ReturnType<typeof range>[]) => ({ id, affected: [{ package: { ecosystem, name }, ranges }] as OsvAffected[] });

const LODASH = adv('GHSA-p6mc-m468-83gw', 'npm', 'lodash', range({ introduced: '3.7.0' }, { fixed: '4.17.19' }));
const LODASH_CMD = adv('GHSA-35jh-r3h4-6jhm', 'npm', 'lodash', range({ introduced: '0' }, { fixed: '4.17.21' }));
// Log4Shell's follow-up fixes ship on three release lines.
const LOG4J = adv(
  'GHSA-7rjr-3q55-vv33',
  'Maven',
  'org.apache.logging.log4j:log4j-core',
  range({ introduced: '2.0-beta9' }, { fixed: '2.3.1' }),
  range({ introduced: '2.4' }, { fixed: '2.12.2' }),
  range({ introduced: '2.13.0' }, { fixed: '2.16.0' }),
);

describe('compareVersions', () => {
  it.each([
    ['1.10.0', '1.9.9', 1],
    ['1.0.0-rc.1', '1.0.0', -1],
    ['2.0b1', '2.0', -1],
    ['1.0.post1', '1.0', 1],
    ['v0.17.0', '0.7.0', 1],
    ['2.0-beta9', '2.0', -1],
    ['1.2.3+build.5', '1.2.3', 0],
  ])('%s vs %s', (a, b, sign) => expect(Math.sign(compareVersions(a, b))).toBe(sign));
});

describe('fixedVersion', () => {
  it('needs the highest per-advisory fix to clear them all', () => {
    expect(fixedVersion([LODASH, LODASH_CMD], 'npm', 'lodash', '4.17.15')).toEqual({ version: '4.17.21', partial: '4.17.21', unfixed: [] });
  });

  it('stays on the installed release line', () => {
    expect(fixedVersion([LOG4J], 'Maven', 'org.apache.logging.log4j:log4j-core', '2.12.1').version).toBe('2.12.2');
    expect(fixedVersion([LOG4J], 'Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1').version).toBe('2.16.0');
  });

  it('says when there is no fix yet', () => {
    const open = adv('GHSA-open', 'npm', 'lodash', range({ introduced: '0' }));
    expect(fixedVersion([open, LODASH], 'npm', 'lodash', '4.17.15')).toEqual({ version: null, partial: '4.17.19', unfixed: ['GHSA-open'] });
  });

  it('matches PyPI names the way pip does and ignores other packages in the advisory', () => {
    const a = { id: 'X', affected: [{ package: { ecosystem: 'PyPI', name: 'other' }, ranges: [range({ introduced: '0' }, { fixed: '9.0' })] }, { package: { ecosystem: 'PyPI', name: 'Typing_Extensions' }, ranges: [range({ introduced: '0' }, { fixed: '4.1.0' })] }] };
    expect(fixedVersion([a], 'PyPI', 'typing-extensions', '4.0.0').version).toBe('4.1.0');
  });
});

describe('upgradeCommand for each package manager', () => {
  it.each([
    ['package-lock.json', 'npm', 'lodash', '4.17.21', 'npm install lodash@4.17.21'],
    ['pnpm-lock.yaml', 'npm', 'lodash', '4.17.21', 'pnpm up lodash@4.17.21'],
    ['web/yarn.lock', 'npm', 'lodash', '4.17.21', 'yarn up lodash@4.17.21'],
    ['bun.lock', 'npm', 'lodash', '4.17.21', 'bun add lodash@4.17.21'],
    ['composer.lock', 'Packagist', 'guzzlehttp/guzzle', '7.4.5', 'composer require guzzlehttp/guzzle:^7.4.5'],
    ['poetry.lock', 'PyPI', 'requests', '2.31.0', 'poetry add "requests>=2.31.0"'],
    ['uv.lock', 'PyPI', 'requests', '2.31.0', 'uv add "requests>=2.31.0"'],
    ['requirements.txt', 'PyPI', 'requests', '2.31.0', 'set requests==2.31.0 in requirements.txt'],
    ['Cargo.lock', 'crates.io', 'time', '0.2.23', 'cargo update -p time --precise 0.2.23'],
    ['go.mod', 'Go', 'golang.org/x/net', '0.17.0', 'go get golang.org/x/net@v0.17.0'],
    ['Gemfile.lock', 'RubyGems', 'nokogiri', '1.13.10', 'bundle update nokogiri --conservative'],
    ['packages.lock.json', 'NuGet', 'Newtonsoft.Json', '13.0.1', 'dotnet add package Newtonsoft.Json --version 13.0.1'],
    ['pom.xml', 'Maven', 'org.apache.logging.log4j:log4j-core', '2.16.0', 'set org.apache.logging.log4j:log4j-core to 2.16.0 in pom.xml'],
    ['pubspec.lock', 'Pub', 'http', '0.13.3', 'dart pub add http:^0.13.3'],
  ] as const)('%s', (file, eco, name, version, cmd) => expect(upgradeCommand(file, eco, name, version)).toBe(cmd));

  it('updates an indirect dependency in place instead of adding it to package.json', () => {
    expect(upgradeCommand('package-lock.json', 'npm', 'minimist', '1.2.6', false)).toBe('npm update minimist');
    expect(upgradeCommand('pnpm-lock.yaml', 'npm', 'minimist', '1.2.6', false)).toBe('pnpm up -r minimist');
    expect(upgradeCommand('composer.lock', 'Packagist', 'psr/http-message', '2.0', false)).toBe('composer update psr/http-message --with-dependencies');
  });
});

describe('fixMessage', () => {
  const p = { file: 'package-lock.json', ecosystem: 'npm' as const, name: 'minimist', version: '1.2.5' };
  it('names the direct dependency that pulls an indirect one in', () => {
    expect(fixMessage({ ...p, direct: false, via: 'mkdirp' }, { version: '1.2.6', partial: '1.2.6', unfixed: [] })).toBe(
      "Upgrade to 1.2.6: npm update minimist. minimist comes in through mkdirp; if the command doesn't move it, upgrade mkdirp.",
    );
  });
  it('says "no fixed version yet"', () => {
    expect(fixMessage({ ...p, direct: true }, { version: null, partial: null, unfixed: ['GHSA-open'] })).toBe('No fixed version yet for GHSA-open. Check the advisory for a workaround, or replace the package.');
  });
});

describe('scanDependencies reports the fix', () => {
  it('in the finding, from the lockfile graph and the advisory ranges', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-fix-'));
    writeFileSync(
      join(dir, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { mkdirp: '^0.5.5', lodash: '^4.17.0' } },
          'node_modules/mkdirp': { version: '0.5.5', dependencies: { minimist: '^1.2.5' } },
          'node_modules/minimist': { version: '1.2.5' },
          'node_modules/lodash': { version: '4.17.15' },
        },
      }),
    );
    const advisories: Record<string, object> = {
      'GHSA-xvch-5gv4-984h': adv('GHSA-xvch-5gv4-984h', 'npm', 'minimist', range({ introduced: '0' }, { fixed: '0.2.4' }), range({ introduced: '1.0.0' }, { fixed: '1.2.6' })),
      'GHSA-p6mc-m468-83gw': LODASH,
      'GHSA-35jh-r3h4-6jhm': LODASH_CMD,
    };
    const fake: typeof fetch = async (url, init) => {
      const u = String(url);
      if (u.endsWith('/v1/querybatch')) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] };
        const ids: Record<string, string[]> = { minimist: ['GHSA-xvch-5gv4-984h'], lodash: ['GHSA-p6mc-m468-83gw', 'GHSA-35jh-r3h4-6jhm'] };
        return new Response(JSON.stringify({ results: queries.map((q) => (ids[q.package.name] ? { vulns: ids[q.package.name]!.map((id) => ({ id })) } : {})) }));
      }
      return new Response(JSON.stringify(advisories[decodeURIComponent(u.split('/').pop()!)]));
    };
    const r = await scanDependencies(dir, ['package-lock.json'], { fetchImpl: fake });
    const by = Object.fromEntries(r.detections.map((d) => [d.snippet.split('@')[0], d]));
    expect(by.lodash).toMatchObject({ fixedVersion: '4.17.21', fix: 'Upgrade to 4.17.21: npm install lodash@4.17.21.' });
    expect(by.minimist).toMatchObject({ fixedVersion: '1.2.6' });
    expect(by.minimist!.fix).toContain('comes in through mkdirp');
  });
});
