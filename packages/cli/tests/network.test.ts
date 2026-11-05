import { createServer, type Server } from 'node:http';
import { connect } from 'node:net';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { networkSetup, redact } from '../src/net';
import { scanDependencies } from '../src/rules/dependencies';
import { CACHE_TTL_MS } from '../src/rules/osv-cache';
import { inRange, lookupLocal, readZip } from '../src/rules/osv-db';
import { readFileSync } from 'node:fs';

const DB = join(__dirname, 'fixtures', 'osv-db');

function lockRepo(pkgs: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'fortis-net-'));
  const packages: Record<string, object> = { '': { dependencies: Object.fromEntries(Object.keys(pkgs).map((n) => [n, '*'])) } };
  for (const [n, v] of Object.entries(pkgs)) packages[`node_modules/${n}`] = { version: v };
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
  return dir;
}

/** A stand-in OSV: lodash@4.17.15 has one advisory. Counts requests. */
function fakeOsv() {
  const calls: string[] = [];
  const impl: typeof fetch = async (url, init) => {
    const u = String(url);
    calls.push(u.endsWith('/v1/querybatch') ? 'querybatch' : u.split('/').pop()!);
    if (u.endsWith('/v1/querybatch')) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] };
      return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }] } : {})) }));
    }
    return new Response(
      JSON.stringify({ id: 'GHSA-35jh-r3h4-6jhm', summary: 'Command Injection in lodash', database_specific: { severity: 'HIGH' }, affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] }),
    );
  };
  return { impl, calls };
}

describe('company proxies', () => {
  let proxy: Server;
  let osv: Server;
  let direct: Server;
  let proxyUrl = '';
  let directPort = 0;
  /** What the proxy was asked to connect to, and what OSV then received through the tunnel. */
  const seen: { target: string; auth?: string; path?: string; host?: string }[] = [];

  beforeAll(async () => {
    // Stands in for api.osv.dev: the proxy tunnels every host here.
    osv = createServer((req, res) => {
      Object.assign(seen.at(-1) ?? {}, { path: req.url, host: req.headers.host });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ results: [{}] }));
    });
    // A company proxy: answers CONNECT and pipes the connection through.
    proxy = createServer((_req, res) => res.writeHead(405).end());
    proxy.on('connect', (req, client, head) => {
      seen.push({ target: req.url ?? '', auth: req.headers['proxy-authorization'] as string | undefined });
      const upstream = connect((osv.address() as { port: number }).port, '127.0.0.1', () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        upstream.write(head);
        upstream.pipe(client);
        client.pipe(upstream);
      });
      upstream.on('error', () => client.destroy());
      client.on('error', () => upstream.destroy());
    });
    direct = createServer((_req, res) => res.end('direct'));
    for (const s of [osv, proxy, direct]) await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
    proxyUrl = `http://127.0.0.1:${(proxy.address() as { port: number }).port}`;
    directPort = (direct.address() as { port: number }).port;
  });
  afterAll(() => {
    for (const s of [proxy, osv, direct]) s.close();
  });

  it('needs no setup when nothing is configured', async () => {
    expect(await networkSetup({})).toBeNull();
  });

  it('sends OSV requests through HTTP_PROXY, with its credentials', async () => {
    const setup = (await networkSetup({ HTTP_PROXY: proxyUrl.replace('//', '//ops:s3cret@') }))!;
    const r = await scanDependencies(lockRepo({ 'left-pad': '1.3.0' }), ['package-lock.json'], { fetchImpl: setup.fetch, osvUrl: 'http://osv.internal.test' });
    expect(r.error).toBeUndefined();
    expect(seen.at(-1)).toMatchObject({ target: 'osv.internal.test:80', path: '/v1/querybatch', host: 'osv.internal.test' });
    expect(seen.at(-1)!.auth).toBe(`Basic ${Buffer.from('ops:s3cret').toString('base64')}`);
  });

  it('reads lower-case variables and never proxies localhost or NO_PROXY hosts', async () => {
    const setup = (await networkSetup({ http_proxy: proxyUrl, no_proxy: 'internal.example' }))!;
    expect(setup.noProxy).toBe('internal.example,localhost,127.0.0.1,::1');
    const before = seen.length;
    const res = await setup.fetch(`http://localhost:${directPort}/`);
    expect(await res.text()).toBe('direct');
    expect(seen.length).toBe(before);
  });

  it('hides a proxy password in messages', () => {
    expect(redact('http://ops:s3cret@proxy.bank.local:8080')).toBe('http://ops:***@proxy.bank.local:8080');
  });
});

describe('OSV cache', () => {
  it('answers a repeat scan from the cache, and asks again once it expires', async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'fortis-cache-'));
    const repo = lockRepo({ lodash: '4.17.15', 'left-pad': '1.3.0' });
    let now = Date.parse('2026-11-05T09:00:00Z');
    const osv = fakeOsv();
    const scan = () => scanDependencies(repo, ['package-lock.json'], { fetchImpl: osv.impl, cacheDir, now: () => now });

    const first = await scan();
    expect(osv.calls).toEqual(['querybatch', 'GHSA-35jh-r3h4-6jhm']);
    expect(first.detections.map((d) => d.fixedVersion)).toEqual(['4.17.21']);

    now += CACHE_TTL_MS - 60_000;
    const second = await scan();
    expect(osv.calls).toHaveLength(2); // nothing new asked
    expect(second.detections).toEqual(first.detections);

    now += 2 * 60_000;
    await scan();
    expect(osv.calls).toEqual(['querybatch', 'GHSA-35jh-r3h4-6jhm', 'querybatch', 'GHSA-35jh-r3h4-6jhm']);
  });

  it('keeps working without the network while the cache is fresh', async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'fortis-cache-'));
    const repo = lockRepo({ lodash: '4.17.15' });
    await scanDependencies(repo, ['package-lock.json'], { fetchImpl: fakeOsv().impl, cacheDir });
    const down: typeof fetch = async () => {
      throw new TypeError('fetch failed');
    };
    const r = await scanDependencies(repo, ['package-lock.json'], { fetchImpl: down, cacheDir });
    expect(r.error).toBeUndefined();
    expect(r.detections).toHaveLength(1);
  });

  it('ignores a damaged cache file', async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'fortis-cache-'));
    writeFileSync(join(cacheDir, 'osv-v1.json'), '{not json');
    const r = await scanDependencies(lockRepo({ lodash: '4.17.15' }), ['package-lock.json'], { fetchImpl: fakeOsv().impl, cacheDir });
    expect(r.detections).toHaveLength(1);
  });
});

describe('air-gapped: --osv-db', () => {
  it('reads a ZIP64 archive written by another zip tool', () => {
    const names: string[] = [];
    readZip(readFileSync(join(DB, 'PyPI', 'all.zip')), (n) => names.push(n));
    expect(names).toEqual(['GHSA-j8r2-6x86-q33q.json', 'README.txt']);
  });

  it.each([
    ['1.2.5', [{ introduced: '1.0.0' }, { fixed: '1.2.6' }], true],
    ['1.2.6', [{ introduced: '1.0.0' }, { fixed: '1.2.6' }], false],
    ['0.9.0', [{ introduced: '1.0.0' }, { fixed: '1.2.6' }], false],
    ['2.0.0', [{ introduced: '0' }, { last_affected: '2.0.0' }], true],
    ['2.0.1', [{ introduced: '0' }, { last_affected: '2.0.0' }], false],
    ['3.1.0', [{ introduced: '0' }, { fixed: '2.0.0' }, { introduced: '3.0.0' }, { fixed: '3.2.0' }], true],
  ])('%s in %j → %s', (v, events, expected) => expect(inRange(v, events)).toBe(expected));

  it('finds advisories in zips and unzipped JSON with no network at all', async () => {
    const repo = lockRepo({ lodash: '4.17.15', minimist: '1.2.5', 'left-pad': '1.3.0' });
    const offline: typeof fetch = async () => {
      throw new Error('the network must not be used');
    };
    const r = await scanDependencies(repo, ['package-lock.json'], { fetchImpl: offline, osvDb: DB });
    expect(r.error).toBeUndefined();
    const by = Object.fromEntries(r.detections.map((d) => [d.snippet.split('@')[0], d]));
    expect(Object.keys(by).sort()).toEqual(['lodash', 'minimist']); // left-pad's advisory is withdrawn
    expect(by.lodash).toMatchObject({ severity: 'high', fixedVersion: '4.17.21' });
    expect(by.minimist).toMatchObject({ severity: 'critical', fixedVersion: '1.2.6' });
    expect(r.notes.join(' ')).toContain('local OSV database');
  });

  it('matches PyPI and Go packages too', () => {
    const key = (p: { ecosystem: string; name: string; version: string }) => `${p.ecosystem}|${p.name}|${p.version}`;
    const r = lookupLocal(DB, [
      { ecosystem: 'PyPI', name: 'Requests', version: '2.28.0', dev: false },
      { ecosystem: 'Go', name: 'golang.org/x/net', version: 'v0.15.0', dev: false },
      { ecosystem: 'Go', name: 'golang.org/x/net', version: 'v0.17.0', dev: false },
    ], key);
    expect([...r.hits.entries()].sort()).toEqual([
      ['Go|golang.org/x/net|v0.15.0', ['GHSA-qppj-fm5r-hxr3']],
      ['PyPI|Requests|2.28.0', ['GHSA-j8r2-6x86-q33q']],
    ]);
  });

  it('explains an empty or missing folder', () => {
    expect(() => lookupLocal(join(DB, 'nope'), [], () => '')).toThrow(/not a folder/);
    expect(() => lookupLocal(mkdtempSync(join(tmpdir(), 'fortis-empty-')), [], () => '')).toThrow(/no \.zip or \.json files/);
  });
});
