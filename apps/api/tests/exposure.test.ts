import { createServer, type Server } from 'node:net';
import type { AddressInfo } from 'node:net';

import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pool } from '../src/db/client';
import { setExposureProbeOptions } from '../src/modules/exposure.routes';
import { exposureFindings, isPublicAddress, PAGE_CHECKS, probeHost, probePages, SERVICES, type Service } from '../src/modules/exposure.service';
import { setTxtResolver } from '../src/modules/targets.routes';
import { projectWithKey, resetDb, setPlan, setupApp, signup, type Client } from './helpers';

/* ------------------------------------------------- fake services on local ports */

type Fake = { server: Server; port: number };
const fakes: Fake[] = [];

/** A TCP server that greets, or answers what it's sent, like the real service would. */
async function fake(handler: (data: string) => string | null, greeting: string | null = null): Promise<number> {
  const server = createServer((socket) => {
    socket.on('error', () => {});
    if (greeting) socket.write(greeting);
    socket.on('data', (d) => {
      const reply = handler(d.toString());
      if (reply !== null) socket.end(reply);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  fakes.push({ server, port });
  return port;
}

/** A port nothing listens on. */
async function closedPort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const port = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

const httpOk = (body: string) => `HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n${body}`;
const svc = (port: number): Service => SERVICES.find((s) => s.port === port)!;

afterAll(async () => {
  for (const f of fakes) await new Promise<void>((r) => f.server.close(() => r()));
});

/* ------------------------------------------------- which addresses may be scanned */

describe('isPublicAddress', () => {
  it('allows public unicast addresses', () => {
    for (const ip of ['8.8.8.8', '102.89.10.4', '41.58.1.1', '172.15.0.1', '172.32.0.1', '100.63.0.1', '2606:4700::1111', '2001:4860:4860::8888']) expect(isPublicAddress(ip), ip).toBe(true);
  });

  it('refuses private, loopback, link-local, metadata, reserved and documentation ranges', () => {
    for (const ip of [
      '10.0.0.1', '127.0.0.1', '127.255.255.254', '0.0.0.0', '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.168.1.1',
      '100.64.0.1', '100.127.255.255', '192.0.2.10', '198.51.100.7', '203.0.113.50', '198.18.0.1', '224.0.0.1', '255.255.255.255',
      '::', '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '2001:db8::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1', '64:ff9b::a00:1',
      'not-an-ip', '',
    ]) expect(isPublicAddress(ip), ip).toBe(false);
  });
});

/* ------------------------------------------------- probing */

describe('probeHost', () => {
  it('finds open ports, reads banners, and tells a passwordless service from a closed one', async () => {
    const redis = await fake((d) => (/PING/.test(d) ? '+PONG\r\n' : null));
    const ssh = await fake(() => null, 'SSH-2.0-OpenSSH_9.6 Ubuntu\r\n');
    const es = await fake(() => httpOk('{"name":"node-1","cluster_name":"payments","version":{"number":"8.15.0"}}'));
    const pgPort = await closedPort();
    const ports: Record<number, number> = { 6379: redis, 22: ssh, 9200: es, 5432: pgPort };
    const { addresses, results } = await probeHost('db.example.com', {
      resolve: async () => ['127.0.0.1'],
      allowPrivate: true, pages: [],
      services: [svc(6379), svc(22), svc(9200), svc(5432)],
      dialPort: (p) => ports[p]!,
      timeoutMs: 800,
    });
    expect(addresses).toEqual(['127.0.0.1']);
    const by = Object.fromEntries(results.map((r) => [r.port, r]));
    expect(by[6379]).toMatchObject({ open: true, noAuth: 'Redis answers commands without a password' });
    expect(by[22]).toMatchObject({ open: true, banner: 'SSH-2.0-OpenSSH_9.6 Ubuntu' });
    expect(by[22]!.noAuth).toBeUndefined();
    expect(by[9200]).toMatchObject({ open: true, noAuth: 'Elasticsearch answers without authentication' });
    expect(by[5432]).toMatchObject({ open: false });
  });

  it('does not call a service passwordless when it asks for credentials', async () => {
    const redis = await fake((d) => (/PING/.test(d) ? '-NOAUTH Authentication required.\r\n' : null));
    const es = await fake(() => 'HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n{"error":"security_exception"}');
    const ports: Record<number, number> = { 6379: redis, 9200: es };
    const { results } = await probeHost('db.example.com', { resolve: async () => ['127.0.0.1'], allowPrivate: true, pages: [], services: [svc(6379), svc(9200)], dialPort: (p) => ports[p]!, timeoutMs: 800 });
    expect(results.every((r) => r.open && !r.noAuth)).toBe(true);
  });

  it('refuses hosts that resolve only to private addresses, and drops the private ones from mixed answers', async () => {
    await expect(probeHost('internal.example.com', { resolve: async () => ['10.0.0.5', '169.254.169.254'] })).rejects.toMatchObject({ code: 'EXPOSURE_NO_PUBLIC_ADDRESS' });
    await expect(probeHost('none.example.com', { resolve: async () => [] })).rejects.toMatchObject({ code: 'EXPOSURE_NO_PUBLIC_ADDRESS' });
    await expect(probeHost('gone.example.com', { resolve: async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }); } })).rejects.toMatchObject({ code: 'EXPOSURE_DNS' });
    const r = await probeHost('mixed.example.com', { resolve: async () => ['10.0.0.5', '192.0.2.1', '127.0.0.1'], services: [], timeoutMs: 50 }).catch((e) => e);
    expect(r.code).toBe('EXPOSURE_NO_PUBLIC_ADDRESS');
  });

  it('caps the addresses per host', async () => {
    const { addresses } = await probeHost('many.example.com', { resolve: async () => ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5', '127.0.0.6'], allowPrivate: true, services: [], pages: [] });
    expect(addresses).toHaveLength(4);
  });
});

describe('probePages', () => {
  /** An HTTP server that serves these paths, and the given fallback for everything else. */
  async function site(routes: Record<string, string>, fallback: { status: number; body: string } = { status: 404, body: 'Not found' }) {
    const { createServer: createHttp } = await import('node:http');
    const server = createHttp((req, res) => {
      const body = routes[req.url ?? ''];
      if (body !== undefined) { res.writeHead(200); res.end(body); return; }
      res.writeHead(fallback.status); res.end(fallback.body);
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    fakes.push({ server: server as unknown as Server, port: (server.address() as AddressInfo).port });
    return (server.address() as AddressInfo).port;
  }

  it('finds exposed files and panels by their fingerprints', async () => {
    const http = await site({
      '/': '<html>ok</html>',
      '/.env': 'APP_ENV=production\nDB_PASSWORD=example\n',
      '/.git/config': '[core]\n\trepositoryformatversion = 0\n',
      '/actuator/env': '{"activeProfiles":["prod"],"propertySources":[]}',
      '/phpmyadmin/': '<title>phpMyAdmin</title>',
      '/swagger.json': '{"openapi":"3.0.1","info":{}}',
      '/__fortis_not_a_page__': "<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>",
    });
    const https = await closedPort();
    const ports: Record<number, number> = { 80: http, 443: https };
    const pages = await probePages('app.example.com', '127.0.0.1', { dialPort: (p) => ports[p]!, timeoutMs: 1500 });
    expect(pages.map((p) => `${p.check.ruleId} ${p.check.severity} ${p.url}`).sort()).toEqual([
      'EXP-FILE-001 critical http://app.example.com/.env',
      'EXP-FILE-001 critical http://app.example.com/.git/config',
      'EXP-PANEL-001 critical http://app.example.com/actuator/env',
      'EXP-PANEL-001 high http://app.example.com/__fortis_not_a_page__',
      'EXP-PANEL-001 high http://app.example.com/phpmyadmin/',
      'EXP-PANEL-001 medium http://app.example.com/swagger.json',
    ]);
    const f = exposureFindings('app.example.com', [], pages);
    expect(f.find((x) => x.ruleId === 'EXP-FILE-001' && x.file.endsWith('/.env'))!.detail).toMatch(/rotate/);
  });

  it('ignores a single-page app that answers every path with its homepage', async () => {
    const spa = '<!doctype html><html><head><title>Paywave</title></head><body><div id="root"></div><script src="/main.js"></script></body></html>';
    const http = await site({ '/': spa }, { status: 200, body: spa });
    const ports: Record<number, number> = { 80: http, 443: await closedPort() };
    expect(await probePages('app.example.com', '127.0.0.1', { dialPort: (p) => ports[p]!, timeoutMs: 1500 })).toEqual([]);
  });

  it('only counts 200 responses, and skips origins that do not answer', async () => {
    const http = await site({ '/': 'ok' }, { status: 403, body: '<title>phpMyAdmin</title> forbidden' });
    const ports: Record<number, number> = { 80: http, 443: await closedPort() };
    expect(await probePages('app.example.com', '127.0.0.1', { dialPort: (p) => ports[p]!, timeoutMs: 1500 })).toEqual([]);
    const none: Record<number, number> = { 80: await closedPort(), 443: await closedPort() };
    expect(await probePages('app.example.com', '127.0.0.1', { dialPort: (p) => none[p]!, timeoutMs: 800 })).toEqual([]);
  });

  it('every check names a real fingerprint and a fix', () => {
    for (const c of PAGE_CHECKS) {
      expect(c.path.startsWith('/'), c.path).toBe(true);
      expect(c.fix.length, c.path).toBeGreaterThan(30);
      expect(c.match.test('<!doctype html><html><body><div id="root"></div></body></html>'), c.path).toBe(false);
    }
  });
});

describe('exposureFindings', () => {
  it('reports each open port, raised to critical when it answered without a password', () => {
    const f = exposureFindings('db.example.com', [
      { ip: '102.89.10.4', port: 22, service: 'SSH', open: true, banner: 'SSH-2.0-OpenSSH_9.6' },
      { ip: '102.89.10.4', port: 6379, service: 'Redis', open: true, noAuth: 'Redis answers commands without a password' },
      { ip: '102.89.10.4', port: 5432, service: 'PostgreSQL', open: false },
      { ip: '102.89.10.4', port: 9092, service: 'Kafka', open: true },
    ]);
    expect(f.map((x) => `${x.ruleId} ${x.severity} ${x.file}`)).toEqual([
      'EXP-PORT-001 high db.example.com:22',
      'EXP-NOAUTH-001 critical db.example.com:6379',
      'EXP-PORT-001 medium db.example.com:9092',
    ]);
    expect(f[0]!.title).toBe('SSH open to the internet (db.example.com:22)');
    expect(f[1]!.detail).toMatch(/turn on authentication/i);
  });

  it('keeps passwords out of banners', () => {
    const f = exposureFindings('h.example.com', [{ ip: '8.8.8.8', port: 22, service: 'SSH', open: true, banner: 'password=[removed]' }]);
    expect(f[0]!.snippet).not.toMatch(/hunter2/);
  });
});

/* ------------------------------------------------- the routes */

let app: FastifyInstance;
beforeAll(async () => {
  app = await setupApp();
});
afterAll(async () => {
  await app.close();
  await pool.end();
});
beforeEach(resetDb);
afterEach(() => {
  setTxtResolver(null);
  setExposureProbeOptions(null);
});

async function setup(plan = 'core') {
  const c = await signup(app);
  await setPlan(c.orgId, plan);
  const { projectId } = await projectWithKey(c);
  return { c, projectId, base: `/v1/orgs/${c.orgId}/projects/${projectId}/targets` };
}

async function target(c: Client, base: string, { verify = true, authorize = true } = {}) {
  const created = await c.req({ method: 'POST', url: base, payload: { url: 'https://staging.paywave.example', environment: 'staging' } });
  const t = created.json().target;
  setTxtResolver(async (name) => (name === t.verification.recordName ? [t.verification.recordValue] : []));
  if (verify) await c.req({ method: 'POST', url: `${base}/${t.id}/verify` });
  if (verify && authorize) await c.req({ method: 'POST', url: `${base}/${t.id}/authorize`, payload: { signerName: 'Ada Okafor', accept: true } });
  return t.id as string;
}

describe('exposure routes', () => {
  it('only run on verified, authorised targets', async () => {
    const { c, base } = await setup();
    const unverified = await target(c, base, { verify: false });
    const res = await c.req({ method: 'POST', url: `${base}/${unverified}/exposure` });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('TARGET_NOT_READY');
  });

  it('records findings, shows them, and closes them when the port is closed', async () => {
    const { c, base } = await setup();
    const id = await target(c, base);
    const redis = await fake((d) => (/PING/.test(d) ? '+PONG\r\n' : null));
    const ssh = await fake(() => null, 'SSH-2.0-OpenSSH_9.6\r\n');
    let ports: Record<number, number> = { 6379: redis, 22: ssh };
    setExposureProbeOptions({ resolve: async () => ['127.0.0.1'], allowPrivate: true, pages: [], services: [svc(6379), svc(22)], dialPort: (p) => ports[p]!, timeoutMs: 800 });

    const first = await c.req({ method: 'POST', url: `${base}/${id}/exposure` });
    expect(first.statusCode).toBe(200);
    expect(first.json()).toMatchObject({ hostname: 'staging.paywave.example', newCount: 2 });
    expect(first.json().findings.map((f: { ruleId: string }) => f.ruleId).sort()).toEqual(['EXP-NOAUTH-001', 'EXP-PORT-001']);

    const shown = await c.req({ method: 'GET', url: `${base}/${id}/exposure` });
    expect(shown.json().findings).toHaveLength(2);
    expect(shown.json().lastScan.findings).toBe(2);

    // SSH is closed now: the next check marks that finding fixed and keeps Redis open.
    ports = { 6379: redis, 22: await closedPort() };
    const second = await c.req({ method: 'POST', url: `${base}/${id}/exposure` });
    expect(second.json()).toMatchObject({ newCount: 0, fixedCount: 1 });
    const after = await c.req({ method: 'GET', url: `${base}/${id}/exposure` });
    expect(after.json().findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(['EXP-NOAUTH-001']);

    // Exposure findings live with the rest, in the findings list.
    const list = await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/findings?status=open` });
    expect(list.statusCode).toBe(200);
  });

  it('reports exposed pages through the route', async () => {
    const { c, base } = await setup();
    const id = await target(c, base);
    const { createServer: createHttp } = await import('node:http');
    const server = createHttp((req, res) => { res.writeHead(req.url === '/.git/config' || req.url === '/' ? 200 : 404); res.end(req.url === '/.git/config' ? '[core]\n' : 'x'); });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    fakes.push({ server: server as unknown as Server, port: (server.address() as AddressInfo).port });
    const ports: Record<number, number> = { 80: (server.address() as AddressInfo).port, 443: await closedPort() };
    setExposureProbeOptions({ resolve: async () => ['127.0.0.1'], allowPrivate: true, services: [], dialPort: (p) => ports[p]!, timeoutMs: 1500 });
    const res = await c.req({ method: 'POST', url: `${base}/${id}/exposure` });
    expect(res.statusCode).toBe(200);
    expect(res.json().pages).toEqual([{ url: 'http://staging.paywave.example/.git/config', what: 'Git repository (.git) is served to anyone', severity: 'critical' }]);
    expect(res.json().findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(['EXP-FILE-001']);
  });

  it('turns a private-only host into a clear error', async () => {
    const { c, base } = await setup();
    const id = await target(c, base);
    setExposureProbeOptions({ resolve: async () => ['10.0.0.8'] });
    const res = await c.req({ method: 'POST', url: `${base}/${id}/exposure` });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('EXPOSURE_NO_PUBLIC_ADDRESS');
  });

  it('needs a plan with running-app tests', async () => {
    const { c, base } = await setup('core');
    const id = await target(c, base);
    await setPlan(c.orgId, 'free');
    const res = await c.req({ method: 'POST', url: `${base}/${id}/exposure` });
    expect(res.statusCode).toBe(402);
  });
});
