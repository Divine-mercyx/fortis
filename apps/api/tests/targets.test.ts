import { randomUUID } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pool } from '../src/db/client';
import { setTxtResolver } from '../src/modules/targets.routes';
import { projectWithKey, resetDb, setPlan, setupApp, signup, type Client } from './helpers';

let app: FastifyInstance;
beforeAll(async () => {
  app = await setupApp();
});
afterAll(async () => {
  await app.close();
  await pool.end();
});
beforeEach(resetDb);
afterEach(() => setTxtResolver(null));

/** Fake DNS: hostname -> TXT records at _fortis-verify.<hostname>. */
function fakeDns(records: Record<string, string[]>) {
  setTxtResolver(async (name) => {
    const hit = records[name];
    if (!hit) throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
    return hit;
  });
}

async function setup(plan = 'core') {
  const c = await signup(app);
  await setPlan(c.orgId, plan);
  const { projectId, key } = await projectWithKey(c);
  return { c, projectId, key, base: `/v1/orgs/${c.orgId}/projects/${projectId}/targets` };
}

async function readyTarget(c: Client, base: string, url = 'https://staging.paywave.ng', environment = 'staging') {
  const created = await c.req({ method: 'POST', url: base, payload: { url, environment } });
  expect(created.statusCode).toBe(201);
  const t = created.json().target;
  fakeDns({ [t.verification.recordName]: [t.verification.recordValue] });
  expect((await c.req({ method: 'POST', url: `${base}/${t.id}/verify` })).json().verified).toBe(true);
  const auth = await c.req({ method: 'POST', url: `${base}/${t.id}/authorize`, payload: { signerName: 'Ada Okafor', accept: true } });
  expect(auth.json().target.status).toBe('ready');
  return t.id as string;
}

const zapFinding = (title = 'Content Security Policy (CSP) Header Not Set', file = '/login') => ({
  ruleId: 'ZAP-10038',
  severity: 'medium',
  title,
  file,
  detail: 'Set a Content-Security-Policy header.',
});

const dastUpload = (key: string, targetId: string, findings: object[], extra: object = {}) =>
  app.inject({
    method: 'POST',
    url: '/v1/cli/scans',
    headers: { authorization: `Bearer ${key}` },
    payload: { scanId: randomUUID(), trigger: 'ci', kind: 'dast', targetId, dastMode: 'baseline', scope: 'full', cliVersion: '0.1.0', findings, ...extra },
  });

describe('staging targets', () => {
  it('needs a plan with running-app tests', async () => {
    const { c, base } = await setup('free');
    const res = await c.req({ method: 'POST', url: base, payload: { url: 'https://staging.paywave.ng', environment: 'staging' } });
    expect(res.statusCode).toBe(402);
  });

  it('stores the origin only and rejects IPs, localhost and credentials', async () => {
    const { c, base } = await setup();
    const ok = await c.req({ method: 'POST', url: base, payload: { url: 'https://Staging.PayWave.ng/login?x=1', environment: 'staging' } });
    expect(ok.json().target).toMatchObject({ url: 'https://staging.paywave.ng', status: 'unverified' });
    expect(ok.json().target.verification.recordName).toBe('_fortis-verify.staging.paywave.ng');
    for (const url of ['http://localhost:3000', 'http://10.0.0.4', 'https://user:pw@staging2.paywave.ng']) {
      const bad = await c.req({ method: 'POST', url: base, payload: { url, environment: 'staging' } });
      expect(bad.statusCode, url).toBe(400);
    }
    const dup = await c.req({ method: 'POST', url: base, payload: { url: 'https://staging.paywave.ng/other', environment: 'staging' } });
    expect(dup.statusCode).toBe(409);
  });

  it('enforces the plan target limit', async () => {
    const { c, base } = await setup('core');
    for (const h of ['a', 'b']) {
      expect((await c.req({ method: 'POST', url: base, payload: { url: `https://${h}.paywave.ng`, environment: 'staging' } })).statusCode).toBe(201);
    }
    expect((await c.req({ method: 'POST', url: base, payload: { url: 'https://c.paywave.ng', environment: 'staging' } })).statusCode).toBe(402);
  });

  it('verifies only with the exact TXT value, and requires verification before authorisation', async () => {
    const { c, base } = await setup();
    const t = (await c.req({ method: 'POST', url: base, payload: { url: 'https://staging.paywave.ng', environment: 'staging' } })).json().target;
    const early = await c.req({ method: 'POST', url: `${base}/${t.id}/authorize`, payload: { signerName: 'Ada Okafor', accept: true } });
    expect(early.statusCode).toBe(400);

    fakeDns({});
    const missing = (await c.req({ method: 'POST', url: `${base}/${t.id}/verify` })).json();
    expect(missing.verified).toBe(false);
    expect(missing.target.verification.lastError).toMatch(/No TXT record/);

    fakeDns({ [t.verification.recordName]: ['fortis-verify=wrong'] });
    const wrong = (await c.req({ method: 'POST', url: `${base}/${t.id}/verify` })).json();
    expect(wrong.verified).toBe(false);
    expect(wrong.target.verification.lastError).toMatch(/does not match/);

    fakeDns({ [t.verification.recordName]: ['v=spf1 -all', t.verification.recordValue] });
    expect((await c.req({ method: 'POST', url: `${base}/${t.id}/verify` })).json().verified).toBe(true);
  });

  it('keeps targets private to the organisation and limits who can change them', async () => {
    const { c, base, projectId } = await setup();
    const id = await readyTarget(c, base);
    const other = await signup(app);
    const res = await other.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/projects/${projectId}/targets` });
    expect(res.statusCode).toBe(404);
    const cross = await other.req({ method: 'POST', url: `/v1/orgs/${other.orgId}/projects/${projectId}/targets/${id}/pause` });
    expect(cross.statusCode).toBe(404);
  });
});

describe('running-app (DAST) uploads', () => {
  it('accepts results only for a verified, authorised, unpaused target', async () => {
    const { c, base, key } = await setup();
    const t = (await c.req({ method: 'POST', url: base, payload: { url: 'https://staging.paywave.ng', environment: 'staging' } })).json().target;
    expect((await dastUpload(key, t.id, [zapFinding()])).statusCode).toBe(403);

    const id = await readyTarget(c, base, 'https://qa.paywave.ng');
    expect((await dastUpload(key, id, [zapFinding()])).statusCode).toBe(201);

    await c.req({ method: 'POST', url: `${base}/${id}/pause` });
    const paused = await dastUpload(key, id, [zapFinding()]);
    expect(paused.statusCode).toBe(403);
    expect(paused.json().error.message).toMatch(/paused/);
    await c.req({ method: 'POST', url: `${base}/${id}/resume` });
    expect((await dastUpload(key, id, [zapFinding()])).statusCode).toBe(201);
  });

  it('gates full active scans by plan and never allows them on production', async () => {
    const { c, base, key } = await setup('core');
    const id = await readyTarget(c, base);
    expect((await dastUpload(key, id, [], { dastMode: 'full' })).statusCode).toBe(402);

    await setPlan(c.orgId, 'plus');
    expect((await dastUpload(key, id, [], { dastMode: 'full' })).statusCode).toBe(201);
    const prod = await readyTarget(c, base, 'https://app.paywave.ng', 'production');
    const res = await dastUpload(key, prod, [], { dastMode: 'full' });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.message).toMatch(/production/);
  });

  it('rejects a target from another project', async () => {
    const { c, base } = await setup();
    const id = await readyTarget(c, base);
    const { key: otherKey } = await projectWithKey(c, 'other-project');
    expect((await dastUpload(otherKey, id, [zapFinding()])).statusCode).toBe(404);
  });

  it('keeps DAST and code findings apart when closing fixed ones', async () => {
    const { c, base, key } = await setup();
    const id = await readyTarget(c, base);
    const codeScan = await app.inject({
      method: 'POST',
      url: '/v1/cli/scans',
      headers: { authorization: `Bearer ${key}` },
      payload: {
        scanId: randomUUID(), trigger: 'ci', scope: 'full', cliVersion: '0.1.0',
        findings: [{ ruleId: 'SEC-GEN-001', severity: 'high', title: 'Secret', file: 'src/a.ts', line: 1, snippet: 'const x = 1' }],
      },
    });
    expect(codeScan.statusCode).toBe(201);

    const first = (await dastUpload(key, id, [zapFinding(), zapFinding('Cookie without Secure flag', '/')])).json();
    expect(first.newCount).toBe(2);
    // The next full DAST run only sees one alert: the other closes, the code finding stays open.
    const second = (await dastUpload(key, id, [zapFinding()])).json();
    expect(second.fixedCount).toBe(1);

    const list = (await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/findings?status=open` })).json();
    expect(list.findings.map((f: { kind: string }) => f.kind).sort()).toEqual(['code', 'dast']);
    const dast = list.findings.find((f: { kind: string }) => f.kind === 'dast');
    const detail = (await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/findings/${dast.id}` })).json();
    expect(detail.finding).toMatchObject({ title: 'Content Security Policy (CSP) Header Not Set', detail: 'Set a Content-Security-Policy header.' });
  });

  it('a baseline run does not close findings that only an active scan can see', async () => {
    const { c, base, key } = await setup('plus');
    const id = await readyTarget(c, base);
    const full = (await dastUpload(key, id, [zapFinding('SQL Injection', '/api/search')], { dastMode: 'full' })).json();
    expect(full.newCount).toBe(1);
    const baseline = (await dastUpload(key, id, [], { dastMode: 'baseline' })).json();
    expect(baseline.fixedCount).toBe(0);
    const fullAgain = (await dastUpload(key, id, [], { dastMode: 'full' })).json();
    expect(fullAgain.fixedCount).toBe(1);
  });

  it('tells the CLI which targets are ready and why others are not', async () => {
    const { c, base, key } = await setup();
    await readyTarget(c, base);
    await c.req({ method: 'POST', url: base, payload: { url: 'https://qa.paywave.ng', environment: 'staging' } });
    const res = await app.inject({ method: 'GET', url: '/v1/cli/targets', headers: { authorization: `Bearer ${key}` } });
    const byUrl = Object.fromEntries(res.json().targets.map((t: { url: string }) => [t.url, t]));
    expect(byUrl['https://staging.paywave.ng']).toMatchObject({ status: 'ready', blocker: null });
    expect(byUrl['https://qa.paywave.ng'].blocker).toMatch(/Verify the domain/);
    const one = await app.inject({
      method: 'GET',
      url: `/v1/cli/targets?url=${encodeURIComponent('https://staging.paywave.ng/login')}&mode=full`,
      headers: { authorization: `Bearer ${key}` },
    });
    expect(one.json().targets).toHaveLength(1);
    expect(one.json().targets[0].blocker).toMatch(/Fortis Plus/);
  });
});
