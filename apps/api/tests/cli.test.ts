import { createHash } from 'node:crypto';
import { createPublicKey, verify } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pool } from '../src/db/client';
import { maskSnippet } from '../src/lib/mask';
import {
  FAKE_LIVE_KEY,
  liveKeyFinding,
  ownershipFinding,
  projectWithKey,
  resetDb,
  scanPayload,
  setPlan,
  setupApp,
  signup,
  type Client,
} from './helpers';

let app: FastifyInstance;
beforeAll(async () => {
  app = await setupApp();
});
afterAll(async () => {
  await app.close();
  await pool.end();
});
beforeEach(resetDb);

async function coreProject(): Promise<{ c: Client; projectId: string; key: string }> {
  const c = await signup(app);
  await setPlan(c.orgId, 'core');
  const { projectId, key } = await projectWithKey(c);
  return { c, projectId, key };
}

const upload = (key: string, payload: unknown) =>
  app.inject({ method: 'POST', url: '/v1/cli/scans', headers: { authorization: `Bearer ${key}` }, payload: payload as object });

describe('entitlements and rule packs', () => {
  it('gives the free plan secrets and dependency rules only, and refuses uploads', async () => {
    const c = await signup(app);
    const { key } = await projectWithKey(c);
    const who = await app.inject({ method: 'GET', url: '/v1/cli/whoami', headers: { authorization: `Bearer ${key}` } });
    expect(who.json().entitlements).toMatchObject({ rulePacks: ['secrets', 'dependencies'], uploadFindings: false });
    const res = await upload(key, scanPayload([liveKeyFinding]));
    expect(res.statusCode).toBe(402);
  });

  it('signs the rule pack so the CLI can verify it, and includes fintech rules on Core', async () => {
    const { key } = await coreProject();
    const res = await app.inject({ method: 'GET', url: '/v1/cli/rules', headers: { authorization: `Bearer ${key}` } });
    expect(res.statusCode).toBe(200);
    const pack = res.json();
    const pub = await app.inject({ method: 'GET', url: '/v1/cli/rules/public-key' });
    const ok = verify(null, Buffer.from(pack.payload), createPublicKey(pub.json().publicKey), Buffer.from(pack.signature, 'base64'));
    expect(ok).toBe(true);
    const tampered = pack.payload.replace('"core"', '"plus"');
    expect(verify(null, Buffer.from(tampered), createPublicKey(pub.json().publicKey), Buffer.from(pack.signature, 'base64'))).toBe(false);
    const payload = JSON.parse(pack.payload);
    expect(payload.packs).toContain('fintech');
    expect(payload.rules.some((r: { id: string }) => r.id === 'FX-OWN-001')).toBe(true);
  });
});

describe('scan upload', () => {
  it('creates open findings with a detected event, and masks secrets before storing them', async () => {
    const { key } = await coreProject();
    const res = await upload(key, scanPayload([liveKeyFinding, ownershipFinding]));
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ newCount: 2, fixedCount: 0, duplicate: false });
    const { rows } = await pool.query('select snippet, status from findings order by rule_id');
    expect(rows.every((r) => r.status === 'open')).toBe(true);
    const all = rows.map((r) => r.snippet).join(' ');
    expect(all).not.toContain(FAKE_LIVE_KEY);
    expect(all).toContain('sk_live_••••••••3b7c');
    const events = await pool.query("select count(*)::int as n from finding_events where type = 'detected'");
    expect(events.rows[0].n).toBe(2);
  });

  it('is idempotent: retrying the same scanId does not duplicate anything', async () => {
    const { key } = await coreProject();
    const payload = scanPayload([liveKeyFinding]);
    const first = await upload(key, payload);
    const retry = await upload(key, payload);
    expect(first.statusCode).toBe(201);
    expect(retry.statusCode).toBe(200);
    expect(retry.json()).toMatchObject({ duplicate: true, scanId: first.json().scanId, newCount: 1 });
    const counts = await pool.query('select (select count(*)::int from scans) s, (select count(*)::int from findings) f, (select count(*)::int from finding_events) e');
    expect(counts.rows[0]).toEqual({ s: 1, f: 1, e: 1 });
  });

  it('treats the same issue on a shifted line as the same finding', async () => {
    const { key } = await coreProject();
    await upload(key, scanPayload([liveKeyFinding]));
    const res = await upload(key, scanPayload([{ ...liveKeyFinding, line: 12 }]));
    expect(res.json().newCount).toBe(0);
    const { rows } = await pool.query('select line from findings');
    expect(rows).toEqual([{ line: 12 }]);
  });

  it('closes findings a full scan no longer sees, and reopens them if they come back', async () => {
    const { key } = await coreProject();
    await upload(key, scanPayload([liveKeyFinding, ownershipFinding]));
    const fixed = await upload(key, scanPayload([ownershipFinding]));
    expect(fixed.json().fixedCount).toBe(1);
    let rows = (await pool.query("select rule_id, status, fixed_at from findings order by rule_id")).rows;
    expect(rows.find((r) => r.rule_id === 'FX-SEC-001')).toMatchObject({ status: 'fixed' });
    expect(rows.find((r) => r.rule_id === 'FX-SEC-001')!.fixed_at).not.toBeNull();

    const back = await upload(key, scanPayload([liveKeyFinding, ownershipFinding]));
    expect(back.json().reopenedCount).toBe(1);
    rows = (await pool.query("select status from findings where rule_id = 'FX-SEC-001'")).rows;
    expect(rows[0].status).toBe('open');
    const types = (await pool.query("select e.type from finding_events e join findings f on f.id = e.finding_id where f.rule_id = 'FX-SEC-001' order by e.id")).rows.map((r) => r.type);
    expect(types).toEqual(['detected', 'fixed', 'reopened']);
  });

  it('keeps dependency findings open when the dependency check could not finish', async () => {
    const { key } = await coreProject();
    const depFinding = { ruleId: 'DEP-OSV', severity: 'high', title: 'axios@0.21.1: SSRF', file: 'package-lock.json', line: 0, snippet: 'axios@0.21.1 · CVE-2021-3749' };
    await upload(key, scanPayload([liveKeyFinding, depFinding]));

    // OSV was down: the key really is gone, but the dependency finding was never looked at.
    const partial = await upload(key, scanPayload([], { incompleteChecks: ['dependencies'] }));
    expect(partial.json().fixedCount).toBe(1);
    let rows = (await pool.query('select rule_id, status from findings order by rule_id')).rows;
    expect(rows).toEqual([{ rule_id: 'DEP-OSV', status: 'open' }, { rule_id: 'FX-SEC-001', status: 'fixed' }]);

    // A complete scan that no longer sees it means it really was fixed.
    const complete = await upload(key, scanPayload([]));
    expect(complete.json().fixedCount).toBe(1);
    rows = (await pool.query("select status from findings where rule_id = 'DEP-OSV'")).rows;
    expect(rows[0].status).toBe('fixed');
  });

  it('does not close anything from a changed-files (pre-push) scan', async () => {
    const { key } = await coreProject();
    await upload(key, scanPayload([liveKeyFinding, ownershipFinding]));
    const res = await upload(key, scanPayload([], { trigger: 'pre-push', scope: 'changed' }));
    expect(res.json().fixedCount).toBe(0);
    const open = await pool.query("select count(*)::int n from findings where status = 'open'");
    expect(open.rows[0].n).toBe(2);
  });

  it('rejects oversized snippets so source files cannot be uploaded', async () => {
    const { key } = await coreProject();
    const res = await upload(key, scanPayload([{ ...liveKeyFinding, snippet: 'x'.repeat(5000) }]));
    expect(res.statusCode).toBe(400);
  });

  it("scopes a key to its own project's findings", async () => {
    const a = await coreProject();
    const { key: otherKey } = await projectWithKey(a.c, 'other-service').catch(async () => {
      await setPlan(a.c.orgId, 'plus');
      return projectWithKey(a.c, 'other-service');
    });
    await upload(a.key, scanPayload([liveKeyFinding]));
    await upload(otherKey, scanPayload([]));
    const open = await pool.query("select count(*)::int n from findings where status = 'open'");
    expect(open.rows[0].n).toBe(1); // a full scan of another project must not close it
  });
});

describe('dependency findings', () => {
  it('keep the package-specific title from the CLI', async () => {
    const { key } = await coreProject();
    await upload(key, scanPayload([{ ruleId: 'DEP-OSV', severity: 'critical', title: 'proxy-addr@2.0.7: IP spoofing via IPv4-mapped IPv6', file: 'package-lock.json', line: 0, snippet: 'proxy-addr@2.0.7 · GHSA-jqcg-44mw-7w3h' }]));
    const { rows } = await pool.query('select title from findings');
    expect(rows[0].title).toBe('proxy-addr@2.0.7: IP spoofing via IPv4-mapped IPv6');
  });
});

describe('findings API', () => {
  it('lists by severity, changes status with a reason, and records the change', async () => {
    const { c, key } = await coreProject();
    await upload(key, scanPayload([liveKeyFinding, { ...ownershipFinding, severity: 'high' }]));
    const list = await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/findings?status=open` });
    expect(list.statusCode).toBe(200);
    const items = list.json().findings;
    expect(items.map((f: { severity: string }) => f.severity)).toEqual(['critical', 'high']);

    const id = items[1].id;
    const noReason = await c.req({ method: 'PATCH', url: `/v1/orgs/${c.orgId}/findings/${id}`, payload: { status: 'false_positive' } });
    expect(noReason.statusCode).toBe(400);
    const ok = await c.req({ method: 'PATCH', url: `/v1/orgs/${c.orgId}/findings/${id}`, payload: { status: 'false_positive', reason: 'Test fixture' } });
    expect(ok.statusCode).toBe(200);

    const detail = await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/findings/${id}` });
    expect(detail.json().events.map((e: { type: string }) => e.type)).toEqual(['detected', 'status_changed']);
    expect(detail.json().rule.id).toBe('FX-OWN-001');

    const overview = await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/overview` });
    expect(overview.statusCode).toBe(200);
    expect(overview.json().open.critical).toBe(1);
    expect(overview.json().trend).toHaveLength(30);
  });
});

describe('masking', () => {
  it.each([
    [`key = '${['sk', 'live', 'abcdefghijklmnop1234'].join('_')}'`, 'sk_live_••••••••1234'],
    [['FLWSECK', 'abcdefghijklmnopqrstuvwx1234', 'X'].join('-'), 'FLWSECK-••••••••34-X'],
    ['bvn: 22123456789', 'bvn: ••••••••6789'],
    [['-----BEGIN RSA PRIVATE', 'KEY----- MIIE...'].join(' '), '[private key removed]'],
  ])('masks %s', (input, expected) => {
    expect(maskSnippet(input)).toContain(expected);
  });
});

describe('rule health', () => {
  it('reports the share of triaged findings marked false positive, per rule', async () => {
    const { c, key } = await coreProject();
    const res = await upload(key, scanPayload([liveKeyFinding, ownershipFinding, { ...ownershipFinding, file: 'src/routes/loans.ts' }]));
    const ids = res.json().findings.map((f: { findingId: string }) => f.findingId);
    const list = (await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/findings` })).json().findings as { id: string; ruleId: string }[];
    const own = list.filter((f) => f.ruleId === 'FX-OWN-001');
    expect(ids).toHaveLength(3);
    await c.req({ method: 'PATCH', url: `/v1/orgs/${c.orgId}/findings/${own[0]!.id}`, payload: { status: 'false_positive', reason: 'Staff-only route' } });
    await c.req({ method: 'PATCH', url: `/v1/orgs/${c.orgId}/findings/${own[1]!.id}`, payload: { status: 'fixed' } });
    const health = (await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/rules/health` })).json().rules;
    expect(health.find((r: { ruleId: string }) => r.ruleId === 'FX-OWN-001')).toMatchObject({ total: 2, triaged: 2, falsePositive: 1, falsePositiveRate: 0.5 });
    expect(health.find((r: { ruleId: string }) => r.ruleId === 'FX-SEC-001')).toMatchObject({ open: 1, falsePositiveRate: null });
  });
});

describe('evidence pack', () => {
  it('is gated by plan, covers the period and is tamper-evident', async () => {
    const free = await signup(app);
    expect((await free.req({ method: 'GET', url: `/v1/orgs/${free.orgId}/evidence` })).statusCode).toBe(402);

    const { c, key } = await coreProject();
    await upload(key, scanPayload([liveKeyFinding, ownershipFinding]));
    const list = (await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/findings` })).json().findings as { id: string; ruleId: string }[];
    await c.req({ method: 'PATCH', url: `/v1/orgs/${c.orgId}/findings/${list.find((f) => f.ruleId === 'FX-OWN-001')!.id}`, payload: { status: 'accepted_risk', reason: 'Internal route, scoped by gateway' } });

    const basic = (await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/evidence` })).json();
    expect(basic.level).toBe('basic');
    expect(basic.findings).toHaveLength(2);
    expect(basic.summary.detected).toBe(2);
    expect(basic.decisions[0]).toMatchObject({ decision: 'accepted_risk', reason: 'Internal route, scoped by gateway', by: 'Ada Okafor' });
    expect(basic.trail).toEqual([]);
    const { digest, ...content } = basic;
    expect(digest).toBe(createHash('sha256').update(JSON.stringify(content)).digest('hex'));
    expect(JSON.stringify(basic)).not.toContain(FAKE_LIVE_KEY);

    await setPlan(c.orgId, 'plus');
    const full = (await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/evidence` })).json();
    expect(full.level).toBe('full');
    expect(full.trail.length).toBeGreaterThanOrEqual(3);
    expect(full.adminLog.some((a: { action: string }) => a.action === 'token.created')).toBe(true);
  });
});
