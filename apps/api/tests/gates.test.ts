import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pool } from '../src/db/client';
import { branchMatches } from '../src/lib/gates';
import { liveKeyFinding, ownershipFinding, projectWithKey, resetDb, scanPayload, setPlan, setupApp, signup, type Client } from './helpers';

let app: FastifyInstance;
beforeAll(async () => {
  app = await setupApp();
});
afterAll(async () => {
  await app.close();
  await pool.end();
});
beforeEach(resetDb);

const highFinding = { ruleId: 'DEP-OSV', severity: 'high', title: 'lodash 4.17.20: prototype pollution', file: 'package-lock.json', line: 1, snippet: 'lodash@4.17.20' };
const mediumFinding = { ruleId: 'SEC-GEN-001', severity: 'medium', title: 'Possible secret', file: 'src/a.ts', line: 3, snippet: 'const token = load()' };

async function plusProject(plan = 'plus') {
  const owner = await signup(app, 'ada@paywave.ng');
  await setPlan(owner.orgId, plan);
  const { key, projectId } = await projectWithKey(owner);
  return { owner, key, projectId };
}
const gateUrl = (c: Client, projectId: string) => `/v1/orgs/${c.orgId}/projects/${projectId}/gate`;
const policy = (c: Client, projectId: string, body: Record<string, unknown>) => c.req({ method: 'PUT', url: gateUrl(c, projectId), payload: body });
const ci = (key: string, findings: Record<string, unknown>[], extra: Record<string, unknown> = {}) =>
  app.inject({ method: 'POST', url: '/v1/cli/scans', headers: { authorization: `Bearer ${key}` }, payload: scanPayload(findings, { trigger: 'ci', branch: 'main', commit: 'a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0', ...extra }) });

describe('branch patterns', () => {
  it('matches names, single-segment and multi-segment wildcards; blank matches everything', () => {
    expect(branchMatches('', 'anything')).toBe(true);
    expect(branchMatches('main', 'main')).toBe(true);
    expect(branchMatches('main', 'main-old')).toBe(false);
    expect(branchMatches('main, release/*', 'release/1.4')).toBe(true);
    expect(branchMatches('release/*', 'release/1.4/hotfix')).toBe(false);
    expect(branchMatches('release/**', 'release/1.4/hotfix')).toBe(true);
    expect(branchMatches('main', null)).toBe(false);
    expect(branchMatches('v1.0', 'v1x0')).toBe(false); // the dot is literal
  });
});

describe('the gate on a CI upload', () => {
  it('is not enforced on Core, or until a Plus project turns it on', async () => {
    const core = await plusProject('core');
    expect((await ci(core.key, [liveKeyFinding])).json().gate).toMatchObject({ enforced: false, reason: expect.stringContaining('release gates') });
    await resetDb();
    const plus = await plusProject();
    expect((await ci(plus.key, [liveKeyFinding])).json().gate).toMatchObject({ enforced: false, reason: expect.stringContaining('turned on') });
  });

  it('fails a CI run with an open finding at the policy level, and passes one without', async () => {
    const { owner, key, projectId } = await plusProject();
    await policy(owner, projectId, { enabled: true });
    const failed = (await ci(key, [ownershipFinding, highFinding])).json().gate;
    expect(failed).toMatchObject({ enforced: true, status: 'failed', blockingCount: 1, policy: { minSeverity: 'critical', blockLiveSecrets: true } });
    expect(failed.blocking[0]).toMatchObject({ ruleId: 'FX-OWN-001', severity: 'critical', file: 'src/routes/transfers.ts' });
    expect(failed.manageUrl).toMatch(/\/projects\/[0-9a-f-]+#release-gate$/);
    const passed = (await ci(key, [highFinding])).json().gate;
    expect(passed).toMatchObject({ enforced: true, status: 'passed', blockingCount: 0 });
  });

  it('follows the policy without any change to the repository', async () => {
    const { owner, key, projectId } = await plusProject();
    await policy(owner, projectId, { enabled: true, minSeverity: 'critical' });
    expect((await ci(key, [highFinding])).json().gate.status).toBe('passed');
    await policy(owner, projectId, { minSeverity: 'high' });
    expect((await ci(key, [highFinding])).json().gate.status).toBe('failed');
    await policy(owner, projectId, { minSeverity: 'medium' });
    expect((await ci(key, [mediumFinding])).json().gate.status).toBe('failed');
  });

  it('only gates CI scans of code, on the branches the policy names', async () => {
    const { owner, key, projectId } = await plusProject();
    await policy(owner, projectId, { enabled: true, branches: 'main, release/*' });
    expect((await ci(key, [ownershipFinding], { branch: 'feature/login' })).json().gate.enforced).toBe(false);
    expect((await ci(key, [ownershipFinding], { branch: 'release/2.0' })).json().gate.status).toBe('failed');
    expect((await ci(key, [ownershipFinding], { trigger: 'pre-push' })).json().gate.enforced).toBe(false);
  });

  it('ignores findings accepted as a risk or marked false positive', async () => {
    const { owner, key, projectId } = await plusProject();
    await policy(owner, projectId, { enabled: true });
    const first = await ci(key, [ownershipFinding]);
    const findingId = first.json().findings[0].findingId;
    await owner.req({ method: 'PATCH', url: `/v1/orgs/${owner.orgId}/findings/${findingId}`, payload: { status: 'accepted_risk', reason: 'Behind a VPN until the rewrite ships' } });
    expect((await ci(key, [ownershipFinding])).json().gate.status).toBe('passed');
  });

  it('blocks a leaked key that is still live, whatever its severity, unless the policy says not to', async () => {
    const { owner, key, projectId } = await plusProject();
    await policy(owner, projectId, { enabled: true, minSeverity: 'critical' });
    const live = { ...highFinding, ruleId: 'SEC-GEN-001', title: 'Generic secret', file: 'src/b.ts', snippet: 'const k = load()', secretStatus: 'live' };
    const g = (await ci(key, [live])).json().gate;
    expect(g.status).toBe('failed');
    expect(g.blocking[0].liveSecret).toBe(true);
    await policy(owner, projectId, { blockLiveSecrets: false });
    expect((await ci(key, [live])).json().gate.status).toBe('passed');
  });

  it('gives a retried upload the verdict it already had', async () => {
    const { owner, key, projectId } = await plusProject();
    await policy(owner, projectId, { enabled: true });
    const payload = scanPayload([ownershipFinding], { trigger: 'ci', branch: 'main' });
    const send = () => app.inject({ method: 'POST', url: '/v1/cli/scans', headers: { authorization: `Bearer ${key}` }, payload });
    const a = (await send()).json();
    await policy(owner, projectId, { enabled: false });
    const b = await send();
    expect(b.statusCode).toBe(200);
    expect(b.json().gate).toEqual(a.gate);
  });
});

describe('approved exceptions', () => {
  it('lets a release through with a reason, for one commit or any, until it expires or is withdrawn', async () => {
    const { owner, key, projectId } = await plusProject();
    await policy(owner, projectId, { enabled: true });
    const tooShort = await owner.req({ method: 'POST', url: `${gateUrl(owner, projectId)}/exceptions`, payload: { reason: 'ok' } });
    expect(tooShort.statusCode).toBe(400);

    const one = await owner.req({ method: 'POST', url: `${gateUrl(owner, projectId)}/exceptions`, payload: { reason: 'Hotfix for the payout outage; key rotated separately', commit: 'A1B2C3D', hours: 4 } });
    expect(one.statusCode).toBe(201);
    const excepted = (await ci(key, [ownershipFinding])).json().gate;
    expect(excepted).toMatchObject({ status: 'excepted', blockingCount: 1, exception: { reason: 'Hotfix for the payout outage; key rotated separately', by: 'Ada Okafor', commit: 'a1b2c3d' } });
    // Another commit isn't covered.
    expect((await ci(key, [ownershipFinding], { commit: 'ffffffffffffffffffffffffffffffffffffffff' })).json().gate.status).toBe('failed');

    await owner.req({ method: 'DELETE', url: `${gateUrl(owner, projectId)}/exceptions/${one.json().id}` });
    expect((await ci(key, [ownershipFinding])).json().gate.status).toBe('failed');

    const any = await owner.req({ method: 'POST', url: `${gateUrl(owner, projectId)}/exceptions`, payload: { reason: 'Release freeze override approved by the CTO' } });
    expect((await ci(key, [ownershipFinding], { commit: 'ffffffffffffffffffffffffffffffffffffffff' })).json().gate.status).toBe('excepted');
    await pool.query("update gate_exceptions set expires_at = now() - interval '1 minute' where id = $1", [any.json().id]);
    expect((await ci(key, [ownershipFinding])).json().gate.status).toBe('failed');
  });
});

describe('managing the gate', () => {
  it('needs Plus to change, an admin to change, and is visible to every member', async () => {
    const core = await plusProject('core');
    expect((await policy(core.owner, core.projectId, { enabled: true })).statusCode).toBe(402);
    expect((await core.owner.req({ method: 'GET', url: gateUrl(core.owner, core.projectId) })).json().available).toBe(false);
    await resetDb();

    const { owner, projectId } = await plusProject();
    const dev = await signup(app, 'tunde@paywave.ng', 'Other');
    await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/members`, payload: { email: 'tunde@paywave.ng', role: 'developer' } });
    expect((await dev.req({ method: 'PUT', url: gateUrl(owner, projectId), payload: { enabled: true } })).statusCode).toBe(403);
    expect((await dev.req({ method: 'GET', url: gateUrl(owner, projectId) })).json()).toMatchObject({ available: true, policy: { enabled: false, minSeverity: 'critical', blockLiveSecrets: true, branches: '' } });
    expect((await policy(owner, projectId, { branches: 'main; rm -rf /' })).statusCode).toBe(400);
  });

  it('lists recent verdicts, audits every change, and puts verdicts in the evidence pack', async () => {
    const { owner, key, projectId } = await plusProject();
    await policy(owner, projectId, { enabled: true, branches: ' main ,release/* ' });
    await ci(key, [ownershipFinding]);
    await owner.req({ method: 'POST', url: `${gateUrl(owner, projectId)}/exceptions`, payload: { reason: 'Hotfix for the payout outage; key rotated separately' } });
    await ci(key, [ownershipFinding]);
    await ci(key, []);
    const view = (await owner.req({ method: 'GET', url: gateUrl(owner, projectId) })).json();
    expect(view.policy.branches).toBe('main, release/*');
    expect(view.runs.map((r: { status: string }) => r.status)).toEqual(['passed', 'excepted', 'failed']);
    expect(view.exceptions).toHaveLength(1);

    const actions = (await owner.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/audit` })).json().entries.map((e: { action: string }) => e.action);
    expect(actions).toEqual(expect.arrayContaining(['project.gate_updated', 'project.gate_exception_approved']));

    const ev = (await owner.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/evidence` })).json();
    expect(ev.summary.releaseGates).toEqual({ passed: 1, failed: 1, excepted: 1 });
    expect(ev.releaseGateRuns.find((r: { status: string }) => r.status === 'excepted')).toMatchObject({ exceptionReason: 'Hotfix for the payout outage; key rotated separately', approvedBy: 'Ada Okafor', branch: 'main' });
  });
});
