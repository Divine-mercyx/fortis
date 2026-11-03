import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pool } from '../src/db/client';
import { projectWithKey, resetDb, scanPayload, setPlan, setupApp, signup, liveKeyFinding } from './helpers';

let app: FastifyInstance;
beforeAll(async () => {
  app = await setupApp();
});
afterAll(async () => {
  await app.close();
  await pool.end();
});
beforeEach(resetDb);

describe('tenant isolation', () => {
  it("never lets one organisation read or change another's data", async () => {
    const a = await signup(app, 'a@example.com', 'Org A');
    const b = await signup(app, 'b@example.com', 'Org B');
    await setPlan(a.orgId, 'core');
    const { projectId, key } = await projectWithKey(a);
    await app.inject({
      method: 'POST', url: '/v1/cli/scans', headers: { authorization: `Bearer ${key}` },
      payload: scanPayload([liveKeyFinding]),
    });
    const [{ id: findingId }] = (await pool.query('select id from findings')).rows;

    // B uses its own session against A's IDs: every route answers 404.
    const attempts = [
      b.req({ method: 'GET', url: `/v1/orgs/${a.orgId}` }),
      b.req({ method: 'GET', url: `/v1/orgs/${a.orgId}/projects` }),
      b.req({ method: 'GET', url: `/v1/orgs/${a.orgId}/projects/${projectId}` }),
      b.req({ method: 'GET', url: `/v1/orgs/${a.orgId}/findings` }),
      b.req({ method: 'GET', url: `/v1/orgs/${a.orgId}/findings/${findingId}` }),
      b.req({ method: 'PATCH', url: `/v1/orgs/${a.orgId}/findings/${findingId}`, payload: { status: 'fixed' } }),
      b.req({ method: 'POST', url: `/v1/orgs/${a.orgId}/projects/${projectId}/tokens`, payload: { name: 'steal' } }),
      b.req({ method: 'GET', url: `/v1/orgs/${a.orgId}/overview` }),
    ];
    for (const res of await Promise.all(attempts)) expect(res.statusCode).toBe(404);

    // B's own org can't reach A's project or finding by ID either.
    const crossProject = await b.req({ method: 'GET', url: `/v1/orgs/${b.orgId}/projects/${projectId}` });
    expect(crossProject.statusCode).toBe(404);
    const crossFinding = await b.req({ method: 'GET', url: `/v1/orgs/${b.orgId}/findings/${findingId}` });
    expect(crossFinding.statusCode).toBe(404);
    const list = await b.req({ method: 'GET', url: `/v1/orgs/${b.orgId}/findings?projectId=${projectId}` });
    expect(list.json().findings).toHaveLength(0);

    const status = (await pool.query('select status from findings where id = $1', [findingId])).rows[0].status;
    expect(status).toBe('open');
  });

  it('requires sign-in for org routes', async () => {
    const a = await signup(app);
    const res = await app.inject({ method: 'GET', url: `/v1/orgs/${a.orgId}/projects` });
    expect(res.statusCode).toBe(401);
  });
});

describe('roles and plan limits', () => {
  it('lets a viewer read but not create projects or keys', async () => {
    const owner = await signup(app, 'owner@example.com');
    const viewer = await signup(app, 'viewer@example.com', 'Viewer Co');
    const add = await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/members`, payload: { email: 'viewer@example.com', role: 'viewer' } });
    expect(add.statusCode).toBe(402); // free plan has one seat
    await setPlan(owner.orgId, 'core');
    const added = await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/members`, payload: { email: 'viewer@example.com', role: 'viewer' } });
    expect(added.statusCode).toBe(201);

    const read = await viewer.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/projects` });
    expect(read.statusCode).toBe(200);
    const create = await viewer.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/projects`, payload: { name: 'nope' } });
    expect(create.statusCode).toBe(403);
    expect(create.json().error.code).toBe('ROLE_REQUIRED');
  });

  it('enforces the project limit of the plan', async () => {
    const c = await signup(app);
    const first = await c.req({ method: 'POST', url: `/v1/orgs/${c.orgId}/projects`, payload: { name: 'one' } });
    expect(first.statusCode).toBe(201);
    const second = await c.req({ method: 'POST', url: `/v1/orgs/${c.orgId}/projects`, payload: { name: 'two' } });
    expect(second.statusCode).toBe(402);
  });

  it('keeps at least one owner', async () => {
    const c = await signup(app);
    const res = await c.req({ method: 'DELETE', url: `/v1/orgs/${c.orgId}/members/${c.userId}` });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('LAST_OWNER');
  });
});

describe('CLI keys', () => {
  it('shows the full key once, stores only its hash, and stops working when revoked', async () => {
    const c = await signup(app);
    const { projectId, key, tokenId } = await projectWithKey(c);
    expect(key).toMatch(/^fts_[A-Za-z0-9]{40}$/);
    const { rows } = await pool.query('select token_hash, token_prefix from project_tokens');
    expect(rows[0].token_hash).not.toContain(key);
    expect(key.startsWith(rows[0].token_prefix)).toBe(true);

    const list = await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/projects/${projectId}/tokens` });
    expect(JSON.stringify(list.json())).not.toContain(key);

    const ok = await app.inject({ method: 'GET', url: '/v1/cli/whoami', headers: { authorization: `Bearer ${key}` } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().project.id).toBe(projectId);

    const revoke = await c.req({ method: 'DELETE', url: `/v1/orgs/${c.orgId}/projects/${projectId}/tokens/${tokenId}` });
    expect(revoke.statusCode).toBe(200);
    const after = await app.inject({ method: 'GET', url: '/v1/cli/whoami', headers: { authorization: `Bearer ${key}` } });
    expect(after.statusCode).toBe(401);
  });

  it('rejects missing, malformed and made-up keys', async () => {
    for (const authorization of [undefined, 'Bearer nope', `Bearer fts_${'x'.repeat(40)}`]) {
      const res = await app.inject({ method: 'GET', url: '/v1/cli/whoami', headers: authorization ? { authorization } : {} });
      expect(res.statusCode).toBe(401);
    }
  });
});
