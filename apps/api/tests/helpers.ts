import { randomUUID } from 'node:crypto';

import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from 'fastify';
import { eq } from 'drizzle-orm';

import { buildApp } from '../src/app';
import { db, pool } from '../src/db/client';
import { organizations } from '../src/db/schema';

export const ORIGIN = 'http://localhost:3000';

export async function setupApp() {
  return buildApp();
}

export async function resetDb() {
  await pool.query(`truncate audit_log, finding_events, findings, scans, targets, project_tokens, projects,
    memberships, sessions, organizations, users restart identity cascade`);
}

export type Client = {
  cookie: string;
  orgId: string;
  userId: string;
  req: (opts: InjectOptions) => Promise<LightMyRequestResponse>;
};

/** Signs up a user and returns a client that sends their session cookie. */
export async function signup(app: FastifyInstance, email = `${randomUUID().slice(0, 8)}@example.com`, company = 'PayWave'): Promise<Client> {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/auth/signup',
    headers: { origin: ORIGIN },
    payload: { name: 'Ada Okafor', email, password: 'correct-horse-battery', company },
  });
  if (res.statusCode !== 201) throw new Error(`signup failed: ${res.statusCode} ${res.body}`);
  const setCookie = res.headers['set-cookie'];
  const raw = Array.isArray(setCookie) ? setCookie[0]! : setCookie!;
  const cookie = raw.split(';')[0]!;
  const body = res.json();
  return {
    cookie,
    orgId: body.orgs[0].id,
    userId: body.user.id,
    req: (opts) => app.inject({ ...opts, headers: { origin: ORIGIN, ...(opts.headers ?? {}), cookie } }),
  };
}

export async function setPlan(orgId: string, plan: string) {
  await db.update(organizations).set({ plan }).where(eq(organizations.id, orgId));
}

/** Creates a project and a CLI key for it. */
export async function projectWithKey(client: Client, name = 'paywave-api') {
  const p = await client.req({ method: 'POST', url: `/v1/orgs/${client.orgId}/projects`, payload: { name } });
  if (p.statusCode !== 201) throw new Error(`project failed: ${p.body}`);
  const projectId = p.json().project.id as string;
  const t = await client.req({ method: 'POST', url: `/v1/orgs/${client.orgId}/projects/${projectId}/tokens`, payload: { name: 'CI' } });
  if (t.statusCode !== 201) throw new Error(`token failed: ${t.body}`);
  return { projectId, key: t.json().token.secret as string, tokenId: t.json().token.id as string };
}

export function scanPayload(findings: Record<string, unknown>[], extra: Record<string, unknown> = {}) {
  return { scanId: randomUUID(), trigger: 'ci', scope: 'full', cliVersion: '0.1.0', findings, ...extra };
}

/** A fake Paystack-style key, assembled at runtime so secret scanners don't flag the source. */
export const FAKE_LIVE_KEY = ['sk', 'live', '4f8a9c2b7d1e6f3a0b5c8d2e9f1a3b7c'].join('_');

export const liveKeyFinding = {
  ruleId: 'FX-SEC-001',
  severity: 'critical',
  title: 'Live Paystack key',
  file: 'src/config.ts',
  line: 4,
  snippet: `export const PAYSTACK_KEY = '${FAKE_LIVE_KEY}'`,
};

export const ownershipFinding = {
  ruleId: 'FX-OWN-001',
  severity: 'critical',
  title: 'Transfer read without ownership check',
  file: 'src/routes/transfers.ts',
  line: 41,
  snippet: 'const t = await Transfer.findById(req.params.id)',
};
