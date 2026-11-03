import { resolveTxt } from 'node:dns/promises';

import { and, count, desc, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import {
  authorizeTargetSchema,
  createTargetSchema,
  TARGET_AUTHORIZATION_TEXT,
  TARGET_AUTHORIZATION_VERSION,
} from '@fortis/shared';

import { db } from '../db/client';
import { projects, targets, users } from '../db/schema';
import { audit } from '../lib/audit';
import { randomBase62 } from '../lib/crypto';
import { badRequest, conflict, notFound, paymentRequired } from '../lib/errors';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';
import { planLimits } from './orgs.routes';

const projectParams = z.object({ orgId: z.string().uuid(), projectId: z.string().uuid() });
const targetParams = projectParams.extend({ targetId: z.string().uuid() });

export const VERIFY_RECORD_PREFIX = '_fortis-verify';

/** TXT lookup, swappable in tests. Returns the joined strings of each record. */
type TxtResolver = (name: string) => Promise<string[]>;
let txtResolver: TxtResolver = async (name) => (await resolveTxt(name)).map((chunks) => chunks.join(''));
export function setTxtResolver(fn: TxtResolver | null) {
  txtResolver = fn ?? (async (name) => (await resolveTxt(name)).map((chunks) => chunks.join('')));
}

type TargetRow = typeof targets.$inferSelect;

/** Ready means every safeguard has been met: domain proven, testing authorised, not paused. */
export function targetStatus(t: Pick<TargetRow, 'verifiedAt' | 'authorizedAt' | 'pausedAt'>) {
  if (t.pausedAt) return 'paused' as const;
  if (!t.verifiedAt) return 'unverified' as const;
  if (!t.authorizedAt) return 'unauthorized' as const;
  return 'ready' as const;
}

export function presentTarget(t: TargetRow & { authorizedByName?: string | null }) {
  return {
    id: t.id,
    projectId: t.projectId,
    url: t.url,
    hostname: t.hostname,
    environment: t.environment,
    label: t.label,
    status: targetStatus(t),
    verification: {
      recordName: `${VERIFY_RECORD_PREFIX}.${t.hostname}`,
      recordType: 'TXT',
      recordValue: `fortis-verify=${t.verificationToken}`,
      verifiedAt: t.verifiedAt,
      lastError: t.lastVerificationError,
    },
    authorization: t.authorizedAt
      ? { signer: t.authorizedSigner, by: t.authorizedByName ?? null, version: t.authorizationVersion, at: t.authorizedAt }
      : null,
    /** Active (attacking) scans are never allowed against production. */
    allowsActiveScan: t.environment !== 'production',
    pausedAt: t.pausedAt,
    lastRunAt: t.lastRunAt,
    createdAt: t.createdAt,
  };
}

/** Reduces a URL to its origin so one target covers one app, and paths can't dodge the unique key. */
export function normaliseTargetUrl(raw: string) {
  const u = new URL(raw);
  if (u.username || u.password) throw badRequest('Remove the username and password from the URL.', 'TARGET_CREDENTIALS');
  const hostname = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname.includes('.') || /^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.startsWith('[')) {
    throw badRequest(
      'Use a domain name you control (for example staging.yourapp.com). IP addresses and localhost cannot be verified; run `fortis test --local` for those.',
      'TARGET_NOT_VERIFIABLE',
    );
  }
  return { url: `${u.protocol}//${u.host.toLowerCase()}`, hostname };
}

async function loadTarget(orgId: string, projectId: string, targetId: string) {
  const [row] = await db
    .select()
    .from(targets)
    .where(and(eq(targets.id, targetId), eq(targets.projectId, projectId), eq(targets.orgId, orgId)))
    .limit(1);
  if (!row) throw notFound('Target not found.');
  return row;
}

async function withSigner(row: TargetRow) {
  if (!row.authorizedBy) return presentTarget(row);
  const [u] = await db.select({ name: users.name }).from(users).where(eq(users.id, row.authorizedBy)).limit(1);
  return presentTarget({ ...row, authorizedByName: u?.name ?? null });
}

export async function targetRoutes(app: FastifyInstance) {
  const base = '/v1/orgs/:orgId/projects/:projectId/targets';

  app.get(base, async (req) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'viewer');
    const rows = await db
      .select({ t: targets, authorizedByName: users.name })
      .from(targets)
      .leftJoin(users, eq(users.id, targets.authorizedBy))
      .where(and(eq(targets.projectId, projectId), eq(targets.orgId, orgId)))
      .orderBy(desc(targets.createdAt));
    const limits = planLimits(org.plan);
    return {
      targets: rows.map((r) => presentTarget({ ...r.t, authorizedByName: r.authorizedByName })),
      plan: { dast: limits.dast, maxTargets: limits.maxTargets, name: limits.name },
      authorization: { version: TARGET_AUTHORIZATION_VERSION, text: TARGET_AUTHORIZATION_TEXT },
    };
  });

  app.post(base, async (req, reply) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    const { org, user } = await requireOrgRole(req, orgId, 'admin');
    const [project] = await db
      .select({ id: projects.id })
      .from(projects)
      .where(and(eq(projects.id, projectId), eq(projects.orgId, orgId)))
      .limit(1);
    if (!project) throw notFound('Project not found.');

    const limits = planLimits(org.plan);
    if (limits.dast === 'none') {
      throw paymentRequired(`${limits.name} does not include running-app tests. Upgrade to Fortis Core for OWASP ZAP baseline scans.`);
    }
    const input = parse(createTargetSchema, req.body);
    const { url, hostname } = normaliseTargetUrl(input.url);

    const [used] = await db.select({ n: count() }).from(targets).where(eq(targets.orgId, orgId));
    if (limits.maxTargets !== null && (used?.n ?? 0) >= limits.maxTargets) {
      throw paymentRequired(`${limits.name} includes ${limits.maxTargets} test target(s). Remove one or upgrade to add more.`);
    }

    const inserted = await db
      .insert(targets)
      .values({
        orgId,
        projectId,
        url,
        hostname,
        environment: input.environment,
        label: input.label ?? null,
        verificationToken: randomBase62(32),
        createdBy: user.id,
      })
      .onConflictDoNothing()
      .returning();
    if (!inserted.length) throw conflict('That URL is already a target for this project.', 'TARGET_EXISTS');
    const row = inserted[0]!;
    await audit(db, req, { orgId, action: 'target.created', targetType: 'target', targetId: row.id, meta: { url, environment: input.environment } });
    return reply.code(201).send({ target: presentTarget(row) });
  });

  /** Checks the DNS TXT record that proves the organisation controls the domain. */
  app.post(`${base}/:targetId/verify`, { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req) => {
    const { orgId, projectId, targetId } = parse(targetParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const row = await loadTarget(orgId, projectId, targetId);
    if (row.verifiedAt) return { target: await withSigner(row), verified: true };

    const recordName = `${VERIFY_RECORD_PREFIX}.${row.hostname}`;
    const expected = `fortis-verify=${row.verificationToken}`;
    let records: string[] = [];
    let error: string | null = null;
    try {
      records = await txtResolver(recordName);
    } catch (e) {
      const code = (e as { code?: string }).code;
      error =
        code === 'ENOTFOUND' || code === 'ENODATA'
          ? `No TXT record found at ${recordName} yet. DNS changes can take a few minutes to appear.`
          : `DNS lookup for ${recordName} failed (${code ?? 'unknown error'}). Try again shortly.`;
    }
    const verified = records.some((r) => r.trim() === expected);
    if (!verified && !error) {
      error = records.length
        ? `Found a TXT record at ${recordName}, but it does not match. Set it to exactly: ${expected}`
        : `No TXT record found at ${recordName} yet. DNS changes can take a few minutes to appear.`;
    }

    const [updated] = await db
      .update(targets)
      .set(verified ? { verifiedAt: new Date(), lastVerificationError: null } : { lastVerificationError: error })
      .where(eq(targets.id, row.id))
      .returning();
    await audit(db, req, {
      orgId,
      action: verified ? 'target.verified' : 'target.verify_failed',
      targetType: 'target',
      targetId: row.id,
      meta: { hostname: row.hostname },
    });
    return { target: await withSigner(updated!), verified };
  });

  /** Records who authorised testing, under which wording. Needed before any test result is accepted. */
  app.post(`${base}/:targetId/authorize`, async (req) => {
    const { orgId, projectId, targetId } = parse(targetParams, req.params);
    const { user } = await requireOrgRole(req, orgId, 'admin');
    const row = await loadTarget(orgId, projectId, targetId);
    if (!row.verifiedAt) throw badRequest('Verify the domain before authorising tests.', 'TARGET_UNVERIFIED');
    const { signerName } = parse(authorizeTargetSchema, req.body);
    const [updated] = await db
      .update(targets)
      .set({
        authorizedBy: user.id,
        authorizedSigner: signerName,
        authorizationVersion: TARGET_AUTHORIZATION_VERSION,
        authorizedAt: new Date(),
      })
      .where(eq(targets.id, row.id))
      .returning();
    await audit(db, req, {
      orgId,
      action: 'target.authorized',
      targetType: 'target',
      targetId: row.id,
      meta: { signerName, version: TARGET_AUTHORIZATION_VERSION, text: TARGET_AUTHORIZATION_TEXT },
    });
    return { target: await withSigner(updated!) };
  });

  /** Kill switch. Developers can pause (stopping is always safe); only admins can resume. */
  app.post(`${base}/:targetId/pause`, async (req) => {
    const { orgId, projectId, targetId } = parse(targetParams, req.params);
    await requireOrgRole(req, orgId, 'developer');
    const row = await loadTarget(orgId, projectId, targetId);
    const [updated] = await db.update(targets).set({ pausedAt: row.pausedAt ?? new Date() }).where(eq(targets.id, row.id)).returning();
    await audit(db, req, { orgId, action: 'target.paused', targetType: 'target', targetId: row.id });
    return { target: await withSigner(updated!) };
  });

  app.post(`${base}/:targetId/resume`, async (req) => {
    const { orgId, projectId, targetId } = parse(targetParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const row = await loadTarget(orgId, projectId, targetId);
    const [updated] = await db.update(targets).set({ pausedAt: null }).where(eq(targets.id, row.id)).returning();
    await audit(db, req, { orgId, action: 'target.resumed', targetType: 'target', targetId: row.id });
    return { target: await withSigner(updated!) };
  });

  app.delete(`${base}/:targetId`, async (req) => {
    const { orgId, projectId, targetId } = parse(targetParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const row = await loadTarget(orgId, projectId, targetId);
    await db.delete(targets).where(eq(targets.id, row.id));
    await audit(db, req, { orgId, action: 'target.deleted', targetType: 'target', targetId: row.id, meta: { url: row.url } });
    return { ok: true };
  });
}
