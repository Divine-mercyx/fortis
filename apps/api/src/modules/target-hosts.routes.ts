import { and, asc, count, eq, isNotNull } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { db } from '../db/client';
import { targetHosts, targets } from '../db/schema';
import { audit } from '../lib/audit';
import { randomBase62 } from '../lib/crypto';
import { badRequest, conflict, notFound, paymentRequired } from '../lib/errors';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';
import { planLimits } from './orgs.routes';
import { normaliseTargetUrl, resolveTxtRecords, VERIFY_RECORD_PREFIX } from './targets.routes';

/*
 * More host names for a target's exposure checks (#92): companies also run admin., api., staging. and backoffice.
 * hosts. Each one is proven the same way as the target, with a TXT record at _fortis-verify.<hostname>, before
 * Fortis connects to it. Nothing is discovered: only host names an admin adds, and only once verified. They run under
 * the target's own safeguards: its plan, its signed authorisation and its kill switch.
 */

const targetParams = z.object({ orgId: z.string().uuid(), projectId: z.string().uuid(), targetId: z.string().uuid() });
const hostParams = targetParams.extend({ hostId: z.string().uuid() });
const addSchema = z.object({ hostname: z.string().trim().min(3).max(253) });

/** Host names per target, so one target can't become a list of every domain an organisation owns. */
export const MAX_HOSTS_PER_TARGET = 10;

type HostRow = typeof targetHosts.$inferSelect;

export function presentHost(h: HostRow) {
  return {
    id: h.id,
    hostname: h.hostname,
    status: h.verifiedAt ? ('verified' as const) : ('unverified' as const),
    verification: {
      recordName: `${VERIFY_RECORD_PREFIX}.${h.hostname}`,
      recordType: 'TXT',
      recordValue: `fortis-verify=${h.verificationToken}`,
      verifiedAt: h.verifiedAt,
      lastError: h.lastVerificationError,
    },
    createdAt: h.createdAt,
  };
}

/** The verified host names of a target: the only extra ones an exposure check may contact. */
export async function verifiedHostnames(targetId: string): Promise<string[]> {
  const rows = await db
    .select({ hostname: targetHosts.hostname })
    .from(targetHosts)
    .where(and(eq(targetHosts.targetId, targetId), isNotNull(targetHosts.verifiedAt)))
    .orderBy(asc(targetHosts.createdAt));
  return rows.map((r) => r.hostname);
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

async function loadHost(orgId: string, targetId: string, hostId: string) {
  const [row] = await db
    .select()
    .from(targetHosts)
    .where(and(eq(targetHosts.id, hostId), eq(targetHosts.targetId, targetId), eq(targetHosts.orgId, orgId)))
    .limit(1);
  if (!row) throw notFound('Host name not found.');
  return row;
}

export async function targetHostRoutes(app: FastifyInstance) {
  const base = '/v1/orgs/:orgId/projects/:projectId/targets/:targetId/hosts';

  app.get(base, async (req) => {
    const { orgId, projectId, targetId } = parse(targetParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const target = await loadTarget(orgId, projectId, targetId);
    const rows = await db.select().from(targetHosts).where(eq(targetHosts.targetId, target.id)).orderBy(asc(targetHosts.createdAt));
    return { hosts: rows.map(presentHost), max: MAX_HOSTS_PER_TARGET };
  });

  app.post(base, async (req, reply) => {
    const { orgId, projectId, targetId } = parse(targetParams, req.params);
    const { org, user } = await requireOrgRole(req, orgId, 'admin');
    const limits = planLimits(org.plan);
    if (limits.dast === 'none') throw paymentRequired('Exposure checks come with running-app tests, on Fortis Core and above.', 'PLAN_EXPOSURE');
    const target = await loadTarget(orgId, projectId, targetId);
    const { hostname: raw } = parse(addSchema, req.body);
    // The same rules as a target: a domain name, not an IP address or localhost.
    const { hostname } = normaliseTargetUrl(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
    if (hostname === target.hostname) throw conflict(`${hostname} is the target's own host name; it's already checked.`, 'TARGET_HOST_EXISTS');
    const [used] = await db.select({ n: count() }).from(targetHosts).where(eq(targetHosts.targetId, target.id));
    if ((used?.n ?? 0) >= MAX_HOSTS_PER_TARGET) throw badRequest(`A target can have up to ${MAX_HOSTS_PER_TARGET} more host names. Remove one first.`, 'TARGET_HOSTS_LIMIT');
    const inserted = await db
      .insert(targetHosts)
      .values({ orgId, targetId: target.id, hostname, verificationToken: randomBase62(32), createdBy: user.id })
      .onConflictDoNothing()
      .returning();
    if (!inserted.length) throw conflict(`${hostname} is already a host name of this target.`, 'TARGET_HOST_EXISTS');
    await audit(db, req, { orgId, action: 'target.host_added', targetType: 'target', targetId: target.id, meta: { hostname } });
    return reply.code(201).send({ host: presentHost(inserted[0]!) });
  });

  /** Checks the host name's own TXT record. Until it matches, exposure checks never contact the host. */
  app.post(`${base}/:hostId/verify`, { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req) => {
    const { orgId, projectId, targetId, hostId } = parse(hostParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const target = await loadTarget(orgId, projectId, targetId);
    const row = await loadHost(orgId, target.id, hostId);
    if (row.verifiedAt) return { host: presentHost(row), verified: true };

    const recordName = `${VERIFY_RECORD_PREFIX}.${row.hostname}`;
    const expected = `fortis-verify=${row.verificationToken}`;
    const lookup = await resolveTxtRecords(recordName);
    let error = lookup.error;
    const verified = lookup.records.some((r) => r.trim() === expected);
    if (!verified && !error) {
      error = lookup.records.length
        ? `Found a TXT record at ${recordName}, but it does not match. Set it to exactly: ${expected}`
        : `No TXT record found at ${recordName} yet. DNS changes can take a few minutes to appear.`;
    }
    const [updated] = await db
      .update(targetHosts)
      .set(verified ? { verifiedAt: new Date(), lastVerificationError: null } : { lastVerificationError: error })
      .where(eq(targetHosts.id, row.id))
      .returning();
    await audit(db, req, { orgId, action: verified ? 'target.host_verified' : 'target.host_verify_failed', targetType: 'target', targetId: target.id, meta: { hostname: row.hostname } });
    return { host: presentHost(updated!), verified };
  });

  app.delete(`${base}/:hostId`, async (req) => {
    const { orgId, projectId, targetId, hostId } = parse(hostParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const target = await loadTarget(orgId, projectId, targetId);
    const row = await loadHost(orgId, target.id, hostId);
    await db.delete(targetHosts).where(eq(targetHosts.id, row.id));
    await audit(db, req, { orgId, action: 'target.host_removed', targetType: 'target', targetId: target.id, meta: { hostname: row.hostname } });
    return { ok: true };
  });
}
