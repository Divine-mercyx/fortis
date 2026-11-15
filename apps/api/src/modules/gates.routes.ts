import { and, desc, eq, gt, isNull } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { gateExceptionSchema, gatePolicySchema } from '@fortis/shared';

import { db } from '../db/client';
import { gateExceptions, projects, releaseGates, users } from '../db/schema';
import { audit } from '../lib/audit';
import { notFound, paymentRequired } from '../lib/errors';
import { loadGate, recentGateRuns } from '../lib/gates';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';
import { planLimits } from './orgs.routes';

const projectParams = z.object({ orgId: z.string().uuid(), projectId: z.string().uuid() });
const exceptionParams = projectParams.extend({ exceptionId: z.string().uuid() });

async function projectIn(orgId: string, projectId: string) {
  const [p] = await db.select({ id: projects.id, name: projects.name }).from(projects).where(and(eq(projects.id, projectId), eq(projects.orgId, orgId))).limit(1);
  if (!p) throw notFound('Project not found.');
  return p;
}

function requireGates(plan: string) {
  const limits = planLimits(plan);
  if (!limits.releaseGates) throw paymentRequired(`${limits.name} doesn't include release gates. They come with Fortis Plus and Enterprise.`);
}

async function present(orgId: string, projectId: string, plan: string) {
  const [policy, exceptions, runs] = await Promise.all([
    loadGate(projectId),
    db
      .select({ id: gateExceptions.id, reason: gateExceptions.reason, commit: gateExceptions.commit, createdAt: gateExceptions.createdAt, expiresAt: gateExceptions.expiresAt, lastUsedAt: gateExceptions.lastUsedAt, by: users.name })
      .from(gateExceptions)
      .leftJoin(users, eq(users.id, gateExceptions.createdBy))
      .where(and(eq(gateExceptions.orgId, orgId), eq(gateExceptions.projectId, projectId), isNull(gateExceptions.revokedAt), gt(gateExceptions.expiresAt, new Date())))
      .orderBy(desc(gateExceptions.createdAt)),
    recentGateRuns(projectId),
  ]);
  return {
    available: planLimits(plan).releaseGates,
    policy,
    exceptions,
    runs: runs.map((r) => {
      const d = (r.detail ?? {}) as { blockingCount?: number; exception?: { reason: string; by: string | null } };
      return { scanId: r.scanId, at: r.at, branch: r.branch, commit: r.commit, status: r.status, blockingCount: d.blockingCount ?? 0, exception: d.exception ?? null };
    }),
  };
}

export async function gateRoutes(app: FastifyInstance) {
  app.get('/v1/orgs/:orgId/projects/:projectId/gate', async (req) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'viewer');
    await projectIn(orgId, projectId);
    return present(orgId, projectId, org.plan);
  });

  app.put('/v1/orgs/:orgId/projects/:projectId/gate', async (req) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'admin');
    requireGates(org.plan);
    const project = await projectIn(orgId, projectId);
    const input = parse(gatePolicySchema, req.body);
    const branches = input.branches !== undefined ? input.branches.split(',').map((b) => b.trim()).filter(Boolean).join(', ') : undefined;
    const values = {
      ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
      ...(input.minSeverity ? { minSeverity: input.minSeverity } : {}),
      ...(input.blockLiveSecrets !== undefined ? { blockLiveSecrets: input.blockLiveSecrets } : {}),
      ...(branches !== undefined ? { branches } : {}),
      updatedAt: new Date(),
    };
    await db.insert(releaseGates).values({ projectId, orgId, ...values }).onConflictDoUpdate({ target: releaseGates.projectId, set: values });
    await audit(db, req, { orgId, action: 'project.gate_updated', targetType: 'project', targetId: projectId, meta: { project: project.name, ...input, ...(branches !== undefined ? { branches } : {}) } });
    return present(orgId, projectId, org.plan);
  });

  /** Lets a release through a failing gate: a reason, an expiry, and optionally one commit. */
  app.post('/v1/orgs/:orgId/projects/:projectId/gate/exceptions', async (req, reply) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    const { org, user } = await requireOrgRole(req, orgId, 'admin');
    requireGates(org.plan);
    const project = await projectIn(orgId, projectId);
    const input = parse(gateExceptionSchema, req.body);
    const expiresAt = new Date(Date.now() + input.hours * 3_600_000);
    const [row] = await db
      .insert(gateExceptions)
      .values({ orgId, projectId, reason: input.reason, commit: input.commit ? input.commit.toLowerCase() : null, createdBy: user.id, expiresAt })
      .returning({ id: gateExceptions.id });
    await audit(db, req, { orgId, action: 'project.gate_exception_approved', targetType: 'project', targetId: projectId, meta: { project: project.name, reason: input.reason, commit: input.commit || null, hours: input.hours } });
    return reply.code(201).send({ id: row!.id, ...(await present(orgId, projectId, org.plan)) });
  });

  app.delete('/v1/orgs/:orgId/projects/:projectId/gate/exceptions/:exceptionId', async (req) => {
    const { orgId, projectId, exceptionId } = parse(exceptionParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'admin');
    const project = await projectIn(orgId, projectId);
    const revoked = await db
      .update(gateExceptions)
      .set({ revokedAt: new Date() })
      .where(and(eq(gateExceptions.id, exceptionId), eq(gateExceptions.projectId, projectId), eq(gateExceptions.orgId, orgId), isNull(gateExceptions.revokedAt)))
      .returning({ id: gateExceptions.id });
    if (!revoked.length) throw notFound('That approval was not found, or it has already been withdrawn.');
    await audit(db, req, { orgId, action: 'project.gate_exception_revoked', targetType: 'project', targetId: projectId, meta: { project: project.name } });
    return present(orgId, projectId, org.plan);
  });
}
