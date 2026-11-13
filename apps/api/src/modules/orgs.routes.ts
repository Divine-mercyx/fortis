import { and, count, desc, eq, isNull, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { addMemberSchema, createProjectSchema, createTokenSchema, isPlanId, PLANS } from '@fortis/shared';

import { db } from '../db/client';
import { memberships, organizations, projectTokens, projects, users } from '../db/schema';
import { audit } from '../lib/audit';
import { newProjectToken } from '../lib/crypto';
import { badRequest, conflict, notFound, paymentRequired } from '../lib/errors';
import { slugify } from '../lib/slug';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';

const orgParams = z.object({ orgId: z.string().uuid() });
const projectParams = orgParams.extend({ projectId: z.string().uuid() });
const tokenParams = projectParams.extend({ tokenId: z.string().uuid() });
const memberParams = orgParams.extend({ userId: z.string().uuid() });

export function planLimits(plan: string) {
  return isPlanId(plan) ? PLANS[plan] : PLANS.free;
}

async function loadProject(orgId: string, projectId: string) {
  const [project] = await db
    .select()
    .from(projects)
    .where(and(eq(projects.id, projectId), eq(projects.orgId, orgId)))
    .limit(1);
  if (!project) throw notFound('Project not found.');
  return project;
}

export async function orgRoutes(app: FastifyInstance) {
  /* ---------- Organisation ---------- */

  app.get('/v1/orgs/:orgId', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const { org, role } = await requireOrgRole(req, orgId, 'viewer');
    const [[p], [m]] = await Promise.all([
      db.select({ n: count() }).from(projects).where(eq(projects.orgId, orgId)),
      db.select({ n: count() }).from(memberships).where(eq(memberships.orgId, orgId)),
    ]);
    return { org, role, plan: { id: org.plan, ...planLimits(org.plan) }, usage: { projects: p?.n ?? 0, seats: m?.n ?? 0 } };
  });

  app.patch('/v1/orgs/:orgId', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const { name } = parse(z.object({ name: z.string().trim().min(2).max(120) }), req.body);
    const [org] = await db.update(organizations).set({ name }).where(eq(organizations.id, orgId)).returning();
    await audit(db, req, { orgId, action: 'org.renamed', targetType: 'organization', targetId: orgId, meta: { name } });
    return { org };
  });

  /* ---------- Members ---------- */

  app.get('/v1/orgs/:orgId/members', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const members = await db
      .select({ userId: users.id, name: users.name, email: users.email, role: memberships.role, joinedAt: memberships.createdAt, twoFactorAt: users.twoFactorEnabledAt })
      .from(memberships)
      .innerJoin(users, eq(users.id, memberships.userId))
      .where(eq(memberships.orgId, orgId))
      .orderBy(memberships.createdAt);
    // Whether each member signs in with an authenticator app, so admins can see who still uses only a password.
    return { members: members.map(({ twoFactorAt, ...m }) => ({ ...m, twoFactorEnabled: Boolean(twoFactorAt) })) };
  });

  app.post('/v1/orgs/:orgId/members', async (req, reply) => {
    const { orgId } = parse(orgParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'admin');
    const input = parse(addMemberSchema, req.body);
    const limits = planLimits(org.plan);
    const [seats] = await db.select({ n: count() }).from(memberships).where(eq(memberships.orgId, orgId));
    if (limits.maxSeats !== null && (seats?.n ?? 0) >= limits.maxSeats) {
      throw paymentRequired(`${limits.name} includes ${limits.maxSeats} seat(s). Upgrade to add more people.`);
    }
    const [user] = await db.select().from(users).where(sql`lower(${users.email}) = ${input.email}`).limit(1);
    if (!user) throw notFound('No Fortis account uses that email yet. Ask them to sign up first.', 'USER_NOT_FOUND');
    const inserted = await db
      .insert(memberships)
      .values({ orgId, userId: user.id, role: input.role })
      .onConflictDoNothing()
      .returning();
    if (!inserted.length) throw conflict('That person is already a member.', 'ALREADY_MEMBER');
    await audit(db, req, { orgId, action: 'member.added', targetType: 'user', targetId: user.id, meta: { role: input.role } });
    return reply.code(201).send({ member: { userId: user.id, name: user.name, email: user.email, role: input.role } });
  });

  app.delete('/v1/orgs/:orgId/members/:userId', async (req) => {
    const { orgId, userId } = parse(memberParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const [target] = await db
      .select({ role: memberships.role })
      .from(memberships)
      .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, userId)))
      .limit(1);
    if (!target) throw notFound('Member not found.');
    if (target.role === 'owner') {
      const [owners] = await db
        .select({ n: count() })
        .from(memberships)
        .where(and(eq(memberships.orgId, orgId), eq(memberships.role, 'owner')));
      if ((owners?.n ?? 0) <= 1) throw badRequest('An organisation needs at least one owner.', 'LAST_OWNER');
    }
    await db.delete(memberships).where(and(eq(memberships.orgId, orgId), eq(memberships.userId, userId)));
    await audit(db, req, { orgId, action: 'member.removed', targetType: 'user', targetId: userId });
    return { ok: true };
  });

  /* ---------- Projects ---------- */

  app.get('/v1/orgs/:orgId/projects', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const rows = await db.execute(sql`
      select p.id, p.name, p.slug, p.repo_url as "repoUrl", p.created_at as "createdAt",
        (select count(*)::int from findings f where f.project_id = p.id and f.status = 'open') as "openFindings",
        (select count(*)::int from findings f where f.project_id = p.id and f.status = 'open' and f.severity = 'critical') as "openCritical",
        (select max(s.created_at) from scans s where s.project_id = p.id) as "lastScanAt"
      from projects p where p.org_id = ${orgId} order by p.created_at`);
    return { projects: rows.rows };
  });

  app.post('/v1/orgs/:orgId/projects', async (req, reply) => {
    const { orgId } = parse(orgParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'admin');
    const input = parse(createProjectSchema, req.body);
    const limits = planLimits(org.plan);
    const [existing] = await db.select({ n: count() }).from(projects).where(eq(projects.orgId, orgId));
    if (limits.maxProjects !== null && (existing?.n ?? 0) >= limits.maxProjects) {
      throw paymentRequired(`${limits.name} includes ${limits.maxProjects} project(s). Upgrade to add more.`);
    }
    const inserted = await db
      .insert(projects)
      .values({ orgId, name: input.name, slug: slugify(input.name), repoUrl: input.repoUrl ?? null })
      .onConflictDoNothing()
      .returning();
    if (!inserted.length) throw conflict('A project with that name already exists.', 'PROJECT_EXISTS');
    const project = inserted[0]!;
    await audit(db, req, { orgId, action: 'project.created', targetType: 'project', targetId: project.id });
    return reply.code(201).send({ project });
  });

  app.get('/v1/orgs/:orgId/projects/:projectId', async (req) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    return { project: await loadProject(orgId, projectId) };
  });

  app.delete('/v1/orgs/:orgId/projects/:projectId', async (req) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    await loadProject(orgId, projectId);
    await db.delete(projects).where(and(eq(projects.id, projectId), eq(projects.orgId, orgId)));
    await audit(db, req, { orgId, action: 'project.deleted', targetType: 'project', targetId: projectId });
    return { ok: true };
  });

  /* ---------- CLI keys ---------- */

  app.get('/v1/orgs/:orgId/projects/:projectId/tokens', async (req) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    await requireOrgRole(req, orgId, 'developer');
    await loadProject(orgId, projectId);
    const tokens = await db
      .select({
        id: projectTokens.id,
        name: projectTokens.name,
        prefix: projectTokens.tokenPrefix,
        createdAt: projectTokens.createdAt,
        lastUsedAt: projectTokens.lastUsedAt,
        revokedAt: projectTokens.revokedAt,
        createdBy: users.name,
      })
      .from(projectTokens)
      .leftJoin(users, eq(users.id, projectTokens.createdBy))
      .where(and(eq(projectTokens.projectId, projectId), eq(projectTokens.orgId, orgId)))
      .orderBy(desc(projectTokens.createdAt));
    return { tokens };
  });

  app.post('/v1/orgs/:orgId/projects/:projectId/tokens', async (req, reply) => {
    const { orgId, projectId } = parse(projectParams, req.params);
    const { user } = await requireOrgRole(req, orgId, 'admin');
    await loadProject(orgId, projectId);
    const { name } = parse(createTokenSchema, req.body);
    const { token, hash, displayPrefix } = newProjectToken();
    const [row] = await db
      .insert(projectTokens)
      .values({ orgId, projectId, name, tokenPrefix: displayPrefix, tokenHash: hash, createdBy: user.id })
      .returning({ id: projectTokens.id, name: projectTokens.name, prefix: projectTokens.tokenPrefix, createdAt: projectTokens.createdAt });
    await audit(db, req, { orgId, action: 'token.created', targetType: 'project_token', targetId: row!.id, meta: { projectId } });
    // The full key is returned once and never stored.
    return reply.code(201).send({ token: { ...row, secret: token } });
  });

  app.delete('/v1/orgs/:orgId/projects/:projectId/tokens/:tokenId', async (req) => {
    const { orgId, projectId, tokenId } = parse(tokenParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const revoked = await db
      .update(projectTokens)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(projectTokens.id, tokenId),
          eq(projectTokens.projectId, projectId),
          eq(projectTokens.orgId, orgId),
          isNull(projectTokens.revokedAt),
        ),
      )
      .returning({ id: projectTokens.id });
    if (!revoked.length) throw notFound('Key not found or already revoked.');
    await audit(db, req, { orgId, action: 'token.revoked', targetType: 'project_token', targetId: tokenId, meta: { projectId } });
    return { ok: true };
  });
}
