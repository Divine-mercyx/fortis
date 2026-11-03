import { eq, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';

import { loginSchema, PLANS, isPlanId, signupSchema } from '@fortis/shared';

import { env } from '../config/env';
import { db } from '../db/client';
import { memberships, organizations, sessions, users } from '../db/schema';
import { audit } from '../lib/audit';
import { conflict, unauthorized } from '../lib/errors';
import { dummyHash, hashPassword, verifyPassword } from '../lib/password';
import { slugWithSuffix } from '../lib/slug';
import { parse } from '../lib/validate';
import { requireUser, SESSION_COOKIE, startSession } from '../plugins/auth';

const authRateLimit = { rateLimit: { max: env.AUTH_RATE_LIMIT_PER_MIN, timeWindow: '1 minute' } };

export async function listUserOrgs(userId: string) {
  const rows = await db
    .select({ id: organizations.id, name: organizations.name, slug: organizations.slug, plan: organizations.plan, role: memberships.role })
    .from(memberships)
    .innerJoin(organizations, eq(organizations.id, memberships.orgId))
    .where(eq(memberships.userId, userId))
    .orderBy(organizations.createdAt);
  return rows.map((o) => ({ ...o, planName: isPlanId(o.plan) ? PLANS[o.plan].name : o.plan }));
}

export async function authRoutes(app: FastifyInstance) {
  app.post('/v1/auth/signup', { config: authRateLimit }, async (req, reply) => {
    const input = parse(signupSchema, req.body);
    const passwordHash = await hashPassword(input.password);

    const result = await db.transaction(async (tx) => {
      const existing = await tx.select({ id: users.id }).from(users).where(sql`lower(${users.email}) = ${input.email}`).limit(1);
      if (existing.length) throw conflict('An account with this email already exists. Try signing in.', 'EMAIL_TAKEN');
      const [user] = await tx.insert(users).values({ email: input.email, name: input.name, passwordHash }).returning();
      const [org] = await tx.insert(organizations).values({ name: input.company, slug: slugWithSuffix(input.company), plan: env.DEFAULT_PLAN }).returning();
      await tx.insert(memberships).values({ orgId: org!.id, userId: user!.id, role: 'owner' });
      req.user = { id: user!.id, email: user!.email, name: user!.name };
      await audit(tx, req, { orgId: org!.id, action: 'org.created', targetType: 'organization', targetId: org!.id });
      return { user: user!, org: org! };
    });

    await startSession(req, reply, result.user.id);
    return reply.code(201).send({
      user: { id: result.user.id, email: result.user.email, name: result.user.name },
      orgs: await listUserOrgs(result.user.id),
    });
  });

  app.post('/v1/auth/login', { config: authRateLimit }, async (req, reply) => {
    const input = parse(loginSchema, req.body);
    const [user] = await db.select().from(users).where(sql`lower(${users.email}) = ${input.email}`).limit(1);
    const ok = await verifyPassword(user?.passwordHash ?? (await dummyHash()), input.password);
    if (!user || !ok) throw unauthorized('Email or password is incorrect.', 'INVALID_CREDENTIALS');
    await startSession(req, reply, user.id);
    return { user: { id: user.id, email: user.email, name: user.name }, orgs: await listUserOrgs(user.id) };
  });

  app.post('/v1/auth/logout', async (req, reply) => {
    if (req.sessionId) await db.delete(sessions).where(eq(sessions.id, req.sessionId));
    reply.clearCookie(SESSION_COOKIE, { path: '/' });
    return { ok: true };
  });

  app.get('/v1/auth/me', async (req) => {
    const user = requireUser(req);
    return { user, orgs: await listUserOrgs(user.id) };
  });
}
