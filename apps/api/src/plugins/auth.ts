import { and, eq, gt, isNull } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { ROLES, type Role } from '@fortis/shared';

import { env } from '../config/env';
import { db } from '../db/client';
import { memberships, organizations, projectTokens, projects, sessions, users } from '../db/schema';
import { newSessionToken, sha256, TOKEN_PREFIX } from '../lib/crypto';
import { forbidden, notFound, unauthorized } from '../lib/errors';

export const SESSION_COOKIE = 'fortis_session';

export type AuthUser = { id: string; email: string; name: string };
export type CliAuth = { tokenId: string; projectId: string; projectName: string; orgId: string; orgName: string; plan: string };

declare module 'fastify' {
  interface FastifyRequest {
    user: AuthUser | null;
    sessionId: string | null;
  }
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const TOUCH_AFTER_MS = 5 * 60 * 1000;

/** Blocks cookie-authenticated writes coming from other sites. */
function assertSameSite(req: FastifyRequest) {
  if (!MUTATING.has(req.method)) return;
  const origin = req.headers.origin;
  if (origin && !env.webOrigins.includes(origin)) throw forbidden('Request origin not allowed.', 'BAD_ORIGIN');
  if (!origin && req.headers['sec-fetch-site'] === 'cross-site') throw forbidden('Cross-site request blocked.', 'BAD_ORIGIN');
}

export const authPlugin = fp(async (app: FastifyInstance) => {
  app.decorateRequest('user', null);
  app.decorateRequest('sessionId', null);

  app.addHook('onRequest', async (req) => {
    const raw = req.cookies[SESSION_COOKIE];
    if (!raw) return;
    const [row] = await db
      .select({ sessionId: sessions.id, lastSeenAt: sessions.lastSeenAt, id: users.id, email: users.email, name: users.name })
      .from(sessions)
      .innerJoin(users, eq(users.id, sessions.userId))
      .where(and(eq(sessions.tokenHash, sha256(raw)), gt(sessions.expiresAt, new Date())))
      .limit(1);
    if (!row) return;
    assertSameSite(req);
    req.user = { id: row.id, email: row.email, name: row.name };
    req.sessionId = row.sessionId;
    if (Date.now() - row.lastSeenAt.getTime() > TOUCH_AFTER_MS) {
      await db.update(sessions).set({ lastSeenAt: new Date() }).where(eq(sessions.id, row.sessionId));
    }
  });
});

export async function startSession(req: FastifyRequest, reply: FastifyReply, userId: string) {
  const { token, hash } = newSessionToken();
  const expiresAt = new Date(Date.now() + env.SESSION_TTL_DAYS * 86_400_000);
  await db.insert(sessions).values({
    userId,
    tokenHash: hash,
    ip: req.ip,
    userAgent: (req.headers['user-agent'] ?? '').slice(0, 300) || null,
    expiresAt,
  });
  reply.setCookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: env.cookieSecure,
    sameSite: 'lax',
    path: '/',
    expires: expiresAt,
  });
}

export function requireUser(req: FastifyRequest): AuthUser {
  if (!req.user) throw unauthorized();
  return req.user;
}

const RANK: Record<Role, number> = { owner: 4, admin: 3, developer: 2, viewer: 1 };
export const roleAtLeast = (role: string, min: Role) =>
  (ROLES as readonly string[]).includes(role) && RANK[role as Role] >= RANK[min];

/**
 * Loads the org only if the signed-in user belongs to it with at least `min` role.
 * Non-members get 404 (not 403) so org IDs can't be probed.
 */
export async function requireOrgRole(req: FastifyRequest, orgId: string, min: Role) {
  const user = requireUser(req);
  const [row] = await db
    .select({ id: organizations.id, name: organizations.name, slug: organizations.slug, plan: organizations.plan, role: memberships.role })
    .from(memberships)
    .innerJoin(organizations, eq(organizations.id, memberships.orgId))
    .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, user.id)))
    .limit(1);
  if (!row) throw notFound('Organisation not found.');
  if (!roleAtLeast(row.role, min)) throw forbidden(`This needs the ${min} role or higher.`, 'ROLE_REQUIRED');
  return { user, org: { id: row.id, name: row.name, slug: row.slug, plan: row.plan }, role: row.role as Role };
}

/** Authenticates the CLI from `Authorization: Bearer fts_...`. */
export async function authenticateCli(req: FastifyRequest): Promise<CliAuth> {
  const header = req.headers.authorization ?? '';
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  const token = match?.[1];
  if (!token || !token.startsWith(TOKEN_PREFIX)) throw unauthorized('Missing or malformed Fortis key.', 'INVALID_KEY');
  const [row] = await db
    .select({
      tokenId: projectTokens.id,
      projectId: projects.id,
      projectName: projects.name,
      orgId: organizations.id,
      orgName: organizations.name,
      plan: organizations.plan,
    })
    .from(projectTokens)
    .innerJoin(projects, eq(projects.id, projectTokens.projectId))
    .innerJoin(organizations, eq(organizations.id, projectTokens.orgId))
    .where(and(eq(projectTokens.tokenHash, sha256(token)), isNull(projectTokens.revokedAt)))
    .limit(1);
  if (!row) throw unauthorized('This Fortis key is invalid or has been revoked.', 'INVALID_KEY');
  await db.update(projectTokens).set({ lastUsedAt: new Date() }).where(eq(projectTokens.id, row.tokenId));
  return row;
}
