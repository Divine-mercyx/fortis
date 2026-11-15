import { and, count, eq, gt, isNotNull, ne, sql } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { env } from '../config/env';
import { db } from '../db/client';
import { auditLog, memberships, organizations, sessions, ssoConnections, ssoIdentities, ssoLogins, users } from '../db/schema';
import { audit } from '../lib/audit';
import { randomBase62 } from '../lib/crypto';
import { AppError, badRequest, conflict, notFound, paymentRequired } from '../lib/errors';
import { hashPassword } from '../lib/password';
import { open, seal } from '../lib/secret-box';
import {
  authorizationUrl,
  discover,
  emailDomain,
  exchangeCode,
  hashValue,
  issuerFor,
  newFlowSecrets,
  SSO_PROVIDERS,
  ssoRedirectUri,
  verifiedEmail,
  verifyIdToken,
  type SsoProvider,
} from '../lib/sso';
import { parse } from '../lib/validate';
import { requireOrgRole, startSession } from '../plugins/auth';
import { listUserOrgs } from './auth.routes';
import { planLimits } from './orgs.routes';
import { VERIFY_RECORD_PREFIX, resolveTxtRecords } from './targets.routes';

const BINDER_COOKIE = 'fortis_sso';
const FLOW_MS = 10 * 60 * 1000;
const orgParams = z.object({ orgId: z.string().uuid() });
const domainRe = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

const settingsSchema = z.object({
  domain: z.string().trim().toLowerCase().regex(domainRe, 'Enter a domain like paywave.ng').optional(),
  provider: z.enum(SSO_PROVIDERS as [SsoProvider, ...SsoProvider[]]).optional(),
  /** Entra: tenant ID or issuer URL. Okta: the Okta domain. Other: the issuer URL. Google: ignored. */
  issuer: z.string().trim().max(300).optional(),
  clientId: z.string().trim().min(3).max(300).optional(),
  clientSecret: z.string().min(3).max(1000).optional(),
  defaultRole: z.enum(['viewer', 'developer']).optional(),
  enabled: z.boolean().optional(),
  enforced: z.boolean().optional(),
});
const startSchema = z.object({ email: z.string().trim().toLowerCase().email().max(254), next: z.string().max(300).optional() });
const callbackSchema = z.object({ code: z.string().min(1).max(4000), state: z.string().min(10).max(200) });

type Connection = typeof ssoConnections.$inferSelect;

function present(c: Connection | null, plan: string, members: number) {
  const available = planLimits(plan).sso;
  if (!c) return { available, connection: null, redirectUri: ssoRedirectUri() };
  return {
    available,
    redirectUri: ssoRedirectUri(),
    connection: {
      domain: c.domain,
      verified: Boolean(c.verifiedAt),
      verifiedAt: c.verifiedAt,
      record: { name: `${VERIFY_RECORD_PREFIX}.${c.domain}`, value: `fortis-verify=${c.verificationToken}` },
      provider: c.provider,
      issuer: c.issuer,
      clientId: c.clientId,
      hasSecret: Boolean(c.clientSecret),
      defaultRole: c.defaultRole,
      enabled: c.enabled,
      enforced: c.enforced,
      testedAt: c.testedAt,
      testedEmail: c.testedEmail,
      configured: Boolean(c.issuer && c.clientId && c.clientSecret),
      ssoMembers: members,
    },
  };
}

async function load(orgId: string) {
  const [c] = await db.select().from(ssoConnections).where(eq(ssoConnections.orgId, orgId)).limit(1);
  return c ?? null;
}
async function ssoMemberCount(orgId: string) {
  const [r] = await db.select({ n: count() }).from(ssoIdentities).where(eq(ssoIdentities.orgId, orgId));
  return r?.n ?? 0;
}

function requireSsoPlan(plan: string) {
  const limits = planLimits(plan);
  if (!limits.sso) throw paymentRequired(`${limits.name} doesn't include single sign-on. It comes with Fortis Plus and Enterprise.`, 'PLAN_SSO');
}

/** Ends password sessions of the workspace's people on the domain, when SSO becomes required. */
async function endPasswordSessions(orgId: string, domain: string, keepSessionId: string | null) {
  // The owner switching it on keeps their own session: they've just proven SSO works with a test.
  const res = await db.execute(sql`
    delete from ${sessions} s using ${memberships} m, ${users} u
    where m.org_id = ${orgId} and m.user_id = s.user_id and u.id = s.user_id
      and lower(u.email) like ${`%@${domain}`} and (s.sso_org_id is null or s.sso_org_id <> ${orgId})
      and s.id <> ${keepSessionId ?? '00000000-0000-0000-0000-000000000000'}`);
  return res.rowCount ?? 0;
}

async function startFlow(req: FastifyRequest, reply: import('fastify').FastifyReply, c: Connection, opts: { next?: string; testBy?: string; loginHint?: string }) {
  if (!c.issuer || !c.clientId || !c.clientSecret) throw badRequest('Finish setting up the identity provider first.', 'SSO_NOT_CONFIGURED');
  const doc = await discover(c.issuer);
  const s = newFlowSecrets();
  await db.delete(ssoLogins).where(sql`${ssoLogins.expiresAt} < now()`);
  await db.insert(ssoLogins).values({
    stateHash: hashValue(s.state),
    binderHash: hashValue(s.binder),
    orgId: c.orgId,
    nonce: s.nonce,
    codeVerifier: s.codeVerifier,
    next: opts.next && opts.next.startsWith('/') && !opts.next.startsWith('//') && !opts.next.startsWith('/\\') ? opts.next : null,
    testBy: opts.testBy ?? null,
    expiresAt: new Date(Date.now() + FLOW_MS),
  });
  reply.setCookie(BINDER_COOKIE, s.binder, { httpOnly: true, secure: env.cookieSecure, sameSite: 'lax', path: '/', maxAge: FLOW_MS / 1000 });
  return authorizationUrl(doc, { clientId: c.clientId, provider: c.provider, domain: c.domain }, s, opts.loginHint);
}

export async function ssoRoutes(app: FastifyInstance) {
  /* ---------------- settings (owners change, admins read) ---------------- */

  app.get('/v1/orgs/:orgId/sso', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'admin');
    return present(await load(orgId), org.plan, await ssoMemberCount(orgId));
  });

  app.put('/v1/orgs/:orgId/sso', { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } }, async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const input = parse(settingsSchema, req.body);
    const { org } = await requireOrgRole(req, orgId, 'owner');
    requireSsoPlan(org.plan);
    let c = await load(orgId);

    if (!c) {
      if (!input.domain) throw badRequest('Start with your email domain.', 'SSO_DOMAIN_REQUIRED');
      [c] = await db.insert(ssoConnections).values({ orgId, domain: input.domain, verificationToken: randomBase62(32) }).returning();
      await audit(db, req, { orgId, action: 'sso.created', targetType: 'organization', targetId: orgId, meta: { domain: input.domain } });
    }
    const conn = c!;
    const changes: Partial<Connection> = {};
    const changed: string[] = [];

    if (input.domain && input.domain !== conn.domain) {
      Object.assign(changes, { domain: input.domain, verifiedAt: null, verificationToken: randomBase62(32), enforced: false, testedAt: null, testedEmail: null });
      changed.push('domain');
    }
    const provider = input.provider ?? (conn.provider as SsoProvider);
    if (input.provider && input.provider !== conn.provider) {
      changes.provider = input.provider;
      changed.push('provider');
    }
    if (input.issuer !== undefined || (input.provider === 'google' && conn.issuer !== issuerFor('google', ''))) {
      const issuer = issuerFor(provider, input.issuer ?? '');
      if (!issuer) throw badRequest('Enter the issuer.', 'SSO_BAD_URL');
      if (issuer !== conn.issuer) {
        await discover(issuer); // must be a real, public OIDC provider
        changes.issuer = issuer;
        changed.push('issuer');
      }
    }
    if (input.clientId && input.clientId !== conn.clientId) {
      changes.clientId = input.clientId;
      changed.push('client ID');
    }
    if (input.clientSecret) {
      changes.clientSecret = seal(input.clientSecret);
      changed.push('client secret');
    }
    // New provider settings must be tested again before they can be required.
    if (changed.some((k) => k !== 'domain')) Object.assign(changes, { testedAt: null, testedEmail: null, enforced: false });
    if (input.defaultRole && input.defaultRole !== conn.defaultRole) {
      changes.defaultRole = input.defaultRole;
      changed.push('default role');
    }
    if (input.enabled !== undefined && input.enabled !== conn.enabled) {
      changes.enabled = input.enabled;
      if (!input.enabled) changes.enforced = false;
      changed.push(input.enabled ? 'switched on' : 'switched off');
    }

    const next = { ...conn, ...changes };
    let endedSessions = 0;
    if (input.enforced !== undefined && input.enforced !== next.enforced) {
      if (input.enforced) {
        if (!next.verifiedAt) throw badRequest(`Verify ${next.domain} first.`, 'SSO_UNVERIFIED');
        if (!next.enabled) throw badRequest('Switch single sign-on on first.', 'SSO_OFF');
        if (!next.testedAt) throw badRequest('Run a test sign-in first, so nobody gets locked out.', 'SSO_UNTESTED');
      }
      changes.enforced = input.enforced;
      changed.push(input.enforced ? 'required' : 'no longer required');
    }
    if (input.enabled === true && !(next.issuer && next.clientId && next.clientSecret)) throw badRequest('Add the provider, client ID and client secret first.', 'SSO_NOT_CONFIGURED');

    if (Object.keys(changes).length) {
      await db.update(ssoConnections).set({ ...changes, updatedAt: new Date() }).where(eq(ssoConnections.orgId, orgId));
      await audit(db, req, { orgId, action: 'sso.updated', targetType: 'organization', targetId: orgId, meta: { changed } });
      if (changes.enforced === true) endedSessions = await endPasswordSessions(orgId, next.domain, req.sessionId);
    }
    return { ...present(await load(orgId), org.plan, await ssoMemberCount(orgId)), endedSessions };
  });

  /** Checks the DNS TXT record that proves the workspace owns the domain. */
  app.post('/v1/orgs/:orgId/sso/verify', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'owner');
    requireSsoPlan(org.plan);
    const c = await load(orgId);
    if (!c) throw notFound('Set up single sign-on first.');
    if (c.verifiedAt) return { verified: true, ...present(c, org.plan, await ssoMemberCount(orgId)) };
    const [taken] = await db.select({ orgId: ssoConnections.orgId }).from(ssoConnections).where(and(eq(ssoConnections.domain, c.domain), isNotNull(ssoConnections.verifiedAt), ne(ssoConnections.orgId, orgId))).limit(1);
    if (taken) throw conflict(`${c.domain} is already verified by another Fortis workspace. Email hello@fortis.dev if that's wrong.`, 'SSO_DOMAIN_TAKEN');
    const name = `${VERIFY_RECORD_PREFIX}.${c.domain}`;
    const expected = `fortis-verify=${c.verificationToken}`;
    const { records, error } = await resolveTxtRecords(name);
    if (!records.some((r) => r.trim() === expected)) {
      return { verified: false, error: error ?? (records.length ? `Found a TXT record at ${name}, but it doesn't match. Set it to exactly: ${expected}` : `No TXT record found at ${name} yet. DNS changes can take a few minutes to appear.`), ...present(c, org.plan, await ssoMemberCount(orgId)) };
    }
    await db.update(ssoConnections).set({ verifiedAt: new Date(), updatedAt: new Date() }).where(eq(ssoConnections.orgId, orgId));
    await audit(db, req, { orgId, action: 'sso.domain_verified', targetType: 'organization', targetId: orgId, meta: { domain: c.domain } });
    return { verified: true, ...present(await load(orgId), org.plan, await ssoMemberCount(orgId)) };
  });

  /** A test sign-in: proves the settings work before anyone depends on them. Signs nobody in. */
  app.post('/v1/orgs/:orgId/sso/test', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { orgId } = parse(orgParams, req.params);
    const { org, user } = await requireOrgRole(req, orgId, 'owner');
    requireSsoPlan(org.plan);
    const c = await load(orgId);
    if (!c) throw notFound('Set up single sign-on first.');
    return { authorizationUrl: await startFlow(req, reply, c, { testBy: user.id, next: '/settings#sso' }) };
  });

  app.delete('/v1/orgs/:orgId/sso', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'owner');
    const c = await load(orgId);
    if (!c) return { ok: true };
    await db.delete(ssoConnections).where(eq(ssoConnections.orgId, orgId));
    await audit(db, req, { orgId, action: 'sso.removed', targetType: 'organization', targetId: orgId, meta: { domain: c.domain } });
    return { ok: true };
  });

  /* ---------------- signing in ---------------- */

  /** From the login page: which provider covers this email, and where to send the browser. */
  app.post('/v1/auth/sso/start', { config: { rateLimit: { max: env.AUTH_RATE_LIMIT_PER_MIN, timeWindow: '1 minute' } } }, async (req, reply) => {
    const input = parse(startSchema, req.body);
    const domain = emailDomain(input.email);
    const [c] = await db
      .select()
      .from(ssoConnections)
      .where(and(eq(ssoConnections.domain, domain), isNotNull(ssoConnections.verifiedAt), eq(ssoConnections.enabled, true)))
      .limit(1);
    if (!c) throw notFound(`Single sign-on isn't set up for ${domain}. Sign in with your password, or ask your Fortis owner.`, 'SSO_NOT_FOUND');
    return { authorizationUrl: await startFlow(req, reply, c, { next: input.next, loginHint: input.email }) };
  });

  /** The dashboard's /login/sso page posts what the provider sent back. */
  app.post('/v1/auth/sso/callback', { config: { rateLimit: { max: env.AUTH_RATE_LIMIT_PER_MIN * 2, timeWindow: '1 minute' } } }, async (req, reply) => {
    const input = parse(callbackSchema, req.body);
    const binder = req.cookies[BINDER_COOKIE];
    reply.clearCookie(BINDER_COOKIE, { path: '/' });
    // One use: the flow row goes whatever happens next.
    const [flow] = await db
      .delete(ssoLogins)
      .where(and(eq(ssoLogins.stateHash, hashValue(input.state)), gt(ssoLogins.expiresAt, new Date())))
      .returning();
    if (!flow) throw new AppError(400, 'SSO_EXPIRED', 'This sign-in expired or was already used. Start again.');
    if (!binder || hashValue(binder) !== flow.binderHash) throw new AppError(400, 'SSO_WRONG_BROWSER', 'Finish signing in in the same browser you started in.');

    const c = await load(flow.orgId);
    if (!c?.issuer || !c.clientId || !c.clientSecret) throw new AppError(400, 'SSO_NOT_CONFIGURED', "Single sign-on isn't set up for this workspace any more.");
    const doc = await discover(c.issuer);
    const idToken = await exchangeCode(doc, { clientId: c.clientId, clientSecret: open(c.clientSecret) }, input.code, flow.codeVerifier);
    const claims = await verifyIdToken(idToken, doc, { issuer: c.issuer, clientId: c.clientId, nonce: flow.nonce });

    const record = async (action: string, meta: Record<string, unknown>, actor: string | null) =>
      db.insert(auditLog).values({ orgId: c.orgId, actorUserId: actor, action, targetType: 'organization', targetId: c.orgId, meta, ip: req.ip });

    if (flow.testBy) {
      let email: string;
      try {
        email = verifiedEmail(claims, c);
      } catch (e) {
        await record('sso.test_failed', { reason: e instanceof AppError ? e.code : 'ERROR' }, flow.testBy);
        throw e;
      }
      await db.update(ssoConnections).set({ testedAt: new Date(), testedEmail: email, updatedAt: new Date() }).where(eq(ssoConnections.orgId, c.orgId));
      await record('sso.tested', { email }, flow.testBy);
      return { test: true, email, next: flow.next ?? '/settings#sso' };
    }

    if (!c.verifiedAt || !c.enabled) throw new AppError(403, 'SSO_OFF', 'Single sign-on is switched off for this workspace.');
    const email = verifiedEmail(claims, c);

    const result = await db.transaction(async (tx) => {
      // The provider's subject is the stable identity; the email links it the first time.
      const [known] = await tx.select({ userId: ssoIdentities.userId }).from(ssoIdentities).where(and(eq(ssoIdentities.orgId, c.orgId), eq(ssoIdentities.subject, claims.sub))).limit(1);
      let userId = known?.userId;
      let created = false;
      if (!userId) {
        const [byEmail] = await tx.select({ id: users.id }).from(users).where(sql`lower(${users.email}) = ${email}`).limit(1);
        if (byEmail) userId = byEmail.id;
        else {
          const name = (claims.name ?? email.split('@')[0]!).slice(0, 120);
          // No password: this person signs in through the provider.
          const [u] = await tx.insert(users).values({ email, name: name.length >= 2 ? name : email, passwordHash: await hashPassword(randomBase62(48)), emailVerifiedAt: new Date() }).returning({ id: users.id });
          userId = u!.id;
          created = true;
        }
        await tx.insert(ssoIdentities).values({ orgId: c.orgId, subject: claims.sub, userId, email }).onConflictDoNothing();
      } else {
        await tx.update(ssoIdentities).set({ lastLoginAt: new Date(), email }).where(and(eq(ssoIdentities.orgId, c.orgId), eq(ssoIdentities.subject, claims.sub)));
      }

      const [member] = await tx.select({ role: memberships.role }).from(memberships).where(and(eq(memberships.orgId, c.orgId), eq(memberships.userId, userId))).limit(1);
      let joined = false;
      if (!member) {
        const [org] = await tx.select({ plan: organizations.plan }).from(organizations).where(eq(organizations.id, c.orgId)).limit(1);
        const limits = planLimits(org?.plan ?? 'free');
        const [seats] = await tx.select({ n: count() }).from(memberships).where(eq(memberships.orgId, c.orgId));
        if (limits.maxSeats !== null && (seats?.n ?? 0) >= limits.maxSeats) {
          throw new AppError(402, 'SEATS_FULL', `Your workspace has used all ${limits.maxSeats} seats. Ask an owner to free one or upgrade.`);
        }
        await tx.insert(memberships).values({ orgId: c.orgId, userId, role: c.defaultRole === 'viewer' ? 'viewer' : 'developer' });
        joined = true;
      }
      return { userId, created, joined };
    });

    await record(result.joined ? 'member.joined_sso' : 'sso.login', { email, role: result.joined ? c.defaultRole : undefined, newAccount: result.created || undefined }, result.userId);
    await startSession(req, reply, result.userId, { ssoOrgId: c.orgId });
    const [user] = await db.select({ id: users.id, email: users.email, name: users.name, twoFactorEnabledAt: users.twoFactorEnabledAt }).from(users).where(eq(users.id, result.userId)).limit(1);
    return {
      user: { id: user!.id, email: user!.email, name: user!.name, twoFactorEnabled: Boolean(user!.twoFactorEnabledAt) },
      orgs: await listUserOrgs(result.userId),
      orgId: c.orgId,
      next: flow.next ?? '/overview',
    };
  });

}

/** When an admin removes someone, their sessions from this workspace's sign-on end too. */
export async function endSsoSessions(orgId: string, userId: string) {
  await db.delete(sessions).where(and(eq(sessions.userId, userId), eq(sessions.ssoOrgId, orgId)));
  await db.delete(ssoIdentities).where(and(eq(ssoIdentities.orgId, orgId), eq(ssoIdentities.userId, userId)));
}

