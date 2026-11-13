import { and, eq, gt, isNull, lt, sql } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomInt } from 'node:crypto';

import { loginTwoFactorSchema, twoFactorConfirmSchema, twoFactorDisableSchema } from '@fortis/shared';

import { env } from '../config/env';
import { db, type DbOrTx } from '../db/client';
import { loginChallenges, memberships, recoveryCodes, sessions, users } from '../db/schema';
import { audit } from '../lib/audit';
import { randomBase62, sha256 } from '../lib/crypto';
import { badRequest, conflict, unauthorized } from '../lib/errors';
import { verifyPassword } from '../lib/password';
import { open, seal } from '../lib/secret-box';
import { newTotpSecret, otpauthUrl, verifyTotp } from '../lib/totp';
import { parse } from '../lib/validate';
import { requireUser, startSession } from '../plugins/auth';
import { listUserOrgs } from './auth.routes';

/*
 * Two-factor sign-in with an authenticator app (Google Authenticator, 1Password, Authy, Microsoft
 * Authenticator). Once it's on, the right password only earns a challenge; the session cookie comes
 * after a six-digit code from the app, or one of ten single-use recovery codes.
 */

const CHALLENGE_MINUTES = 5;
const CHALLENGE_TRIES = 5;
const RECOVERY_CODES = 10;
const authRateLimit = { rateLimit: { max: env.AUTH_RATE_LIMIT_PER_MIN, timeWindow: '1 minute' } };

/** A recovery code: eight characters from an alphabet without look-alikes, shown as xxxx-xxxx. */
const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
function newRecoveryCode(): string {
  const raw = Array.from({ length: 8 }, () => RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)]).join('');
  return `${raw.slice(0, 4)}-${raw.slice(4)}`;
}
const normaliseRecovery = (code: string) => code.toLowerCase().replace(/[^a-z0-9]/g, '');
const hashRecovery = (code: string) => sha256(`fortis-recovery:${normaliseRecovery(code)}`);
const looksLikeTotp = (code: string) => /^\d{6}$/.test(code.replace(/\s/g, ''));

async function issueRecoveryCodes(tx: DbOrTx, userId: string): Promise<string[]> {
  const codes = Array.from({ length: RECOVERY_CODES }, newRecoveryCode);
  await tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
  await tx.insert(recoveryCodes).values(codes.map((c) => ({ userId, codeHash: hashRecovery(c) })));
  return codes;
}

/** Writes one audit entry in each workspace the user belongs to, so their admins see it. */
async function auditForUser(tx: DbOrTx, req: FastifyRequest, userId: string, action: string, meta?: Record<string, unknown>) {
  const orgs = await tx.select({ orgId: memberships.orgId }).from(memberships).where(eq(memberships.userId, userId));
  for (const { orgId } of orgs) await audit(tx, req, { orgId, action, targetType: 'user', targetId: userId, ...(meta ? { meta } : {}) });
}

type TwoFactorUser = { id: string; twoFactorSecret: string | null; twoFactorLastStep: number | null };

/**
 * Checks an authenticator code or an unused recovery code for a user with 2FA on, and records its use.
 * Returns how it was proven, or null. Runs inside the caller's transaction.
 */
async function checkSecondFactor(tx: DbOrTx, user: TwoFactorUser, code: string): Promise<'totp' | 'recovery' | null> {
  if (!user.twoFactorSecret) return null;
  if (looksLikeTotp(code)) {
    const step = verifyTotp(open(user.twoFactorSecret), code, Date.now(), user.twoFactorLastStep);
    if (step === null) return null;
    // Only move forward: of two requests with the same code, one wins.
    const moved = await tx
      .update(users)
      .set({ twoFactorLastStep: step })
      .where(and(eq(users.id, user.id), sql`coalesce(${users.twoFactorLastStep}, -1) < ${step}`))
      .returning({ id: users.id });
    return moved.length ? 'totp' : null;
  }
  const used = await tx
    .update(recoveryCodes)
    .set({ usedAt: new Date() })
    .where(and(eq(recoveryCodes.userId, user.id), eq(recoveryCodes.codeHash, hashRecovery(code)), isNull(recoveryCodes.usedAt)))
    .returning({ id: recoveryCodes.id });
  return used.length ? 'recovery' : null;
}

/** Called by the password step of /v1/auth/login when 2FA is on: a challenge instead of a session. */
export async function startLoginChallenge(userId: string): Promise<string> {
  const token = randomBase62(43);
  await db.delete(loginChallenges).where(lt(loginChallenges.expiresAt, new Date()));
  await db.insert(loginChallenges).values({ userId, tokenHash: sha256(token), expiresAt: new Date(Date.now() + CHALLENGE_MINUTES * 60_000) });
  return token;
}

async function loadUser(userId: string) {
  const [user] = await db
    .select({
      id: users.id,
      email: users.email,
      name: users.name,
      passwordHash: users.passwordHash,
      twoFactorSecret: users.twoFactorSecret,
      twoFactorPendingSecret: users.twoFactorPendingSecret,
      twoFactorEnabledAt: users.twoFactorEnabledAt,
      twoFactorLastStep: users.twoFactorLastStep,
    })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);
  if (!user) throw unauthorized();
  return user;
}

const invalidCode = () => unauthorized('That code is not right. Check the time on your phone, then use the newest code in your authenticator app.', 'INVALID_CODE');

export async function twoFactorRoutes(app: FastifyInstance) {
  /* ---------- Signing in ---------- */

  app.post('/v1/auth/login/2fa', { config: authRateLimit }, async (req, reply) => {
    const input = parse(loginTwoFactorSchema, req.body);
    const [challenge] = await db
      .select()
      .from(loginChallenges)
      .where(and(eq(loginChallenges.tokenHash, sha256(input.challenge)), gt(loginChallenges.expiresAt, new Date())))
      .limit(1);
    if (!challenge || challenge.attempts >= CHALLENGE_TRIES) {
      throw unauthorized('This sign-in has expired. Enter your email and password again.', 'CHALLENGE_EXPIRED');
    }
    const user = await loadUser(challenge.userId);
    const how = await db.transaction(async (tx) => {
      const proven = await checkSecondFactor(tx, user, input.code);
      if (!proven) return null;
      await tx.delete(loginChallenges).where(eq(loginChallenges.id, challenge.id));
      req.user = { id: user.id, email: user.email, name: user.name };
      if (proven === 'recovery') await auditForUser(tx, req, user.id, 'user.recovery_code_used');
      return proven;
    });
    if (!how) {
      const [row] = await db
        .update(loginChallenges)
        .set({ attempts: sql`${loginChallenges.attempts} + 1` })
        .where(eq(loginChallenges.id, challenge.id))
        .returning({ attempts: loginChallenges.attempts });
      if ((row?.attempts ?? CHALLENGE_TRIES) >= CHALLENGE_TRIES) {
        await db.delete(loginChallenges).where(eq(loginChallenges.id, challenge.id));
        throw unauthorized('Too many wrong codes. Enter your email and password again.', 'CHALLENGE_EXPIRED');
      }
      throw invalidCode();
    }
    await startSession(req, reply, user.id);
    const left = how === 'recovery' ? await recoveryCodesLeft(user.id) : undefined;
    return {
      user: { id: user.id, email: user.email, name: user.name, twoFactorEnabled: true },
      orgs: await listUserOrgs(user.id),
      ...(left !== undefined ? { recoveryCodesLeft: left } : {}),
    };
  });

  /* ---------- Settings ---------- */

  app.get('/v1/auth/2fa', async (req) => {
    const me = requireUser(req);
    const user = await loadUser(me.id);
    return {
      enabled: Boolean(user.twoFactorEnabledAt),
      enabledAt: user.twoFactorEnabledAt,
      recoveryCodesLeft: user.twoFactorEnabledAt ? await recoveryCodesLeft(user.id) : 0,
    };
  });

  /**
   * Starts setup: a secret to scan. Nothing changes for sign-in until a code confirms it. Asking again
   * before confirming gives the same secret, so two tabs, a double click or a page that loads twice
   * never leave the QR code on screen out of step with the one stored.
   */
  app.post('/v1/auth/2fa/setup', { config: authRateLimit }, async (req) => {
    const me = requireUser(req);
    const user = await loadUser(me.id);
    if (user.twoFactorEnabledAt) throw conflict('Two-factor authentication is already on.', 'TWO_FACTOR_ON');
    const fresh = newTotpSecret();
    // Only the first request stores its secret; any other reads that one back.
    const stored = await db
      .update(users)
      .set({ twoFactorPendingSecret: seal(fresh) })
      .where(and(eq(users.id, user.id), isNull(users.twoFactorPendingSecret)))
      .returning({ id: users.id });
    const secret = stored.length ? fresh : open((await loadUser(user.id)).twoFactorPendingSecret!);
    return { secret, otpauthUrl: otpauthUrl(secret, user.email) };
  });

  /** Confirms setup with a code from the app; turns 2FA on and returns recovery codes, shown once. */
  app.post('/v1/auth/2fa/enable', { config: authRateLimit }, async (req) => {
    const me = requireUser(req);
    const input = parse(twoFactorConfirmSchema, req.body);
    const user = await loadUser(me.id);
    if (user.twoFactorEnabledAt) throw conflict('Two-factor authentication is already on.', 'TWO_FACTOR_ON');
    if (!user.twoFactorPendingSecret) throw badRequest('Start the setup again: scan a new QR code first.', 'NO_SETUP');
    const step = verifyTotp(open(user.twoFactorPendingSecret), input.code);
    if (step === null) throw invalidCode();
    const codes = await db.transaction(async (tx) => {
      await tx
        .update(users)
        .set({ twoFactorSecret: user.twoFactorPendingSecret, twoFactorPendingSecret: null, twoFactorEnabledAt: new Date(), twoFactorLastStep: step })
        .where(eq(users.id, user.id));
      const issued = await issueRecoveryCodes(tx, user.id);
      // Other signed-in browsers got in with the password alone; they sign in again with a code.
      if (req.sessionId) await tx.delete(sessions).where(and(eq(sessions.userId, user.id), sql`${sessions.id} <> ${req.sessionId}`));
      await auditForUser(tx, req, user.id, 'user.two_factor_enabled');
      return issued;
    });
    return { enabled: true, recoveryCodes: codes };
  });

  /** New recovery codes, which replace the old ones. Needs a current code. */
  app.post('/v1/auth/2fa/recovery-codes', { config: authRateLimit }, async (req) => {
    const me = requireUser(req);
    const input = parse(twoFactorConfirmSchema, req.body);
    const user = await loadUser(me.id);
    if (!user.twoFactorEnabledAt) throw badRequest('Turn on two-factor authentication first.', 'TWO_FACTOR_OFF');
    const codes = await db.transaction(async (tx) => {
      if (!(await checkSecondFactor(tx, user, input.code))) throw invalidCode();
      const issued = await issueRecoveryCodes(tx, user.id);
      await auditForUser(tx, req, user.id, 'user.recovery_codes_replaced');
      return issued;
    });
    return { recoveryCodes: codes };
  });

  /** Turns 2FA off. Needs the password and a current code (or a recovery code). */
  app.post('/v1/auth/2fa/disable', { config: authRateLimit }, async (req) => {
    const me = requireUser(req);
    const input = parse(twoFactorDisableSchema, req.body);
    const user = await loadUser(me.id);
    if (!user.twoFactorEnabledAt) return { enabled: false };
    if (!(await verifyPassword(user.passwordHash, input.password))) throw unauthorized('Your password is not right.', 'INVALID_CREDENTIALS');
    await db.transaction(async (tx) => {
      if (!(await checkSecondFactor(tx, user, input.code))) throw invalidCode();
      await tx
        .update(users)
        .set({ twoFactorSecret: null, twoFactorPendingSecret: null, twoFactorEnabledAt: null, twoFactorLastStep: null })
        .where(eq(users.id, user.id));
      await tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, user.id));
      await auditForUser(tx, req, user.id, 'user.two_factor_disabled');
    });
    return { enabled: false };
  });
}

async function recoveryCodesLeft(userId: string): Promise<number> {
  const [row] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(recoveryCodes)
    .where(and(eq(recoveryCodes.userId, userId), isNull(recoveryCodes.usedAt)));
  return row?.n ?? 0;
}

