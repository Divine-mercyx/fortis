import { timingSafeEqual } from 'node:crypto';

import { and, eq } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { env } from '../config/env';
import { db } from '../db/client';
import { billingEvents, billingPayments, organizations } from '../db/schema';
import { changePlan, presentBilling, runDueBilling, settle, validWebhookSignature, verifyPayment, type PaystackTransaction } from '../lib/billing';
import { notFound } from '../lib/errors';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';

const orgParams = z.object({ orgId: z.string().uuid() });
const changeBody = z.object({ plan: z.enum(['free', 'core', 'plus', 'enterprise']) });
const verifyBody = z.object({ reference: z.string().regex(/^[\w.=-]{6,100}$/) });

async function currentPlan(orgId: string) {
  const [row] = await db.select({ plan: organizations.plan }).from(organizations).where(eq(organizations.id, orgId)).limit(1);
  return row?.plan ?? 'free';
}

function cronAllowed(req: FastifyRequest): boolean {
  const secret = env.CRON_SECRET;
  const given = req.headers['x-fortis-cron'];
  if (!secret || typeof given !== 'string') return false;
  const a = Buffer.from(given);
  const b = Buffer.from(secret);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function billingRoutes(app: FastifyInstance) {
  /** Plan, renewal date, saved card (brand and last four only), prices and recent payments. Admins and owners. */
  app.get('/v1/orgs/:orgId/billing', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const { org } = await requireOrgRole(req, orgId, 'admin');
    return presentBilling(orgId, org.plan);
  });

  /** Owners choose a plan: pay for it, move to a cheaper one or Free at renewal, or undo that. */
  app.post('/v1/orgs/:orgId/billing/change', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const { plan } = parse(changeBody, req.body);
    const { org, user } = await requireOrgRole(req, orgId, 'owner');
    const result = await changePlan(org, { userId: user.id, email: user.email, ip: req.ip }, plan);
    return { ...result, billing: result.action === 'pay' ? undefined : await presentBilling(orgId, await currentPlan(orgId)) };
  });

  /** After Paystack's page sends the owner back: checks the payment and applies it if it went through. */
  app.post('/v1/orgs/:orgId/billing/verify', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const { reference } = parse(verifyBody, req.body);
    await requireOrgRole(req, orgId, 'admin');
    const [payment] = await db.select({ status: billingPayments.status }).from(billingPayments).where(and(eq(billingPayments.reference, reference), eq(billingPayments.orgId, orgId))).limit(1);
    if (!payment) throw notFound('Payment not found.');
    const result = payment.status === 'success' ? 'already' : await verifyPayment(reference);
    const status = result === 'applied' || result === 'already' ? 'success' : result === 'failed' ? 'failed' : 'pending';
    return { status, billing: await presentBilling(orgId, await currentPlan(orgId)) };
  });

  /**
   * Paystack's webhook. The signature is checked against the raw body, each event is handled once,
   * and only payments Fortis started change a plan. Always answers quickly so Paystack doesn't retry.
   */
  await app.register(async (hook) => {
    hook.removeContentTypeParser('application/json');
    hook.addContentTypeParser('application/json', { parseAs: 'string', bodyLimit: 64 * 1024 }, (_req, body, done) => done(null, body));

    hook.post('/v1/billing/paystack/webhook', { config: { rateLimit: { max: 600, timeWindow: '1 minute' } } }, async (req, reply) => {
      const raw = typeof req.body === 'string' ? req.body : '';
      const signature = req.headers['x-paystack-signature'];
      if (!validWebhookSignature(raw, typeof signature === 'string' ? signature : undefined)) {
        return reply.code(401).send({ error: { code: 'BAD_SIGNATURE', message: 'Signature mismatch.' } });
      }
      let event: { event?: string; data?: PaystackTransaction & { id?: number } };
      try {
        event = JSON.parse(raw);
      } catch {
        return reply.code(400).send({ error: { code: 'BAD_REQUEST', message: 'Unreadable body.' } });
      }
      const type = event.event ?? 'unknown';
      const data = event.data;
      if (type !== 'charge.success' || !data?.reference) return { ok: true, ignored: type };

      const key = `${type}:${data.id ?? data.reference}`;
      const [fresh] = await db.insert(billingEvents).values({ eventKey: key, type, reference: data.reference }).onConflictDoNothing().returning({ id: billingEvents.id });
      if (!fresh) return { ok: true, duplicate: true };
      try {
        const result = await settle(data, 'webhook');
        return { ok: true, result };
      } catch (e) {
        // Let Paystack retry: forget the event so the retry is handled.
        await db.delete(billingEvents).where(eq(billingEvents.id, fresh.id));
        throw e;
      }
    });
  });

  /** Daily, from a cron with the shared CRON_SECRET: reminders, renewals, retries and stepping down. */
  app.post('/v1/internal/billing/run-due', { config: { rateLimit: { max: 30, timeWindow: '1 hour' } } }, async (req, reply) => {
    if (!cronAllowed(req)) return reply.code(env.CRON_SECRET ? 401 : 404).send({ error: { code: 'UNAUTHORIZED', message: 'Not allowed.' } });
    return runDueBilling();
  });
}
