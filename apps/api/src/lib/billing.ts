import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { and, desc, eq, inArray, like, lte, sql } from 'drizzle-orm';

import { PLANS, isPlanId, type PlanId } from '@fortis/shared';

import { env } from '../config/env';
import { db, type DbOrTx } from '../db/client';
import { auditLog, billingPayments, billingSubscriptions, memberships, organizations, users } from '../db/schema';
import { AppError, badRequest, conflict } from './errors';
import { open, seal } from './secret-box';

/*
 * Paying for a plan in naira through Paystack.
 *
 * - An owner picks Core or Plus and pays on Paystack's page by card, bank transfer, USSD or bank.
 *   The plan switches when Paystack confirms the payment, by webhook or when the owner comes back.
 * - Each month the saved card is charged (a cron calls runDueBilling). A workspace that paid by
 *   transfer gets a reminder and pays again.
 * - A failed renewal keeps the plan for BILLING_GRACE_DAYS, then the workspace steps down to Free.
 *   Findings and history stay; only the paid features switch off.
 * - Every payment, plan change and step down is in the audit log.
 */

export type PaidPlan = 'core' | 'plus';
export const SELF_SERVE: readonly PaidPlan[] = ['core', 'plus'];
const RANK: Record<PlanId, number> = { free: 0, core: 1, plus: 2, enterprise: 3 };
const MIN_CHARGE_KOBO = 100_00;
const DAY = 24 * 60 * 60 * 1000;
const REMIND_BEFORE_MS = 3 * DAY;

export const billingReady = () => Boolean(env.PAYSTACK_SECRET_KEY);

/* ---------------- money and dates ---------------- */

export function vatOn(baseKobo: number) {
  return Math.round((baseKobo * env.BILLING_VAT_PERCENT) / 100);
}

export function priceFor(plan: PaidPlan) {
  const base = PLANS[plan].monthlyPriceKobo ?? 0;
  const vat = vatOn(base);
  return { base, vat, total: base + vat };
}

/** One calendar month later; the 31st becomes the last day of a shorter month. */
export function addMonth(d: Date): Date {
  const out = new Date(d);
  const day = out.getUTCDate();
  out.setUTCDate(1);
  out.setUTCMonth(out.getUTCMonth() + 1);
  const last = new Date(Date.UTC(out.getUTCFullYear(), out.getUTCMonth() + 1, 0)).getUTCDate();
  out.setUTCDate(Math.min(day, last));
  return out;
}

/** What an upgrade costs now: the new plan's price, less the unused part of what was paid for the old one. */
export function upgradePrice(from: PaidPlan, to: PaidPlan, periodStart: Date, periodEnd: Date, now = new Date()) {
  const length = periodEnd.getTime() - periodStart.getTime();
  const left = Math.max(0, Math.min(length, periodEnd.getTime() - now.getTime()));
  const credit = length > 0 ? Math.round(((PLANS[from].monthlyPriceKobo ?? 0) * left) / length) : 0;
  const base = Math.max(MIN_CHARGE_KOBO, (PLANS[to].monthlyPriceKobo ?? 0) - credit);
  const vat = vatOn(base);
  return { base, vat, total: base + vat, credit };
}

export const naira = (kobo: number) => `₦${(kobo / 100).toLocaleString('en-NG', { minimumFractionDigits: kobo % 100 ? 2 : 0, maximumFractionDigits: 2 })}`;
const day = (d: Date) => d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Africa/Lagos' });

/* ---------------- Paystack ---------------- */

type Sender = typeof fetch;
let send: Sender = (...args) => fetch(...args);
/** Tests replace the network calls (Paystack and the email API). */
export function setBillingTransport(fn: Sender | null) {
  send = fn ?? ((...args) => fetch(...args));
}

export type PaystackAuthorization = {
  authorization_code?: string;
  reusable?: boolean;
  channel?: string;
  brand?: string;
  last4?: string;
  exp_month?: string;
  exp_year?: string;
};
export type PaystackTransaction = {
  id?: number;
  reference: string;
  status: string;
  amount: number;
  currency: string;
  channel?: string;
  gateway_response?: string;
  authorization?: PaystackAuthorization;
  customer?: { email?: string };
};

export class PaystackError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function paystack<T>(path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await send(`https://api.paystack.co${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new PaystackError(0, "Couldn't reach Paystack.");
  }
  const json = (await res.json().catch(() => null)) as { status?: boolean; message?: string; data?: T } | null;
  if (!json) throw new PaystackError(res.status, 'Paystack sent an unreadable response.');
  if (!res.ok || json.status === false) throw new PaystackError(res.status, json.message || `Paystack answered ${res.status}.`);
  return json.data as T;
}

const unavailable = () => new AppError(502, 'PAYSTACK_UNAVAILABLE', "Paystack didn't answer. Nothing was charged; try again in a minute.");

/** Paystack signs each webhook with HMAC-SHA512 of the raw body, keyed with the secret key. */
export function validWebhookSignature(rawBody: string, signature: string | undefined): boolean {
  if (!env.PAYSTACK_SECRET_KEY || !signature) return false;
  const expected = Buffer.from(createHmac('sha512', env.PAYSTACK_SECRET_KEY).update(rawBody).digest('hex'));
  const given = Buffer.from(signature);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

/* ---------------- records ---------------- */

async function log(tx: DbOrTx, orgId: string, action: string, meta: Record<string, unknown>, actorUserId: string | null = null, ip: string | null = null) {
  await tx.insert(auditLog).values({ orgId, actorUserId, action, targetType: 'organization', targetId: orgId, meta, ip });
}

export async function loadSubscription(orgId: string, tx: DbOrTx = db) {
  const [row] = await tx.select().from(billingSubscriptions).where(eq(billingSubscriptions.orgId, orgId)).limit(1);
  return row ?? null;
}

/** What Settings shows: the subscription without the card authorization, prices and recent payments. */
export async function presentBilling(orgId: string, plan: string) {
  const [sub, payments] = await Promise.all([
    loadSubscription(orgId),
    db
      .select({
        reference: billingPayments.reference,
        kind: billingPayments.kind,
        plan: billingPayments.plan,
        amountKobo: billingPayments.amountKobo,
        vatKobo: billingPayments.vatKobo,
        status: billingPayments.status,
        channel: billingPayments.channel,
        failureReason: billingPayments.failureReason,
        periodStart: billingPayments.periodStart,
        periodEnd: billingPayments.periodEnd,
        createdAt: billingPayments.createdAt,
        paidAt: billingPayments.paidAt,
        by: users.name,
      })
      .from(billingPayments)
      .leftJoin(users, eq(users.id, billingPayments.createdBy))
      .where(and(eq(billingPayments.orgId, orgId), sql`${billingPayments.status} <> 'pending' or ${billingPayments.createdAt} > now() - interval '1 day'`))
      .orderBy(desc(billingPayments.createdAt))
      .limit(24),
  ]);
  return {
    ready: billingReady(),
    plan,
    /** A paid plan with no subscription was set by Fortis (a design partner, Enterprise). */
    managed: plan !== 'free' && (!sub || sub.status === 'ended'),
    vatPercent: env.BILLING_VAT_PERCENT,
    graceDays: env.BILLING_GRACE_DAYS,
    prices: { core: priceFor('core'), plus: priceFor('plus') },
    subscription: sub
      ? {
          plan: sub.plan,
          status: sub.status,
          currentPeriodStart: sub.currentPeriodStart,
          currentPeriodEnd: sub.currentPeriodEnd,
          cancelAtPeriodEnd: sub.cancelAtPeriodEnd,
          nextPlan: sub.nextPlan,
          card: sub.authorization ? { brand: sub.cardBrand, last4: sub.cardLast4, exp: sub.cardExp } : null,
          billingEmail: sub.billingEmail,
          graceEndsAt: sub.graceEndsAt,
          upgradeQuotes:
            sub.status === 'active' && isPlanId(sub.plan) && sub.plan !== 'enterprise' && sub.plan !== 'free'
              ? Object.fromEntries(SELF_SERVE.filter((p) => RANK[p] > RANK[sub.plan as PlanId]).map((p) => [p, upgradePrice(sub.plan as PaidPlan, p, sub.currentPeriodStart, sub.currentPeriodEnd)]))
              : {},
        }
      : null,
    payments,
  };
}

/* ---------------- changing plan ---------------- */

export type ChangeResult =
  | { action: 'pay'; authorizationUrl: string; reference: string; amountKobo: number; kind: string }
  | { action: 'scheduled'; plan: string; effectiveAt: Date }
  | { action: 'resumed'; plan: string };

type Actor = { userId: string; email: string; ip: string | null };

async function startPayment(orgId: string, actor: Actor, plan: PaidPlan, kind: 'checkout' | 'upgrade' | 'renewal', price: { base: number; vat: number; total: number }, email: string): Promise<ChangeResult> {
  const reference = `fts-${randomBytes(10).toString('hex')}`;
  await db.insert(billingPayments).values({ orgId, reference, kind, plan, amountKobo: price.total, vatKobo: price.vat, createdBy: actor.userId });
  const settings = `${env.WEB_URL.replace(/\/+$/, '')}/settings`;
  let started: { authorization_url: string };
  try {
    started = await paystack<{ authorization_url: string }>('/transaction/initialize', {
      email,
      amount: String(price.total),
      currency: 'NGN',
      reference,
      callback_url: `${settings}?billing=return`,
      channels: ['card', 'bank_transfer', 'ussd', 'bank'],
      metadata: { org_id: orgId, plan, kind, cancel_action: settings },
    });
  } catch (e) {
    await db.update(billingPayments).set({ status: 'failed', failureReason: e instanceof Error ? e.message : 'Paystack error' }).where(eq(billingPayments.reference, reference));
    throw unavailable();
  }
  await log(db, orgId, 'billing.checkout_started', { reference, plan, kind, amountKobo: price.total }, actor.userId, actor.ip);
  return { action: 'pay', authorizationUrl: started.authorization_url, reference, amountKobo: price.total, kind };
}

/**
 * An owner chooses a plan. Paying starts a Paystack checkout; moving to a cheaper plan, or to Free,
 * happens at the end of the month already paid for; choosing the current plan again undoes that.
 */
export async function changePlan(org: { id: string; plan: string }, actor: Actor, target: string): Promise<ChangeResult> {
  if (!billingReady()) throw new AppError(503, 'BILLING_OFF', "Paying online isn't set up yet. Email hello@fortis.dev to change plan.");
  if (target === 'enterprise') throw badRequest('Enterprise is set up with our team. Email hello@fortis.dev and we will be in touch the same day.', 'ENTERPRISE_SALES');
  if (!isPlanId(target)) throw badRequest('Unknown plan.');
  const sub = await loadSubscription(org.id);
  const live = sub && (sub.status === 'active' || sub.status === 'past_due') ? sub : null;
  if (!live && org.plan !== 'free') throw conflict('Your plan was set up with Fortis directly. Email hello@fortis.dev to change it.', 'PLAN_MANAGED');

  if (target === 'free') {
    if (!live) throw conflict('This workspace is already on Fortis Free.', 'SAME_PLAN');
    if (live.cancelAtPeriodEnd) return { action: 'scheduled', plan: 'free', effectiveAt: live.currentPeriodEnd };
    await db.transaction(async (tx) => {
      await tx.update(billingSubscriptions).set({ cancelAtPeriodEnd: true, nextPlan: null, updatedAt: new Date() }).where(eq(billingSubscriptions.orgId, org.id));
      await log(tx, org.id, 'billing.canceled', { plan: live.plan, endsAt: live.currentPeriodEnd.toISOString() }, actor.userId, actor.ip);
    });
    return { action: 'scheduled', plan: 'free', effectiveAt: live.currentPeriodEnd };
  }

  const plan = target as PaidPlan;
  if (!live) return startPayment(org.id, actor, plan, 'checkout', priceFor(plan), actor.email);

  if (plan === live.plan) {
    if (live.cancelAtPeriodEnd || live.nextPlan) {
      await db.transaction(async (tx) => {
        await tx.update(billingSubscriptions).set({ cancelAtPeriodEnd: false, nextPlan: null, updatedAt: new Date() }).where(eq(billingSubscriptions.orgId, org.id));
        await log(tx, org.id, 'billing.resumed', { plan }, actor.userId, actor.ip);
      });
      return { action: 'resumed', plan };
    }
    if (live.status === 'past_due') return startPayment(org.id, actor, plan, 'renewal', priceFor(plan), live.billingEmail);
    throw conflict(`This workspace is already on ${PLANS[plan].name}.`, 'SAME_PLAN');
  }

  if (RANK[plan] < RANK[live.plan as PlanId]) {
    await db.transaction(async (tx) => {
      await tx.update(billingSubscriptions).set({ nextPlan: plan, cancelAtPeriodEnd: false, updatedAt: new Date() }).where(eq(billingSubscriptions.orgId, org.id));
      await log(tx, org.id, 'billing.downgrade_scheduled', { from: live.plan, to: plan, at: live.currentPeriodEnd.toISOString() }, actor.userId, actor.ip);
    });
    return { action: 'scheduled', plan, effectiveAt: live.currentPeriodEnd };
  }

  // Upgrade: credit for the unused part of a paid month; an unpaid month earns no credit.
  if (live.status === 'active' && (live.plan === 'core' || live.plan === 'plus')) {
    return startPayment(org.id, actor, plan, 'upgrade', upgradePrice(live.plan, plan, live.currentPeriodStart, live.currentPeriodEnd), live.billingEmail);
  }
  return startPayment(org.id, actor, plan, 'checkout', priceFor(plan), live.billingEmail);
}

/* ---------------- settling a payment ---------------- */

export type SettleResult = 'applied' | 'already' | 'pending' | 'failed' | 'unknown';

/**
 * Applies a payment Paystack reports (webhook, verify, or a renewal charge). Only references Fortis
 * created count, the amount and currency must match, and each payment is applied once.
 */
export async function settle(tx0: PaystackTransaction, source: 'webhook' | 'verify' | 'renewal'): Promise<SettleResult> {
  const [payment] = await db.select().from(billingPayments).where(eq(billingPayments.reference, tx0.reference)).limit(1);
  if (!payment) return 'unknown';
  if (payment.status === 'success') return 'already';

  if (tx0.status !== 'success') {
    if (['failed', 'abandoned', 'reversed'].includes(tx0.status)) {
      const status = tx0.status === 'abandoned' ? 'abandoned' : 'failed';
      await db.update(billingPayments).set({ status, failureReason: tx0.gateway_response ?? tx0.status }).where(and(eq(billingPayments.id, payment.id), eq(billingPayments.status, 'pending')));
      return 'failed';
    }
    return 'pending';
  }

  if (tx0.currency !== 'NGN' || Number(tx0.amount) !== payment.amountKobo) {
    await db.transaction(async (tx) => {
      await tx.update(billingPayments).set({ status: 'failed', failureReason: 'Amount or currency did not match' }).where(eq(billingPayments.id, payment.id));
      await log(tx, payment.orgId, 'billing.payment_mismatch', { reference: payment.reference, expected: payment.amountKobo, got: Number(tx0.amount), currency: tx0.currency, source });
    });
    return 'failed';
  }

  const applied = await db.transaction(async (tx) => {
    const now = new Date();
    const [claimed] = await tx
      .update(billingPayments)
      .set({ status: 'success', paidAt: now, channel: tx0.channel ?? null, failureReason: null })
      .where(and(eq(billingPayments.id, payment.id), inArray(billingPayments.status, ['pending', 'failed', 'abandoned'])))
      .returning({ id: billingPayments.id });
    if (!claimed) return null;

    const [org] = await tx.select({ plan: organizations.plan }).from(organizations).where(eq(organizations.id, payment.orgId)).for('update').limit(1);
    if (!org) return null;
    const sub = await loadSubscription(payment.orgId, tx);
    const start = payment.kind === 'renewal' && sub ? sub.currentPeriodEnd : now;
    const end = addMonth(start);
    const a = tx0.authorization;
    const card =
      a?.reusable && a.authorization_code && (a.channel ?? tx0.channel) === 'card'
        ? { authorization: seal(a.authorization_code), cardBrand: a.brand ?? null, cardLast4: a.last4 ?? null, cardExp: a.exp_month && a.exp_year ? `${a.exp_month}/${a.exp_year.slice(-2)}` : null }
        : {};
    const values = {
      plan: payment.plan,
      status: 'active',
      currentPeriodStart: start,
      currentPeriodEnd: end,
      cancelAtPeriodEnd: false,
      nextPlan: null,
      graceEndsAt: null,
      failedAttempts: 0,
      lastAttemptAt: null,
      reminderSentAt: null,
      updatedAt: now,
      ...card,
    };
    const billingEmail = sub?.billingEmail ?? tx0.customer?.email ?? '';
    await tx.insert(billingSubscriptions).values({ orgId: payment.orgId, billingEmail, ...values }).onConflictDoUpdate({ target: billingSubscriptions.orgId, set: values });
    await tx.update(billingPayments).set({ periodStart: start, periodEnd: end }).where(eq(billingPayments.id, payment.id));
    await tx.update(organizations).set({ plan: payment.plan }).where(eq(organizations.id, payment.orgId));
    await log(tx, payment.orgId, 'billing.payment_succeeded', { reference: payment.reference, plan: payment.plan, kind: payment.kind, amountKobo: payment.amountKobo, channel: tx0.channel ?? null, source }, source === 'renewal' ? null : payment.createdBy);
    if (org.plan !== payment.plan) await log(tx, payment.orgId, 'plan.changed', { from: org.plan, to: payment.plan, by: 'billing', reference: payment.reference });
    return { start, end };
  });
  if (!applied) return 'already';
  track(sendReceipt(payment.reference));
  return 'applied';
}

/** Asks Paystack about a payment (the owner came back from checkout) and applies it if it went through. */
export async function verifyPayment(reference: string): Promise<SettleResult> {
  let t: PaystackTransaction;
  try {
    t = await paystack<PaystackTransaction>(`/transaction/verify/${encodeURIComponent(reference)}`);
  } catch (e) {
    if (e instanceof PaystackError && e.status === 400) return 'pending';
    throw unavailable();
  }
  return settle(t, 'verify');
}

/* ---------------- renewals ---------------- */

type RunReport = { renewed: string[]; failed: string[]; reminded: string[]; ended: string[]; pending: string[] };

/** Called daily by a cron: reminders, renewals, retries and stepping down after the grace period. */
export async function runDueBilling(now = new Date()): Promise<RunReport> {
  const report: RunReport = { renewed: [], failed: [], reminded: [], ended: [], pending: [] };
  if (!billingReady()) return report;
  const due = await db
    .select()
    .from(billingSubscriptions)
    .where(and(inArray(billingSubscriptions.status, ['active', 'past_due']), lte(billingSubscriptions.currentPeriodEnd, new Date(now.getTime() + REMIND_BEFORE_MS))))
    .limit(200);

  for (const sub of due) {
    try {
      await runOne(sub, now, report);
    } catch (e) {
      report.failed.push(sub.orgId);
      console.error('billing run failed for', sub.orgId, e instanceof Error ? e.message : e);
    }
  }
  return report;
}

type Sub = typeof billingSubscriptions.$inferSelect;

async function runOne(sub: Sub, now: Date, report: RunReport) {
  const orgId = sub.orgId;

  // Not due yet: remind workspaces that pay by transfer.
  if (sub.currentPeriodEnd > now) {
    if (!sub.authorization && !sub.cancelAtPeriodEnd && !sub.reminderSentAt && sub.status === 'active') {
      const [claimed] = await db.update(billingSubscriptions).set({ reminderSentAt: now }).where(and(eq(billingSubscriptions.orgId, orgId), sql`${billingSubscriptions.reminderSentAt} is null`)).returning({ orgId: billingSubscriptions.orgId });
      if (claimed) {
        await notifyOwners(orgId, reminderEmail(sub.nextPlan ?? sub.plan, sub.currentPeriodEnd));
        report.reminded.push(orgId);
      }
    }
    return;
  }

  if (sub.cancelAtPeriodEnd) return stepDown(sub, 'canceled', report);
  if (sub.status === 'past_due' && sub.graceEndsAt && sub.graceEndsAt <= now) return stepDown(sub, 'unpaid', report);

  // A cheaper plan chosen for the next month starts now.
  let plan = sub.plan as PaidPlan;
  if (sub.nextPlan && (sub.nextPlan === 'core' || sub.nextPlan === 'plus')) {
    const from = sub.plan;
    plan = sub.nextPlan;
    await db.transaction(async (tx) => {
      await tx.update(billingSubscriptions).set({ plan, nextPlan: null, updatedAt: now }).where(eq(billingSubscriptions.orgId, orgId));
      await tx.update(organizations).set({ plan }).where(eq(organizations.id, orgId));
      await log(tx, orgId, 'plan.changed', { from, to: plan, by: 'billing', reason: 'scheduled' });
    });
  }

  // Due: the plan stays on through the grace period while we try to collect.
  let enteredGrace = false;
  if (sub.status === 'active') {
    const graceEndsAt = new Date(sub.currentPeriodEnd.getTime() + env.BILLING_GRACE_DAYS * DAY);
    const [moved] = await db
      .update(billingSubscriptions)
      .set({ status: 'past_due', graceEndsAt, updatedAt: now })
      .where(and(eq(billingSubscriptions.orgId, orgId), eq(billingSubscriptions.status, 'active')))
      .returning({ orgId: billingSubscriptions.orgId });
    enteredGrace = Boolean(moved);
    sub = { ...sub, status: 'past_due', graceEndsAt };
  }

  if (!sub.authorization) {
    if (enteredGrace) {
      await log(db, orgId, 'billing.past_due', { plan, graceEndsAt: sub.graceEndsAt?.toISOString(), reason: 'no saved card' });
      await notifyOwners(orgId, pastDueEmail(plan, sub.graceEndsAt!, null));
    }
    report.pending.push(orgId);
    return;
  }

  // One try a day. A charge still processing is checked first, so a card is never charged twice.
  if (sub.lastAttemptAt && now.getTime() - sub.lastAttemptAt.getTime() < 20 * 60 * 60 * 1000) return;
  const period = `fts-renew-${orgId.replace(/-/g, '').slice(0, 12)}-${Math.floor(sub.currentPeriodEnd.getTime() / 1000)}`;
  const [open_] = await db
    .select({ reference: billingPayments.reference })
    .from(billingPayments)
    .where(and(eq(billingPayments.orgId, orgId), eq(billingPayments.status, 'pending'), like(billingPayments.reference, `${period}-%`)))
    .limit(1);
  if (open_) {
    const r = await verifyPayment(open_.reference).catch(() => 'pending' as const);
    if (r === 'applied' || r === 'already') return void report.renewed.push(orgId);
    if (r === 'pending') return void report.pending.push(orgId);
  }

  const price = priceFor(plan);
  const reference = `${period}-${Math.floor(now.getTime() / DAY)}`;
  const [created] = await db.insert(billingPayments).values({ orgId, reference, kind: 'renewal', plan, amountKobo: price.total, vatKobo: price.vat }).onConflictDoNothing().returning({ id: billingPayments.id });
  if (!created) return;
  await db.update(billingSubscriptions).set({ lastAttemptAt: now }).where(eq(billingSubscriptions.orgId, orgId));

  let result: PaystackTransaction | null = null;
  let reason = 'The card was declined.';
  try {
    result = await paystack<PaystackTransaction>('/transaction/charge_authorization', {
      authorization_code: open(sub.authorization),
      email: sub.billingEmail,
      amount: String(price.total),
      currency: 'NGN',
      reference,
      metadata: { org_id: orgId, plan, kind: 'renewal' },
    });
  } catch (e) {
    reason = e instanceof PaystackError && e.status ? e.message : "Couldn't reach Paystack.";
    if (!(e instanceof PaystackError) || !e.status) {
      // Paystack may not have seen it: leave the payment pending and check it tomorrow.
      report.pending.push(orgId);
      return;
    }
  }

  if (result?.status === 'success') {
    const r = await settle(result, 'renewal');
    if (r === 'applied' || r === 'already') return void report.renewed.push(orgId);
  } else if (result && !['failed', 'reversed', 'abandoned'].includes(result.status)) {
    report.pending.push(orgId);
    return;
  }

  reason = result?.gateway_response || reason;
  await db.transaction(async (tx) => {
    await tx.update(billingPayments).set({ status: 'failed', failureReason: reason }).where(and(eq(billingPayments.reference, reference), eq(billingPayments.status, 'pending')));
    await tx.update(billingSubscriptions).set({ failedAttempts: sql`${billingSubscriptions.failedAttempts} + 1`, updatedAt: now }).where(eq(billingSubscriptions.orgId, orgId));
    await log(tx, orgId, 'billing.renewal_failed', { reference, plan, amountKobo: price.total, reason, attempt: sub.failedAttempts + 1 });
  });
  if (sub.failedAttempts === 0) await notifyOwners(orgId, pastDueEmail(plan, sub.graceEndsAt!, reason));
  report.failed.push(orgId);
}

async function stepDown(sub: Sub, reason: 'canceled' | 'unpaid', report: RunReport) {
  const done = await db.transaction(async (tx) => {
    const [moved] = await tx
      .update(billingSubscriptions)
      .set({ status: 'ended', cancelAtPeriodEnd: false, nextPlan: null, updatedAt: new Date() })
      .where(and(eq(billingSubscriptions.orgId, sub.orgId), inArray(billingSubscriptions.status, ['active', 'past_due'])))
      .returning({ orgId: billingSubscriptions.orgId });
    if (!moved) return false;
    const [org] = await tx.select({ plan: organizations.plan }).from(organizations).where(eq(organizations.id, sub.orgId)).limit(1);
    await tx.update(organizations).set({ plan: 'free' }).where(eq(organizations.id, sub.orgId));
    await log(tx, sub.orgId, 'billing.ended', { plan: sub.plan, reason });
    if (org && org.plan !== 'free') await log(tx, sub.orgId, 'plan.changed', { from: org.plan, to: 'free', by: 'billing', reason });
    return true;
  });
  if (!done) return;
  await notifyOwners(sub.orgId, endedEmail(sub.plan, reason));
  report.ended.push(sub.orgId);
}

/* ---------------- email ---------------- */

const pending = new Set<Promise<unknown>>();
function track(p: Promise<unknown>) {
  const q = p.catch((e) => console.error('billing email failed', e instanceof Error ? e.message : e)).finally(() => pending.delete(q));
  pending.add(q);
}
/** Emails still being sent, so tests can wait for them. */
export async function billingIdle() {
  while (pending.size) await Promise.allSettled([...pending]);
}

type Email = { subject: string; lines: string[] };
const settingsUrl = () => `${env.WEB_URL.replace(/\/+$/, '')}/settings#billing`;
const planName = (p: string) => (isPlanId(p) ? PLANS[p].name : p);

function reminderEmail(plan: string, at: Date): Email {
  return {
    subject: `Your ${planName(plan)} plan renews on ${day(at)}`,
    lines: [`Your ${planName(plan)} plan is paid up to ${day(at)}.`, `There's no card saved, so pay for the next month in Settings before then (card, transfer, USSD or bank): ${settingsUrl()}`],
  };
}
function pastDueEmail(plan: string, graceEndsAt: Date, reason: string | null): Email {
  return {
    subject: `We couldn't renew your ${planName(plan)} plan`,
    lines: [
      reason ? `We tried to charge your saved card and Paystack said: ${reason}` : `Your ${planName(plan)} month has ended and there's no card saved to renew it.`,
      `Your plan stays on until ${day(graceEndsAt)}. Pay in Settings before then to keep it: ${settingsUrl()}`,
      'After that the workspace moves to Fortis Free. Your findings and history are kept.',
    ],
  };
}
function endedEmail(plan: string, reason: 'canceled' | 'unpaid'): Email {
  return {
    subject: 'Your workspace is now on Fortis Free',
    lines: [
      reason === 'canceled' ? `Your ${planName(plan)} plan ended as you asked.` : `We couldn't collect payment for ${planName(plan)}, so the workspace has moved to Fortis Free.`,
      'Your findings, scans and history are all kept. Paid features are off until you choose a plan again.',
      `Choose a plan: ${settingsUrl()}`,
    ],
  };
}

async function ownerEmails(orgId: string): Promise<string[]> {
  const rows = await db.select({ email: users.email }).from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(and(eq(memberships.orgId, orgId), eq(memberships.role, 'owner')));
  return rows.map((r) => r.email);
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);

async function sendEmail(to: string[], email: Email) {
  if (!env.RESEND_API_KEY || !to.length) return false;
  const text = `${email.lines.join('\n\n')}\n\nFortis`;
  const html = `<div style="font-family:system-ui,sans-serif;font-size:15px;line-height:1.5;color:#0b1b33">${email.lines.map((l) => `<p>${esc(l)}</p>`).join('')}<p style="color:#5b6b85">Fortis</p></div>`;
  const res = await send('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({ from: env.ALERTS_FROM, to, subject: email.subject, text, html }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`Email API answered ${res.status}`);
  return true;
}

async function notifyOwners(orgId: string, email: Email) {
  track(ownerEmails(orgId).then((to) => sendEmail(to, email)));
}

/** The receipt for a payment, to the workspace's owners and the billing email. Sent once. */
async function sendReceipt(reference: string) {
  const [p] = await db.select().from(billingPayments).where(eq(billingPayments.reference, reference)).limit(1);
  if (!p || p.status !== 'success' || p.receiptSentAt) return;
  const [org] = await db.select({ name: organizations.name }).from(organizations).where(eq(organizations.id, p.orgId)).limit(1);
  const sub = await loadSubscription(p.orgId);
  const to = [...new Set([...(await ownerEmails(p.orgId)), ...(sub?.billingEmail ? [sub.billingEmail] : [])])];
  const lines = [
    `Thank you. Payment received for ${org?.name ?? 'your workspace'}.`,
    `${planName(p.plan)}${p.periodStart && p.periodEnd ? `, ${day(p.periodStart)} to ${day(p.periodEnd)}` : ''}`,
    `Amount: ${naira(p.amountKobo - p.vatKobo)}${p.vatKobo ? ` + VAT ${naira(p.vatKobo)} = ${naira(p.amountKobo)}` : ''}${p.channel ? ` (paid by ${p.channel.replace('_', ' ')})` : ''}`,
    `Reference: ${p.reference}. Every payment is listed in Settings: ${settingsUrl()}`,
  ];
  const sent = await sendEmail(to, { subject: `Fortis receipt: ${planName(p.plan)}, ${naira(p.amountKobo)}`, lines });
  if (sent) await db.update(billingPayments).set({ receiptSentAt: new Date() }).where(eq(billingPayments.id, p.id));
}
