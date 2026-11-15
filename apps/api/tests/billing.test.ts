import { createHmac } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { env } from '../src/config/env';
import { pool } from '../src/db/client';
import { addMonth, billingIdle, runDueBilling, setBillingTransport, upgradePrice } from '../src/lib/billing';
import { projectWithKey, resetDb, scanPayload, setPlan, setupApp, signup, type Client } from './helpers';

/*
 * Billing against a fake Paystack. Each test decides what Paystack answers; the webhook is signed the
 * way Paystack signs it. scripts/billing-e2e (run by hand) does the same against Paystack's test mode.
 */

let app: FastifyInstance;
type Call = { url: string; body: any };
let calls: Call[] = [];
/** Paystack's answer to charge_authorization and verify, by reference. */
let charge: (ref: string, body: any) => { status: number; json: any };
let verify: (ref: string) => { status: number; json: any };

const SECRET = 'sk_test_fortis_billing_tests';
const CORE = 450_000_00 + 33_750_00;
const PLUS = 750_000_00 + 56_250_00;
const DAY = 86_400_000;

const card = { authorization_code: 'AUTH_test123', reusable: true, channel: 'card', brand: 'visa', last4: '4081', exp_month: '12', exp_year: '2030' };
const paid = (reference: string, amount: number, extra: Record<string, unknown> = {}) => ({
  id: Math.floor(Math.random() * 1e9),
  reference,
  status: 'success',
  amount,
  currency: 'NGN',
  channel: 'card',
  gateway_response: 'Successful',
  authorization: card,
  customer: { email: 'ada@paywave.ng' },
  ...extra,
});

beforeAll(async () => {
  app = await setupApp();
  setBillingTransport(async (url, init) => {
    const u = String(url);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ url: u, body });
    const reply = (status: number, json: unknown) => new Response(JSON.stringify(json), { status });
    if (u.endsWith('/transaction/initialize')) return reply(200, { status: true, message: 'ok', data: { authorization_url: `https://checkout.paystack.com/${body.reference}`, reference: body.reference } });
    if (u.includes('/transaction/verify/')) {
      const r = verify(decodeURIComponent(u.split('/transaction/verify/')[1]!));
      return reply(r.status, r.json);
    }
    if (u.endsWith('/transaction/charge_authorization')) {
      const r = charge(body.reference, body);
      return reply(r.status, r.json);
    }
    if (u === 'https://api.resend.com/emails') return reply(200, { id: 'email' });
    return reply(404, { status: false, message: 'not mocked' });
  });
});
afterAll(async () => {
  setBillingTransport(null);
  env.PAYSTACK_SECRET_KEY = undefined;
  env.RESEND_API_KEY = undefined;
  env.CRON_SECRET = undefined;
  await app.close();
  await pool.end();
});
beforeEach(async () => {
  await resetDb();
  env.PAYSTACK_SECRET_KEY = SECRET;
  env.RESEND_API_KEY = 're_test_key';
  calls = [];
  charge = (ref, body) => ({ status: 200, json: { status: true, message: 'Charge attempted', data: paid(ref, Number(body.amount)) } });
  verify = () => ({ status: 200, json: { status: true, message: 'ok', data: { reference: 'x', status: 'abandoned', amount: 0, currency: 'NGN' } } });
});

const change = (c: Client, plan: string) => c.req({ method: 'POST', url: `/v1/orgs/${c.orgId}/billing/change`, payload: { plan } });
const billing = async (c: Client) => (await c.req({ method: 'GET', url: `/v1/orgs/${c.orgId}/billing` })).json();
const planOf = async (orgId: string) => (await pool.query('select plan from organizations where id = $1', [orgId])).rows[0].plan as string;
const auditActions = async (orgId: string) => (await pool.query('select action from audit_log where org_id = $1 order by created_at, id', [orgId])).rows.map((r) => r.action as string);
const emails = () => calls.filter((c) => c.url === 'https://api.resend.com/emails').map((c) => c.body);
const sign = (raw: string, secret = SECRET) => createHmac('sha512', secret).update(raw).digest('hex');
const webhook = (event: unknown, secret = SECRET) => {
  const raw = JSON.stringify(event);
  return app.inject({ method: 'POST', url: '/v1/billing/paystack/webhook', headers: { 'content-type': 'application/json', 'x-paystack-signature': sign(raw, secret) }, payload: raw });
};
const setSub = (orgId: string, fields: Record<string, unknown>) => {
  const keys = Object.keys(fields);
  return pool.query(`update billing_subscriptions set ${keys.map((k, i) => `${k} = $${i + 2}`).join(', ')} where org_id = $1`, [orgId, ...Object.values(fields)]);
};

/** Owner starts a checkout and Paystack confirms it by webhook. */
async function subscribe(owner: Client, plan: 'core' | 'plus') {
  const res = await change(owner, plan);
  expect(res.statusCode).toBe(200);
  const { reference, amountKobo } = res.json();
  const hook = await webhook({ event: 'charge.success', data: paid(reference, amountKobo) });
  expect(hook.json().result).toBe('applied');
  await billingIdle();
  return reference as string;
}

describe('choosing a plan', () => {
  it('says paying online is not set up when there is no Paystack key', async () => {
    env.PAYSTACK_SECRET_KEY = undefined;
    const owner = await signup(app, 'ada@paywave.ng');
    expect((await billing(owner)).ready).toBe(false);
    const res = await change(owner, 'core');
    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe('BILLING_OFF');
  });

  it('starts a Paystack checkout in naira with VAT, for owners only', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    const res = await change(owner, 'core');
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.action).toBe('pay');
    expect(body.amountKobo).toBe(CORE);
    expect(body.authorizationUrl).toMatch(/^https:\/\/checkout\.paystack\.com\//);
    const init = calls.find((c) => c.url.endsWith('/transaction/initialize'))!.body;
    expect(init).toMatchObject({ email: 'ada@paywave.ng', amount: String(CORE), currency: 'NGN', reference: body.reference, metadata: { org_id: owner.orgId, plan: 'core', kind: 'checkout' } });
    expect(init.channels).toEqual(['card', 'bank_transfer', 'ussd', 'bank']);
    expect(init.callback_url).toBe(`${env.WEB_URL}/settings?billing=return`);
    expect(body.reference).toMatch(/^fts-[0-9a-f]{20}$/);
    // Nothing changes until Paystack confirms.
    expect(await planOf(owner.orgId)).toBe('free');
    expect(await auditActions(owner.orgId)).toContain('billing.checkout_started');
  });

  it("refuses admins, Enterprise (that's a conversation) and plans Fortis set up by hand", async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    const tunde = await signup(app, 'tunde@paywave.ng');
    await setPlan(owner.orgId, 'core'); // Free has one seat.
    await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/members`, payload: { email: 'tunde@paywave.ng', role: 'admin' } });
    const asAdmin = { ...tunde, orgId: owner.orgId };
    await setPlan(owner.orgId, 'free');
    expect((await change(asAdmin, 'core')).statusCode).toBe(403);
    expect((await asAdmin.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/billing` })).statusCode).toBe(200);

    const ent = await change(owner, 'enterprise');
    expect(ent.statusCode).toBe(400);
    expect(ent.json().error.code).toBe('ENTERPRISE_SALES');

    await setPlan(owner.orgId, 'plus');
    expect((await billing(owner)).managed).toBe(true);
    const managed = await change(owner, 'core');
    expect(managed.statusCode).toBe(409);
    expect(managed.json().error.code).toBe('PLAN_MANAGED');
  });
});

describe('payments', () => {
  it('applies a signed webhook once: plan on, a month paid, the card saved sealed, a receipt sent', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    const reference = await subscribe(owner, 'core');
    expect(await planOf(owner.orgId)).toBe('core');

    const b = await billing(owner);
    expect(b.subscription).toMatchObject({ plan: 'core', status: 'active', cancelAtPeriodEnd: false, card: { brand: 'visa', last4: '4081', exp: '12/30' } });
    const start = new Date(b.subscription.currentPeriodStart);
    expect(new Date(b.subscription.currentPeriodEnd).toISOString()).toBe(addMonth(start).toISOString());
    expect(JSON.stringify(b)).not.toContain('AUTH_test123');
    const stored = (await pool.query('select "authorization" from billing_subscriptions where org_id = $1', [owner.orgId])).rows[0].authorization as string;
    expect(stored).toMatch(/^v1\./);
    expect(stored).not.toContain('AUTH_test123');
    expect(b.payments[0]).toMatchObject({ reference, status: 'success', amountKobo: CORE, vatKobo: 33_750_00, channel: 'card' });

    const mails = emails();
    expect(mails).toHaveLength(1);
    expect(mails[0].to).toEqual(['ada@paywave.ng']);
    expect(mails[0].subject).toBe('Fortis receipt: Fortis Core, ₦483,750');
    expect(mails[0].text).toContain('₦450,000 + VAT ₦33,750 = ₦483,750');
    expect(mails[0].text).toContain(reference);

    // Paystack redelivers; the owner also comes back from checkout. Neither applies it again.
    const event = { event: 'charge.success', data: paid(reference, CORE, { id: 42 }) };
    const first = await webhook(event);
    const again = await webhook(event);
    expect(first.json().result).toBe('already');
    expect(again.json().duplicate).toBe(true);
    const v = await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/billing/verify`, payload: { reference } });
    expect(v.json().status).toBe('success');
    await billingIdle();
    expect(emails()).toHaveLength(1);
    const actions = await auditActions(owner.orgId);
    expect(actions.filter((a) => a === 'billing.payment_succeeded')).toHaveLength(1);
    expect(actions).toContain('plan.changed');
  });

  it('rejects a bad signature, ignores other events and payments Fortis did not start', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    const { reference } = (await change(owner, 'core')).json();
    const forged = await webhook({ event: 'charge.success', data: paid(reference, CORE) }, 'sk_test_someone_else');
    expect(forged.statusCode).toBe(401);
    const unsigned = await app.inject({ method: 'POST', url: '/v1/billing/paystack/webhook', headers: { 'content-type': 'application/json' }, payload: '{}' });
    expect(unsigned.statusCode).toBe(401);
    expect((await webhook({ event: 'transfer.success', data: { reference } })).json().ignored).toBe('transfer.success');
    expect((await webhook({ event: 'charge.success', data: paid('someone-elses-ref', CORE) })).json().result).toBe('unknown');
    expect(await planOf(owner.orgId)).toBe('free');
  });

  it("doesn't apply a payment for the wrong amount or currency", async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    const { reference } = (await change(owner, 'plus')).json();
    expect((await webhook({ event: 'charge.success', data: paid(reference, CORE) })).json().result).toBe('failed');
    expect(await planOf(owner.orgId)).toBe('free');
    expect(await auditActions(owner.orgId)).toContain('billing.payment_mismatch');
  });

  it('applies a payment when the owner comes back, and waits for a transfer still on its way', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    const { reference } = (await change(owner, 'core')).json();
    verify = () => ({ status: 200, json: { status: true, message: 'ok', data: { reference, status: 'ongoing', amount: CORE, currency: 'NGN', channel: 'bank_transfer' } } });
    const waiting = await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/billing/verify`, payload: { reference } });
    expect(waiting.json().status).toBe('pending');
    expect(await planOf(owner.orgId)).toBe('free');

    verify = () => ({ status: 200, json: { status: true, message: 'ok', data: paid(reference, CORE, { channel: 'bank_transfer', authorization: { channel: 'bank_transfer', reusable: false } }) } });
    const done = await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/billing/verify`, payload: { reference } });
    expect(done.json().status).toBe('success');
    expect(done.json().billing.subscription).toMatchObject({ plan: 'core', card: null });
    expect(await planOf(owner.orgId)).toBe('core');

    const other = await signup(app, 'eve@elsewhere.ng');
    expect((await other.req({ method: 'POST', url: `/v1/orgs/${other.orgId}/billing/verify`, payload: { reference } })).statusCode).toBe(404);
  });
});

describe('changing plan', () => {
  it('upgrades now with credit for the unused days, and moves down at renewal', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await subscribe(owner, 'core');
    // Halfway through the month.
    const start = new Date(Date.now() - 15 * DAY);
    const end = new Date(Date.now() + 15 * DAY);
    await setSub(owner.orgId, { current_period_start: start, current_period_end: end });

    const quote = upgradePrice('core', 'plus', start, end);
    expect(quote.credit).toBeGreaterThan(224_000_00);
    expect(quote.credit).toBeLessThan(226_000_00);
    const up = (await change(owner, 'plus')).json();
    expect(up.kind).toBe('upgrade');
    expect(Math.abs(up.amountKobo - quote.total)).toBeLessThan(200);
    await webhook({ event: 'charge.success', data: paid(up.reference, up.amountKobo) });
    expect(await planOf(owner.orgId)).toBe('plus');

    const down = (await change(owner, 'core')).json();
    expect(down.action).toBe('scheduled');
    expect(await planOf(owner.orgId)).toBe('plus');
    expect(down.billing.subscription.nextPlan).toBe('core');

    // Renewal day: Core starts and the saved card is charged Core's price.
    const periodEnd = new Date(down.billing.subscription.currentPeriodEnd);
    const report = await runDueBilling(new Date(periodEnd.getTime() + 60_000));
    expect(report.renewed).toEqual([owner.orgId]);
    expect(await planOf(owner.orgId)).toBe('core');
    const renewal = calls.filter((c) => c.url.endsWith('/transaction/charge_authorization'));
    expect(renewal).toHaveLength(1);
    expect(renewal[0]!.body).toMatchObject({ authorization_code: 'AUTH_test123', amount: String(CORE), currency: 'NGN', email: 'ada@paywave.ng' });
    const b = await billing(owner);
    expect(new Date(b.subscription.currentPeriodStart).toISOString()).toBe(periodEnd.toISOString());
    expect(b.subscription).toMatchObject({ status: 'active', nextPlan: null });
  });

  it('cancels at the end of the month, can be undone, and then keeps every finding on Free', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await subscribe(owner, 'core');
    const { key } = await projectWithKey(owner);
    const up = await app.inject({ method: 'POST', url: '/v1/cli/scans', headers: { authorization: `Bearer ${key}` }, payload: scanPayload([{ ruleId: 'DEP-OSV', severity: 'high', title: 'lodash 4.17.20: prototype pollution', file: 'package-lock.json', line: 1, snippet: 'lodash@4.17.20' }]) });
    expect(up.statusCode, up.body).toBe(201);

    expect((await change(owner, 'free')).json().action).toBe('scheduled');
    expect((await change(owner, 'core')).json().action).toBe('resumed');
    expect((await change(owner, 'free')).json().action).toBe('scheduled');
    expect(await planOf(owner.orgId)).toBe('core');

    const b = await billing(owner);
    calls = [];
    const report = await runDueBilling(new Date(new Date(b.subscription.currentPeriodEnd).getTime() + 1000));
    await billingIdle();
    expect(report.ended).toEqual([owner.orgId]);
    expect(await planOf(owner.orgId)).toBe('free');
    expect(calls.some((c) => c.url.endsWith('/charge_authorization'))).toBe(false);
    expect(emails()[0].subject).toBe('Your workspace is now on Fortis Free');
    expect((await pool.query('select count(*)::int as n from findings where org_id = $1', [owner.orgId])).rows[0].n).toBe(1);
    expect(await auditActions(owner.orgId)).toEqual(expect.arrayContaining(['billing.canceled', 'billing.resumed', 'billing.ended']));

    // Choosing a plan again is a fresh checkout.
    expect((await change(owner, 'core')).json()).toMatchObject({ action: 'pay', kind: 'checkout', amountKobo: CORE });
  });
});

describe('renewals', () => {
  it('keeps the plan through the grace period after a declined card, retries daily, then steps down to Free', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await subscribe(owner, 'core');
    charge = (ref, body) => ({ status: 200, json: { status: true, message: 'Charge attempted', data: { ...paid(ref, Number(body.amount)), status: 'failed', gateway_response: 'Insufficient Funds' } } });
    const end = new Date((await billing(owner)).subscription.currentPeriodEnd);
    calls = [];

    const day1 = await runDueBilling(new Date(end.getTime() + 60_000));
    await billingIdle();
    expect(day1.failed).toEqual([owner.orgId]);
    expect(await planOf(owner.orgId)).toBe('core');
    let b = await billing(owner);
    expect(b.subscription.status).toBe('past_due');
    expect(new Date(b.subscription.graceEndsAt).getTime()).toBe(end.getTime() + 7 * DAY);
    expect(emails().map((m) => m.subject)).toEqual(["We couldn't renew your Fortis Core plan"]);
    expect(emails()[0].text).toContain('Insufficient Funds');

    // Same day: no second charge.
    await runDueBilling(new Date(end.getTime() + 2 * 60 * 60 * 1000));
    expect(calls.filter((c) => c.url.endsWith('/charge_authorization'))).toHaveLength(1);
    // Next day: one retry, no second email.
    await runDueBilling(new Date(end.getTime() + DAY + 60_000));
    await billingIdle();
    expect(calls.filter((c) => c.url.endsWith('/charge_authorization'))).toHaveLength(2);
    expect(emails()).toHaveLength(1);

    const gone = await runDueBilling(new Date(end.getTime() + 7 * DAY + 60_000));
    await billingIdle();
    expect(gone.ended).toEqual([owner.orgId]);
    expect(await planOf(owner.orgId)).toBe('free');
    b = await billing(owner);
    expect(b.subscription.status).toBe('ended');
    expect(b.payments.filter((p: any) => p.status === 'failed')).toHaveLength(2);
    expect(await auditActions(owner.orgId)).toEqual(expect.arrayContaining(['billing.renewal_failed', 'billing.ended', 'plan.changed']));
  });

  it('a retry that goes through during the grace period continues the same months', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await subscribe(owner, 'core');
    const end = new Date((await billing(owner)).subscription.currentPeriodEnd);
    charge = (ref, body) => ({ status: 400, json: { status: false, message: 'Declined' } });
    await runDueBilling(new Date(end.getTime() + 60_000));
    charge = (ref, body) => ({ status: 200, json: { status: true, message: 'ok', data: paid(ref, Number(body.amount)) } });
    const r = await runDueBilling(new Date(end.getTime() + DAY + 60_000));
    expect(r.renewed).toEqual([owner.orgId]);
    const b = await billing(owner);
    expect(b.subscription).toMatchObject({ status: 'active', graceEndsAt: null });
    expect(new Date(b.subscription.currentPeriodStart).toISOString()).toBe(end.toISOString());
  });

  it('reminds a workspace that paid by transfer, then lets it pay the next month from where it left off', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    const { reference } = (await change(owner, 'core')).json();
    await webhook({ event: 'charge.success', data: paid(reference, CORE, { channel: 'bank_transfer', authorization: { channel: 'bank_transfer', reusable: false } }) });
    await billingIdle();
    const end = new Date((await billing(owner)).subscription.currentPeriodEnd);
    calls = [];

    const early = await runDueBilling(new Date(end.getTime() - 2 * DAY));
    await runDueBilling(new Date(end.getTime() - DAY));
    await billingIdle();
    expect(early.reminded).toEqual([owner.orgId]);
    expect(emails().map((m) => m.subject)).toEqual([`Your Fortis Core plan renews on ${end.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Africa/Lagos' })}`]);

    await runDueBilling(new Date(end.getTime() + 60_000));
    expect((await billing(owner)).subscription.status).toBe('past_due');
    expect(calls.some((c) => c.url.endsWith('/charge_authorization'))).toBe(false);

    const renew = (await change(owner, 'core')).json();
    expect(renew).toMatchObject({ action: 'pay', kind: 'renewal', amountKobo: CORE });
    await webhook({ event: 'charge.success', data: paid(renew.reference, CORE, { channel: 'bank_transfer', authorization: { reusable: false } }) });
    const b = await billing(owner);
    expect(b.subscription.status).toBe('active');
    expect(new Date(b.subscription.currentPeriodStart).toISOString()).toBe(end.toISOString());
  });

  it("doesn't charge again while a renewal is still processing", async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await subscribe(owner, 'core');
    const end = new Date((await billing(owner)).subscription.currentPeriodEnd);
    charge = (ref, body) => ({ status: 200, json: { status: true, message: 'ok', data: { ...paid(ref, Number(body.amount)), status: 'processing' } } });
    verify = (ref) => ({ status: 200, json: { status: true, message: 'ok', data: { ...paid(ref, CORE), status: 'processing' } } });
    await runDueBilling(new Date(end.getTime() + 60_000));
    await runDueBilling(new Date(end.getTime() + DAY + 60_000));
    expect(calls.filter((c) => c.url.endsWith('/charge_authorization'))).toHaveLength(1);
    expect(calls.filter((c) => c.url.includes('/transaction/verify/'))).toHaveLength(1);
  });

  it('runs from the cron route only with the shared secret', async () => {
    env.CRON_SECRET = undefined;
    expect((await app.inject({ method: 'POST', url: '/v1/internal/billing/run-due' })).statusCode).toBe(404);
    env.CRON_SECRET = 'c'.repeat(40);
    expect((await app.inject({ method: 'POST', url: '/v1/internal/billing/run-due', headers: { 'x-fortis-cron': 'nope' } })).statusCode).toBe(401);
    const ok = await app.inject({ method: 'POST', url: '/v1/internal/billing/run-due', headers: { 'x-fortis-cron': 'c'.repeat(40) } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toMatchObject({ renewed: [], ended: [] });
    env.CRON_SECRET = undefined;
  });
});
