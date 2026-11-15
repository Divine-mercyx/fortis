'use client';

import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import useSWR, { useSWRConfig } from 'swr';

import { PLANS, PLAN_IDS, type PlanId } from '@fortis/shared';

import { useSession } from '@/components/session';
import { Modal, Skeleton, useToast } from '@/components/ui';
import { api, fetcher } from '@/lib/api';
import { naira } from '@/lib/format';

type Price = { base: number; vat: number; total: number; credit?: number };
type Payment = {
  reference: string;
  kind: 'checkout' | 'upgrade' | 'renewal';
  plan: string;
  amountKobo: number;
  vatKobo: number;
  status: 'pending' | 'success' | 'failed' | 'abandoned';
  channel: string | null;
  failureReason: string | null;
  periodStart: string | null;
  periodEnd: string | null;
  createdAt: string;
  paidAt: string | null;
  by: string | null;
};
export type Billing = {
  ready: boolean;
  plan: string;
  managed: boolean;
  vatPercent: number;
  graceDays: number;
  prices: Record<'core' | 'plus', Price>;
  subscription: null | {
    plan: string;
    status: 'active' | 'past_due' | 'ended';
    currentPeriodStart: string;
    currentPeriodEnd: string;
    cancelAtPeriodEnd: boolean;
    nextPlan: string | null;
    card: { brand: string | null; last4: string | null; exp: string | null } | null;
    billingEmail: string;
    graceEndsAt: string | null;
    upgradeQuotes: Partial<Record<'core' | 'plus', Price>>;
  };
  payments: Payment[];
};
type ChangeResult = { action: 'pay'; authorizationUrl: string; reference: string } | { action: 'scheduled' | 'resumed'; plan: string; billing: Billing };

const RANK: Record<string, number> = { free: 0, core: 1, plus: 2, enterprise: 3 };
const day = (v: string | Date) => new Date(v).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
const planName = (p: string) => (p in PLANS ? PLANS[p as PlanId].name : p);
const limit = (n: number | null) => (n === null ? 'Unlimited' : String(n));
const kobo = (n: number) => `₦${(n / 100).toLocaleString('en-NG', { maximumFractionDigits: 2 })}`;
const live = (b: Billing | undefined) => (b?.subscription && b.subscription.status !== 'ended' ? b.subscription : null);

export function useBilling() {
  const { org } = useSession();
  const canSee = org.role === 'owner' || org.role === 'admin';
  return useSWR<Billing>(canSee ? `/v1/orgs/${org.id}/billing` : null, fetcher);
}

/** Comes back from Paystack's page: confirm the payment, and keep checking while a transfer lands. */
function useReturnFromPaystack(onSettled: (b: Billing) => void) {
  const { org, refresh } = useSession();
  const toast = useToast();
  const [waiting, setWaiting] = useState<string | null>(null);
  const done = useRef(false);
  const { mutate: mutateAll } = useSWRConfig();
  const latest = useRef({ onSettled, refresh, toast, mutateAll });
  latest.current = { onSettled, refresh, toast, mutateAll };

  useEffect(() => {
    const { onSettled, refresh, toast } = latest.current;
    if (done.current) return;
    const params = new URLSearchParams(window.location.search);
    const reference = params.get('reference') ?? params.get('trxref');
    if (params.get('billing') !== 'return' || !reference) return;
    done.current = true;
    window.history.replaceState(null, '', `${window.location.pathname}#billing`);
    let tries = 0;
    let timer: ReturnType<typeof setTimeout>;
    const check = async () => {
      try {
        const r = await api<{ status: 'success' | 'pending' | 'failed'; billing: Billing }>(`/v1/orgs/${org.id}/billing/verify`, { method: 'POST', body: { reference } });
        latest.current.onSettled(r.billing);
        if (r.status === 'success') {
          setWaiting(null);
          latest.current.toast(`Payment received. You're on ${planName(r.billing.plan)}.`);
          void latest.current.refresh();
          // Limits, usage and the audit log all change with the plan.
          void latest.current.mutateAll((key) => typeof key === 'string' && key.startsWith(`/v1/orgs/${org.id}`) && !key.endsWith('/billing'));
          return;
        }
        if (r.status === 'failed') {
          setWaiting(null);
          toast("The payment didn't go through, so your plan hasn't changed.", true);
          return;
        }
        setWaiting(reference);
        if (++tries < 24) timer = setTimeout(check, 5000);
      } catch (err) {
        setWaiting(null);
        toast((err as Error).message, true);
      }
    };
    void check();
    return () => clearTimeout(timer);
  }, [org.id]);
  return waiting;
}

/** One line under the usage bars: what's paid, until when, and what happens next. */
export function BillingStatus() {
  const { org } = useSession();
  const { data, mutate } = useBilling();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const waiting = useReturnFromPaystack((b) => void mutate(b, { revalidate: false }));
  const isOwner = org.role === 'owner';

  if (org.role !== 'owner' && org.role !== 'admin') return <p className="small bill-note">Owners manage billing.</p>;
  if (!data) return <div style={{ marginTop: 20 }}><Skeleton h={40} /></div>;
  if (!data.ready) return <p className="small bill-note">Paying online isn't switched on yet. To change plan, email hello@fortis.dev.</p>;

  const sub = live(data);
  async function resume(plan: string) {
    setBusy(true);
    try {
      const r = await api<ChangeResult>(`/v1/orgs/${org.id}/billing/change`, { method: 'POST', body: { plan } });
      if (r.action !== 'pay') void mutate(r.billing, { revalidate: false });
      toast(`${planName(plan)} renews as normal`);
    } catch (err) {
      toast((err as Error).message, true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="bill-status" id="billing">
      {waiting ? (
        <div className="bill-line warn"><span className="spinner" /> Waiting for Paystack to confirm your payment. A transfer can take a few minutes; this updates by itself.</div>
      ) : null}
      {!sub ? (
        data.managed ? (
          <p className="small bill-note">Your plan was set up with Fortis directly. To change it, email hello@fortis.dev.</p>
        ) : (
          <p className="small bill-note">Pay monthly in naira by card, bank transfer, USSD or bank, through Paystack. {isOwner ? 'Choose a plan below.' : 'An owner can choose a plan below.'}</p>
        )
      ) : sub.status === 'past_due' ? (
        <div className="bill-line bad">
          <span>
            <strong>Payment due.</strong> {planName(sub.plan)} stays on until {day(sub.graceEndsAt ?? sub.currentPeriodEnd)}, then the workspace moves to Free. Your findings are kept.
          </span>
          {isOwner ? <PayButton plan={sub.plan as 'core' | 'plus'} label="Pay now" billing={data} /> : null}
        </div>
      ) : sub.cancelAtPeriodEnd || sub.nextPlan ? (
        <div className="bill-line">
          <span>
            {planName(sub.plan)} until {day(sub.currentPeriodEnd)}, then {sub.cancelAtPeriodEnd ? 'Fortis Free. Your findings are kept.' : `${planName(sub.nextPlan!)}.`}
          </span>
          {isOwner ? <button className="btn btn-outline btn-sm" disabled={busy} onClick={() => resume(sub.plan)}>{busy ? <span className="spinner" /> : null} Keep {planName(sub.plan).replace('Fortis ', '')}</button> : null}
        </div>
      ) : (
        <div className="bill-line">
          <span>
            Renews on <strong>{day(sub.currentPeriodEnd)}</strong>{' '}
            {sub.card ? <>with <span style={{ whiteSpace: 'nowrap' }}>{cap(sub.card.brand)} •••• {sub.card.last4}</span></> : <>· no card saved, so we'll email a reminder to pay</>}
          </span>
          {isOwner ? <CancelButton billing={data} /> : null}
        </div>
      )}
    </div>
  );
}

const cap = (s: string | null) => (s ? s[0]!.toUpperCase() + s.slice(1) : 'Card');

function PayButton({ plan, label, billing, primary = true }: { plan: 'core' | 'plus'; label: string; billing: Billing; primary?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className={`btn btn-sm ${primary ? 'btn-primary' : 'btn-outline'}`} onClick={() => setOpen(true)}>{label}</button>
      {open ? createPortal(<Checkout plan={plan} billing={billing} onClose={() => setOpen(false)} />, document.body) : null}
    </>
  );
}

function Checkout({ plan, billing, onClose }: { plan: 'core' | 'plus'; billing: Billing; onClose: () => void }) {
  const { org } = useSession();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const sub = live(billing);
  const quote = (sub?.status === 'active' ? sub.upgradeQuotes[plan] : undefined) ?? billing.prices[plan];
  const renewing = sub?.plan === plan && sub.status === 'past_due';

  async function go() {
    setBusy(true);
    try {
      const r = await api<ChangeResult>(`/v1/orgs/${org.id}/billing/change`, { method: 'POST', body: { plan } });
      if (r.action === 'pay') window.location.assign(r.authorizationUrl);
    } catch (err) {
      toast((err as Error).message, true);
      setBusy(false);
    }
  }

  return (
    <Modal
      title={renewing ? `Pay for ${planName(plan)}` : `Move to ${planName(plan)}`}
      lead={quote.credit ? `It starts as soon as you pay. What's left of this month on ${planName(sub!.plan)} comes off the price, and a new month starts today.` : renewing ? 'The new month continues from where the last one ended.' : 'It starts as soon as you pay, for one month. It renews monthly; you can change plan or cancel at any time.'}
      onClose={onClose}
    >
      <dl className="bill-sum">
        <dt>{planName(plan)}, one month</dt><dd>{kobo(PLANS[plan].monthlyPriceKobo ?? 0)}</dd>
        {quote.credit ? <><dt>Unused days on {planName(sub!.plan)}</dt><dd>−{kobo(quote.credit)}</dd></> : null}
        <dt>VAT ({billing.vatPercent}%)</dt><dd>{kobo(quote.vat)}</dd>
        <dt className="total">You pay now</dt><dd className="total">{kobo(quote.total)}</dd>
      </dl>
      <p className="small" style={{ margin: '14px 0 0' }}>
        You'll pay on Paystack's page by card, bank transfer, USSD or bank. A card is kept by Paystack to renew each month; with a transfer we email you before the next month is due.
      </p>
      <div className="modal-actions">
        <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" disabled={busy} onClick={go}>{busy ? <span className="spinner" /> : null} Continue to Paystack</button>
      </div>
    </Modal>
  );
}

function Schedule({ plan, billing, onClose }: { plan: string; billing: Billing; onClose: () => void }) {
  const { org } = useSession();
  const { mutate } = useBilling();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const sub = live(billing)!;
  const toFree = plan === 'free';

  async function go() {
    setBusy(true);
    try {
      const r = await api<ChangeResult>(`/v1/orgs/${org.id}/billing/change`, { method: 'POST', body: { plan } });
      if (r.action !== 'pay') void mutate(r.billing, { revalidate: false });
      toast(toFree ? `Moves to Free on ${day(sub.currentPeriodEnd)}` : `Moves to ${planName(plan)} on ${day(sub.currentPeriodEnd)}`);
      onClose();
    } catch (err) {
      toast((err as Error).message, true);
      setBusy(false);
    }
  }

  return (
    <Modal
      title={toFree ? 'Cancel your plan' : `Move to ${planName(plan)}`}
      lead={
        toFree
          ? `${planName(sub.plan)} stays on until ${day(sub.currentPeriodEnd)}, and nothing more is charged. Then the workspace moves to Fortis Free: findings, scans and history are kept, and paid features switch off.`
          : `${planName(sub.plan)} stays on until ${day(sub.currentPeriodEnd)}, which is paid for. Then ${planName(plan)} starts at ${kobo(billing.prices[plan as 'core'].total)} a month, VAT included.`
      }
      onClose={onClose}
    >
      <div className="modal-actions">
        <button type="button" className="btn btn-outline" onClick={onClose}>Keep {planName(sub.plan).replace('Fortis ', '')}</button>
        <button className={`btn ${toFree ? 'btn-danger' : 'btn-primary'}`} disabled={busy} onClick={go}>{busy ? <span className="spinner" /> : null} {toFree ? `Move to Free on ${day(sub.currentPeriodEnd)}` : `Switch on ${day(sub.currentPeriodEnd)}`}</button>
      </div>
    </Modal>
  );
}

function CancelButton({ billing }: { billing: Billing }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="btn btn-outline btn-sm" onClick={() => setOpen(true)}>Cancel plan</button>
      {open ? createPortal(<Schedule plan="free" billing={billing} onClose={() => setOpen(false)} />, document.body) : null}
    </>
  );
}

function ScheduleButton({ plan, billing }: { plan: string; billing: Billing }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="btn btn-outline btn-sm" onClick={() => setOpen(true)}>Switch at renewal</button>
      {open ? createPortal(<Schedule plan={plan} billing={billing} onClose={() => setOpen(false)} />, document.body) : null}
    </>
  );
}

/** The plan cards, with what an owner can do on each. */
export function PlanCards() {
  const { org } = useSession();
  const { data } = useBilling();
  const isOwner = org.role === 'owner';
  const sub = live(data);
  const current = data?.plan ?? org.plan;

  function action(id: PlanId) {
    if (!data?.ready || !isOwner || data.managed) return null;
    if (id === 'enterprise') return <a className="btn btn-outline btn-sm" href="mailto:hello@fortis.dev?subject=Fortis%20Enterprise">Talk to us</a>;
    if (id === 'free') return null;
    if (id === current) return null;
    if (!sub || RANK[id]! > RANK[sub.plan]!) return <PayButton plan={id} label={sub ? `Upgrade to ${PLANS[id].name.replace('Fortis ', '')}` : `Choose ${PLANS[id].name.replace('Fortis ', '')}`} billing={data} primary={id === 'plus' || !sub} />;
    if (sub.nextPlan === id) return <span className="small">Starts {day(sub.currentPeriodEnd)}</span>;
    return <ScheduleButton plan={id} billing={data} />;
  }

  return (
    <div className="card-pad" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 14 }}>
      {PLAN_IDS.map((id) => {
        const p = PLANS[id];
        const isCurrent = id === current;
        const dark = id === 'plus';
        const act = action(id);
        return (
          <div key={id} className="tile plan-tile" style={{ ['--c' as string]: isCurrent ? 'var(--green)' : 'transparent', background: dark ? 'var(--navy)' : '#fff', borderColor: dark ? 'var(--navy)' : undefined }}>
            <div className="lbl" style={{ color: dark ? 'var(--mint)' : undefined }}>{p.name}{isCurrent ? ' · current' : ''}</div>
            <div className="v" style={{ fontSize: 26, color: dark ? '#fff' : undefined }}>
              {id === 'enterprise' ? `from ${naira(p.monthlyPriceKobo)}` : naira(p.monthlyPriceKobo)}
            </div>
            <ul style={{ listStyle: 'none', padding: 0, margin: '12px 0 0', fontSize: 13, color: dark ? '#D3DBEA' : 'var(--ink-2)', display: 'grid', gap: 6 }}>
              <li>{limit(p.maxProjects)} projects · {limit(p.maxSeats)} seats</li>
              <li>{p.rulePacks.includes('fintech') ? 'Fintech rule pack' : 'Secrets, dependencies, infrastructure and mobile'}</li>
              <li>{p.dashboard ? 'Findings dashboard' : 'Results stay local'}</li>
              {p.dast !== 'none' ? <li>OWASP ZAP {p.dast === 'full' ? 'baseline + full scans' : 'baseline scans'} · {limit(p.maxTargets)} targets</li> : null}
              {p.stagingChecks ? <li>Access checks with two test users</li> : null}
              {p.releaseGates ? <li>Release gates</li> : null}
            </ul>
            {act ? <div className="plan-act">{act}</div> : null}
          </div>
        );
      })}
    </div>
  );
}

const STATUS: Record<Payment['status'], { label: string; cls: string }> = {
  success: { label: 'Paid', cls: 'p-ok' },
  pending: { label: 'Waiting', cls: 'p-medium' },
  failed: { label: 'Failed', cls: 'p-critical' },
  abandoned: { label: 'Not finished', cls: 'p-mute' },
};
const KIND: Record<Payment['kind'], string> = { checkout: 'New plan', upgrade: 'Upgrade', renewal: 'Renewal' };

/** Every payment: the record behind each receipt. */
export function PaymentHistory() {
  const { data } = useBilling();
  if (!data?.ready || !data.payments.length) return null;
  return (
    <section className="card reveal">
      <div className="card-head"><h3>Payments</h3><span className="small">Receipts are emailed to the owners</span></div>
      <ul className="list">
        {data.payments.map((p, i) => (
          <li key={p.reference} className="row-in bill-pay" style={{ ['--i' as string]: i }}>
            <span className={`pill ${STATUS[p.status].cls}`}>{STATUS[p.status].label}</span>
            <span style={{ minWidth: 0 }}>
              <strong style={{ color: 'var(--ink)' }}>{planName(p.plan)} · {KIND[p.kind]}</strong>
              <span className="small" style={{ display: 'block' }}>
                {p.periodStart && p.periodEnd ? `${day(p.periodStart)} to ${day(p.periodEnd)}` : day(p.createdAt)}
                {p.channel ? ` · ${p.channel.replace('_', ' ')}` : ''}
                {p.status === 'failed' && p.failureReason ? ` · ${p.failureReason}` : ''}
                {p.by ? ` · ${p.by}` : ''}
              </span>
              <span className="small mono" style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.reference}</span>
            </span>
            <span className="meta bill-amt">{kobo(p.amountKobo)}{p.vatKobo ? <span className="small" style={{ display: 'block' }}>incl. VAT {kobo(p.vatKobo)}</span> : null}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
