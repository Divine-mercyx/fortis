'use client';

import { useState } from 'react';
import useSWR from 'swr';

import { Check, Lock, Plus, Pulse, Shield, Target, Trash } from '@/components/icons';
import { useSession } from '@/components/session';
import { CodeLine, CopyButton, Empty, FormError, Modal, useToast } from '@/components/ui';
import { InfoTip } from '@/components/widgets';
import { api, fetcher } from '@/lib/api';
import { CLI_COMMAND } from '@/lib/cli';
import { timeAgo } from '@/lib/format';

export type StagingTarget = {
  id: string;
  url: string;
  hostname: string;
  environment: 'staging' | 'development' | 'production';
  label: string | null;
  status: 'unverified' | 'unauthorized' | 'ready' | 'paused';
  verification: { recordName: string; recordType: string; recordValue: string; verifiedAt: string | null; lastError: string | null };
  authorization: { signer: string; by: string | null; version: string; at: string } | null;
  allowsActiveScan: boolean;
  pausedAt: string | null;
  lastRunAt: string | null;
};

type TargetsResponse = {
  targets: StagingTarget[];
  plan: { dast: 'none' | 'baseline' | 'full'; maxTargets: number | null; name: string };
  authorization: { version: string; text: string };
};

const STATUS: Record<StagingTarget['status'], { label: string; cls: string; hint: string }> = {
  unverified: { label: 'Verify domain', cls: 'p-medium', hint: 'Add the DNS record below to prove you control this domain.' },
  unauthorized: { label: 'Needs authorisation', cls: 'p-high', hint: 'An admin must sign the testing authorisation.' },
  ready: { label: 'Ready', cls: 'p-ok', hint: 'Tests can run against this target.' },
  paused: { label: 'Paused', cls: 'p-mute', hint: 'Tests are blocked. Running tests stop within 20 seconds.' },
};

function Steps({ t }: { t: StagingTarget }) {
  const steps = [
    { done: true, label: 'Added' },
    { done: Boolean(t.verification.verifiedAt), label: 'Domain verified' },
    { done: Boolean(t.authorization), label: 'Authorised' },
    { done: Boolean(t.lastRunAt), label: 'First test' },
  ];
  return (
    <div className="target-steps" aria-label="Progress">
      {steps.map((s, i) => (
        <span key={s.label} className={s.done ? 'done' : ''}>
          <i>{s.done ? <Check /> : i + 1}</i>
          {s.label}
        </span>
      ))}
    </div>
  );
}

function AddTarget({ base, onClose, onDone }: { base: string; onClose: () => void; onDone: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api(base, { method: 'POST', body: { url: f.get('url'), environment: f.get('environment'), label: f.get('label') || undefined } });
      onDone();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Add a staging target" lead="The running app Fortis tests with OWASP ZAP. You'll prove you control the domain with a DNS record, then authorise testing." onClose={onClose}>
      <form onSubmit={submit}>
        <FormError message={error} />
        <label className="field">
          <span>URL</span>
          <input className="input" name="url" type="url" placeholder="https://staging.yourapp.com" required autoFocus />
        </label>
        <label className="field">
          <span>Environment</span>
          <select className="select" name="environment" defaultValue="staging">
            <option value="staging">Staging</option>
            <option value="development">Development</option>
            <option value="production">Production (passive baseline only)</option>
          </select>
        </label>
        <label className="field">
          <span>Label <span className="muted" style={{ fontWeight: 500 }}>(optional)</span></span>
          <input className="input" name="label" placeholder="Customer web app" maxLength={80} />
        </label>
        <div className="modal-actions">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy}>{busy ? <span className="spinner" /> : null} Add target</button>
        </div>
      </form>
    </Modal>
  );
}

function Authorize({ base, t, text, onClose, onDone }: { base: string; t: StagingTarget; text: string; onClose: () => void; onDone: () => void }) {
  const { user } = useSession();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [accept, setAccept] = useState(false);
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api(`${base}/${t.id}/authorize`, { method: 'POST', body: { signerName: f.get('signerName'), accept: true } });
      onDone();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Authorise security testing" lead={t.url} onClose={onClose}>
      <form onSubmit={submit}>
        <FormError message={error} />
        <div className="auth-text">{text}</div>
        <label className="check-line">
          <input type="checkbox" checked={accept} onChange={(e) => setAccept(e.target.checked)} />
          <span>I agree, on behalf of my organisation.</span>
        </label>
        <label className="field">
          <span>Your full name</span>
          <input className="input" name="signerName" defaultValue={user.name} required minLength={3} maxLength={120} />
        </label>
        <p className="small" style={{ marginTop: 0 }}>Your name, the time and this wording are kept in the audit log as evidence.</p>
        <div className="modal-actions">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy || !accept}>{busy ? <span className="spinner" /> : <Lock />} Sign and authorise</button>
        </div>
      </form>
    </Modal>
  );
}

function TargetCard({ t, base, isAdmin, canPause, dast, onChange, onAuthorize }: {
  t: StagingTarget; base: string; isAdmin: boolean; canPause: boolean; dast: string; onChange: () => void; onAuthorize: () => void;
}) {
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const s = STATUS[t.status];

  async function act(path: string, method = 'POST', done?: (r: { verified?: boolean }) => void) {
    setBusy(path);
    try {
      const r = await api<{ verified?: boolean }>(`${base}/${t.id}${path}`, { method });
      done?.(r);
      onChange();
    } catch (err) {
      toast((err as Error).message, true);
    } finally {
      setBusy(null);
    }
  }

  const fullOk = dast === 'full' && t.allowsActiveScan;
  return (
    <div className="target">
      <div className="target-top">
        <span className="ic"><Target /></span>
        <div style={{ minWidth: 0, flex: 1 }}>
          <strong className="t-title" style={{ display: 'block' }}>{t.label ?? t.hostname}</strong>
          <span className="t-file">{t.url} · {t.environment}</span>
        </div>
        <span className={`pill ${s.cls}`} title={s.hint}>{s.label}</span>
      </div>
      <Steps t={t} />

      {t.status === 'unverified' ? (
        <div className="target-body">
          <p className="small" style={{ margin: '0 0 10px' }}>Add this <b>TXT</b> record with your DNS provider, then check it. Leave it in place: removing it doesn't stop tests, but it shows you still control the domain.</p>
          <div className="dns">
            <div><span>Name</span><code>{t.verification.recordName}</code><CopyButton text={t.verification.recordName} /></div>
            <div><span>Value</span><code>{t.verification.recordValue}</code><CopyButton text={t.verification.recordValue} /></div>
          </div>
          {t.verification.lastError ? <p className="field-msg" style={{ marginTop: 10 }}>{t.verification.lastError}</p> : null}
          {isAdmin ? (
            <button
              className="btn btn-primary btn-sm"
              style={{ marginTop: 12 }}
              disabled={busy !== null}
              onClick={() => act('/verify', 'POST', (r) => toast(r.verified ? 'Domain verified' : 'Record not found yet', !r.verified))}
            >
              {busy === '/verify' ? <span className="spinner" /> : <Shield />} Check DNS record
            </button>
          ) : null}
        </div>
      ) : null}

      {t.status === 'unauthorized' ? (
        <div className="target-body">
          <p className="small" style={{ margin: '0 0 10px' }}>Domain verified {timeAgo(t.verification.verifiedAt)}. Before any test runs, an admin signs that you may test it.</p>
          {isAdmin ? <button className="btn btn-primary btn-sm" onClick={onAuthorize}><Lock /> Authorise testing</button> : <span className="small">Ask an admin to authorise testing.</span>}
        </div>
      ) : null}

      {t.status === 'ready' || t.status === 'paused' ? (
        <div className="target-body">
          <CodeLine cmd={`npx ${CLI_COMMAND} test --target ${t.url}`} />
          {fullOk ? <CodeLine cmd={`npx ${CLI_COMMAND} test --target ${t.url} --mode full`} /> : null}
          {dast === 'full' && t.allowsActiveScan ? <CodeLine cmd={`npx ${CLI_COMMAND} access --target ${t.url}`} /> : null}
          <p className="small" style={{ margin: '10px 0 0' }}>
            {t.authorization ? <>Authorised by {t.authorization.signer} {timeAgo(t.authorization.at)}. </> : null}
            {t.lastRunAt ? <>Last test {timeAgo(t.lastRunAt)}. </> : 'No tests yet. '}
            {!t.allowsActiveScan ? 'Production: passive baseline only.' : dast === 'baseline' ? 'Your plan runs passive baseline tests; full active scans come with Fortis Plus.' : null}
          </p>
        </div>
      ) : null}

      <div className="target-actions">
        {t.status === 'paused'
          ? isAdmin ? <button className="btn btn-outline btn-sm" disabled={busy !== null} onClick={() => act('/resume')}><Pulse /> Resume tests</button> : null
          : canPause && t.status !== 'unverified' ? <button className="btn btn-outline btn-sm" disabled={busy !== null} onClick={() => act('/pause')}>Pause tests</button> : null}
        {isAdmin ? (
          <button
            className="btn btn-danger btn-sm"
            disabled={busy !== null}
            onClick={() => window.confirm(`Remove ${t.url}? Its running-app findings are deleted too.`) && act('', 'DELETE', () => toast('Target removed'))}
          >
            <Trash /> Remove
          </button>
        ) : null}
      </div>
    </div>
  );
}

/** Project section: running apps Fortis tests with OWASP ZAP, each verified and authorised first. */
export function StagingTargets({ projectId }: { projectId: string }) {
  const { org } = useSession();
  const isAdmin = org.role === 'owner' || org.role === 'admin';
  const canPause = org.role !== 'viewer';
  const base = `/v1/orgs/${org.id}/projects/${projectId}/targets`;
  const { data, mutate } = useSWR<TargetsResponse>(base, fetcher, { refreshInterval: 30_000 });
  const [adding, setAdding] = useState(false);
  const [authorizing, setAuthorizing] = useState<StagingTarget | null>(null);
  const dast = data?.plan.dast ?? 'none';

  return (
    <section className="card reveal" style={{ ['--d' as string]: '280ms' }}>
      <div className="card-head">
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          Staging targets
          <InfoTip text="Fortis runs OWASP ZAP against your running app. Baseline mode only watches traffic (no attacks); full mode simulates attacks. Every target needs a verified domain and a signed authorisation, and can be paused at any time." />
        </h3>
        {isAdmin && dast !== 'none' ? <button className="btn btn-outline btn-sm" onClick={() => setAdding(true)}><Plus /> Add target</button> : null}
      </div>
      {dast === 'none' && data ? (
        <Empty
          icon={<Lock />}
          title="Running-app tests need Fortis Core"
          text={`${data.plan.name} covers code checks. Core adds OWASP ZAP baseline tests on up to 2 staging targets; Plus adds full active scans.`}
        />
      ) : data && data.targets.length === 0 ? (
        <Empty
          icon={<Target />}
          title="No targets yet"
          text="Add your staging URL to test the running app for missing headers, cookie flags, exposed data and, on Plus, injection flaws."
          action={isAdmin ? <button className="btn btn-primary" onClick={() => setAdding(true)}><Plus /> Add target</button> : undefined}
        />
      ) : (
        <div className="targets">
          {(data?.targets ?? []).map((t) => (
            <TargetCard key={t.id} t={t} base={base} isAdmin={isAdmin} canPause={canPause} dast={dast} onChange={() => mutate()} onAuthorize={() => setAuthorizing(t)} />
          ))}
          {data && data.plan.maxTargets !== null ? (
            <p className="small" style={{ margin: 0 }}>{data.plan.name}: {dast === 'full' ? 'baseline and full scans' : 'baseline scans'} · up to {data.plan.maxTargets} target{data.plan.maxTargets === 1 ? '' : 's'} across the workspace.</p>
          ) : null}
        </div>
      )}
      {adding ? <AddTarget base={base} onClose={() => setAdding(false)} onDone={() => mutate()} /> : null}
      {authorizing && data ? (
        <Authorize base={base} t={authorizing} text={data.authorization.text} onClose={() => setAuthorizing(null)} onDone={() => mutate()} />
      ) : null}
    </section>
  );
}
