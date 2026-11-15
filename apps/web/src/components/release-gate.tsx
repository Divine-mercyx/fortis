'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import useSWR from 'swr';

import { Shield } from '@/components/icons';
import { useSession } from '@/components/session';
import { FormError, Modal, Skeleton, useToast } from '@/components/ui';
import { api, fetcher } from '@/lib/api';
import { dateTime, timeAgo } from '@/lib/format';

type Policy = { enabled: boolean; minSeverity: 'critical' | 'high' | 'medium'; blockLiveSecrets: boolean; branches: string };
type Exception = { id: string; reason: string; commit: string | null; createdAt: string; expiresAt: string; lastUsedAt: string | null; by: string | null };
type Run = { scanId: string; at: string; branch: string | null; commit: string | null; status: 'passed' | 'failed' | 'excepted'; blockingCount: number; exception: { reason: string; by: string | null } | null };
type Gate = { available: boolean; policy: Policy; exceptions: Exception[]; runs: Run[] };

const LEVEL: Record<Policy['minSeverity'], string> = { critical: 'Critical findings', high: 'High and critical findings', medium: 'Medium, high and critical findings' };
const VERDICT: Record<Run['status'], { label: string; cls: string }> = {
  passed: { label: 'Passed', cls: 'p-ok' },
  failed: { label: 'Blocked', cls: 'p-critical' },
  excepted: { label: 'Approved', cls: 'p-high' },
};

function Approve({ orgId, projectId, onClose, onDone }: { orgId: string; projectId: string; onClose: () => void; onDone: (g: Gate) => void }) {
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const g = await api<Gate>(`/v1/orgs/${orgId}/projects/${projectId}/gate/exceptions`, { method: 'POST', body: { reason: f.get('reason'), commit: String(f.get('commit') ?? '').trim(), hours: Number(f.get('hours')) } });
      onDone(g);
      toast('Release approved');
      onClose();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }
  return (
    <Modal title="Approve a release through the gate" lead="CI runs pass while this approval lasts, with the open findings listed in the log and the evidence pack. Use it for a release that can't wait for a fix." onClose={onClose}>
      <form onSubmit={onSubmit}>
        <FormError message={error} />
        <label className="field" htmlFor="gate-reason">
          <span>Why can this release go out with the finding open?</span>
          <textarea id="gate-reason" className="textarea" name="reason" required minLength={10} maxLength={500} placeholder="Hotfix for the payout outage. The key is being rotated in OPS-142." autoFocus />
        </label>
        <div className="gate-form-row">
          <label className="field" htmlFor="gate-commit">
            <span>Only this commit (optional)</span>
            <input id="gate-commit" className="input mono" name="commit" pattern="[0-9a-fA-F]{7,40}" placeholder="a1b2c3d" autoComplete="off" spellCheck={false} />
          </label>
          <label className="field" htmlFor="gate-hours">
            <span>For</span>
            <select id="gate-hours" className="select" name="hours" defaultValue="24">
              <option value="1">1 hour</option>
              <option value="4">4 hours</option>
              <option value="24">24 hours</option>
              <option value="72">3 days</option>
            </select>
          </label>
        </div>
        <div className="modal-actions">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy}>{busy ? <span className="spinner" /> : null} Approve release</button>
        </div>
      </form>
    </Modal>
  );
}

/** Project card: the release gate's policy, approvals and recent verdicts. */
export function ReleaseGate({ projectId }: { projectId: string }) {
  const { org } = useSession();
  const toast = useToast();
  const isAdmin = org.role === 'owner' || org.role === 'admin';
  const url = `/v1/orgs/${org.id}/projects/${projectId}/gate`;
  const { data, mutate } = useSWR<Gate>(url, fetcher);
  const [form, setForm] = useState<Policy | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approving, setApproving] = useState(false);

  useEffect(() => {
    if (data && !form) setForm(data.policy);
  }, [data, form]);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!form) return;
    setSaving(true);
    setError(null);
    try {
      const g = await api<Gate>(url, { method: 'PUT', body: form });
      await mutate(g, { revalidate: false });
      setForm(g.policy);
      toast(g.policy.enabled ? 'Release gate saved' : 'Release gate turned off');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function revoke(id: string) {
    try {
      await mutate(await api<Gate>(`${url}/exceptions/${id}`, { method: 'DELETE' }), { revalidate: false });
      toast('Approval withdrawn');
    } catch (err) {
      toast((err as Error).message, true);
    }
  }

  const set = <K extends keyof Policy>(k: K, v: Policy[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));

  return (
    <section className="card reveal" id="release-gate" style={{ ['--d' as string]: '280ms' }}>
      <div className="card-head">
        <h3>Release gate</h3>
        {data?.available ? <span className={`pill ${data.policy.enabled ? 'p-ok' : 'p-mute'}`}>{data.policy.enabled ? 'On' : 'Off'}</span> : null}
      </div>
      {!data || !form ? (
        <div className="card-pad"><Skeleton h={120} /></div>
      ) : !data.available ? (
        <div className="card-pad gate-upsell">
          <span className="ic"><Shield /></span>
          <div>
            <p style={{ margin: 0 }}>Block a release from CI when it has open critical findings, set the rules here instead of in every repository, and approve urgent releases with a reason that goes in the evidence pack.</p>
            <p className="small" style={{ margin: '8px 0 0' }}>Release gates come with Fortis Plus and Enterprise. <Link href="/settings" className="link-arrow">See plans</Link></p>
          </div>
        </div>
      ) : (
        <div className="card-pad gate">
          <form onSubmit={save} className="gate-policy">
            <FormError message={error} />
            <label className="switch">
              <input id="gate-enabled" type="checkbox" checked={form.enabled} disabled={!isAdmin} onChange={(e) => set('enabled', e.target.checked)} />
              <span>Fail CI runs that break this policy</span>
            </label>
            <div className="gate-form-row">
              <label className="field" htmlFor="gate-level">
                <span>Block on open</span>
                <select id="gate-level" className="select" value={form.minSeverity} disabled={!isAdmin} onChange={(e) => set('minSeverity', e.target.value as Policy['minSeverity'])}>
                  {(Object.keys(LEVEL) as Policy['minSeverity'][]).map((k) => <option key={k} value={k}>{LEVEL[k]}</option>)}
                </select>
              </label>
              <label className="field" htmlFor="gate-branches">
                <span>On branches</span>
                <input id="gate-branches" className="input mono" value={form.branches} disabled={!isAdmin} placeholder="All branches (or: main, release/*)" onChange={(e) => set('branches', e.target.value)} spellCheck={false} />
              </label>
            </div>
            <label className="switch">
              <input id="gate-live" type="checkbox" checked={form.blockLiveSecrets} disabled={!isAdmin} onChange={(e) => set('blockLiveSecrets', e.target.checked)} />
              <span>Always block a leaked key that still works (<code className="mono">fortis scan --verify</code>)</span>
            </label>
            <p className="small gate-note">Applies to <code className="mono">fortis scan --ci</code> runs with this project&apos;s key. Findings accepted as a risk or marked false positive never block. Pre-push checks keep each developer&apos;s own threshold.</p>
            {isAdmin ? (
              <div className="gate-actions">
                <button type="button" className="btn btn-outline btn-sm" onClick={() => setApproving(true)}>Approve a release</button>
                <button className="btn btn-primary btn-sm" disabled={saving}>{saving ? <span className="spinner" /> : null} Save</button>
              </div>
            ) : <p className="small gate-note">Owners and admins can change the gate.</p>}
          </form>

          {data.exceptions.length ? (
            <div className="gate-block">
              <h4>Active approvals</h4>
              <ul className="list">
                {data.exceptions.map((x) => (
                  <li key={x.id}>
                    <span style={{ minWidth: 0 }}>
                      <strong style={{ color: 'var(--ink)' }}>{x.reason}</strong>
                      <span className="small" style={{ display: 'block' }}>
                        {x.by ?? 'An admin'} · {x.commit ? `commit ${x.commit.slice(0, 7)}` : 'any commit'} · ends {dateTime(x.expiresAt)}{x.lastUsedAt ? ` · used ${timeAgo(x.lastUsedAt)}` : ''}
                      </span>
                    </span>
                    {isAdmin ? <span className="meta"><button className="btn btn-outline btn-sm" onClick={() => revoke(x.id)}>Withdraw</button></span> : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          <div className="gate-block">
            <h4>Recent CI runs</h4>
            {data.runs.length ? (
              <ul className="list">
                {data.runs.map((r) => (
                  <li key={r.scanId}>
                    <span className={`pill ${VERDICT[r.status].cls}`}>{VERDICT[r.status].label}</span>
                    <span style={{ minWidth: 0 }}>
                      <strong style={{ color: 'var(--ink)' }}>{r.branch ?? 'detached'}{r.commit ? ` · ${r.commit.slice(0, 7)}` : ''}</strong>
                      <span className="small" style={{ display: 'block' }}>
                        {r.status === 'passed' ? 'Nothing at the blocking level' : `${r.blockingCount} open finding${r.blockingCount === 1 ? '' : 's'} at the blocking level`}
                        {r.exception ? ` · approved by ${r.exception.by ?? 'an admin'}: ${r.exception.reason}` : ''}
                      </span>
                    </span>
                    <span className="meta">{timeAgo(r.at)}</span>
                  </li>
                ))}
              </ul>
            ) : <p className="small gate-note">No CI run has been judged yet. Turn the gate on and run <code className="mono">fortis scan --ci</code> in your pipeline.</p>}
          </div>
        </div>
      )}
      {approving ? createPortal(<Approve orgId={org.id} projectId={projectId} onClose={() => setApproving(false)} onDone={(g) => void mutate(g, { revalidate: false })} />, document.body) : null}
    </section>
  );
}
