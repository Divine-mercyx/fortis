'use client';

import { useState } from 'react';
import useSWR from 'swr';

import { PLANS, PLAN_IDS } from '@fortis/shared';

import { Check, Plus, Users } from '@/components/icons';
import { Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { Empty, FormError, Modal, Skeleton, useToast } from '@/components/ui';
import { api, fetcher } from '@/lib/api';
import { dateTime, initials, naira, timeAgo } from '@/lib/format';

type OrgInfo = { org: { id: string; name: string; plan: string }; role: string; plan: { id: string; name: string; maxProjects: number | null; maxSeats: number | null }; usage: { projects: number; seats: number } };
type Member = { userId: string; name: string; email: string; role: string; joinedAt: string };
type AuditEntry = { id: number; action: string; targetType: string | null; meta: Record<string, unknown> | null; ip: string | null; createdAt: string; actor: string | null };

const ROLE_TEXT: Record<string, string> = {
  owner: 'Full control, including billing',
  admin: 'Projects, keys and members',
  developer: 'Triage and fix findings',
  viewer: 'Read-only',
};

function AddMember({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const { org } = useSession();
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api(`/v1/orgs/${org.id}/members`, { method: 'POST', body: { email: f.get('email'), role: f.get('role') } });
      toast('Teammate added');
      onAdded();
      onClose();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }
  return (
    <Modal title="Add a teammate" lead="They need a Fortis account first. Invitations by email are coming soon." onClose={onClose}>
      <form onSubmit={onSubmit}>
        <FormError message={error} />
        <label className="field"><span>Work email</span><input className="input" name="email" type="email" required autoFocus placeholder="teammate@company.com" /></label>
        <label className="field">
          <span>Role</span>
          <select className="select" name="role" defaultValue="developer">
            {['admin', 'developer', 'viewer'].map((r) => <option key={r} value={r}>{r[0]!.toUpperCase() + r.slice(1)} · {ROLE_TEXT[r]}</option>)}
          </select>
        </label>
        <div className="modal-actions">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy}>{busy ? <span className="spinner" /> : null} Add teammate</button>
        </div>
      </form>
    </Modal>
  );
}

export default function SettingsPage() {
  const { org, user, refresh } = useSession();
  const toast = useToast();
  const isAdmin = org.role === 'owner' || org.role === 'admin';
  const { data: info, mutate: refreshInfo } = useSWR<OrgInfo>(`/v1/orgs/${org.id}`, fetcher);
  const { data: members, mutate: refreshMembers } = useSWR<{ members: Member[] }>(`/v1/orgs/${org.id}/members`, fetcher);
  const { data: auditLog } = useSWR<{ entries: AuditEntry[] }>(isAdmin ? `/v1/orgs/${org.id}/audit` : null, fetcher);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function saveName(e: React.FormEvent) {
    e.preventDefault();
    if (!name) return;
    setSaving(true);
    try {
      await api(`/v1/orgs/${org.id}`, { method: 'PATCH', body: { name } });
      toast('Workspace renamed');
      await Promise.all([refresh(), refreshInfo()]);
      setName(null);
    } catch (err) {
      toast((err as Error).message, true);
    } finally {
      setSaving(false);
    }
  }

  async function remove(m: Member) {
    if (!window.confirm(`Remove ${m.name} from ${org.name}?`)) return;
    try {
      await api(`/v1/orgs/${org.id}/members/${m.userId}`, { method: 'DELETE' });
      toast('Teammate removed');
      refreshMembers();
      refreshInfo();
    } catch (err) {
      toast((err as Error).message, true);
    }
  }

  const limit = (n: number | null) => (n === null ? 'Unlimited' : String(n));

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <span className="eyebrow reveal">Settings</span>
          <h1 className="display"><Words>Your <span className="it accent">workspace.</span></Words></h1>
        </div>
      </div>

      <div className="grid-2">
        <section className="card reveal">
          <div className="card-head"><h3>Workspace</h3></div>
          <form className="card-pad" onSubmit={saveName}>
            <label className="field">
              <span>Name</span>
              <input className="input" value={name ?? org.name} onChange={(e) => setName(e.target.value)} disabled={!isAdmin} minLength={2} />
            </label>
            <dl className="kv">
              <dt>Your role</dt><dd style={{ textTransform: 'capitalize' }}>{org.role}</dd>
              <dt>Signed in as</dt><dd>{user.email}</dd>
              <dt>Workspace ID</dt><dd className="mono">{org.slug}</dd>
            </dl>
            {isAdmin ? <button className="btn btn-primary" disabled={!name || name === org.name || saving}>{saving ? <span className="spinner" /> : null} Save</button> : null}
          </form>
        </section>

        <section className="card reveal" style={{ ['--d' as string]: '80ms' }}>
          <div className="card-head"><h3>Plan and usage</h3><span className="pill p-ok">{org.planName}</span></div>
          <div className="card-pad">
            {info ? (
              <div className="sev-bars">
                {[
                  { lbl: 'Projects', used: info.usage.projects, max: info.plan.maxProjects },
                  { lbl: 'Seats', used: info.usage.seats, max: info.plan.maxSeats },
                ].map((u) => (
                  <div key={u.lbl}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, fontWeight: 700, color: 'var(--ink)', marginBottom: 6 }}>
                      <span>{u.lbl}</span><span>{u.used} / {limit(u.max)}</span>
                    </div>
                    <div className="sev-track"><i style={{ ['--w' as string]: u.max ? `${Math.min(100, (u.used / u.max) * 100)}%` : '8%', background: 'var(--green)' }} /></div>
                  </div>
                ))}
              </div>
            ) : <Skeleton h={70} />}
            <p className="small" style={{ margin: '20px 0 0' }}>Paying in naira by card or transfer is coming soon. To change plan during early access, email hello@fortis.dev.</p>
          </div>
        </section>
      </div>

      <section className="card reveal" style={{ ['--d' as string]: '120ms' }}>
        <div className="card-head"><h3>Plans</h3><span className="small">Monthly, excluding VAT</span></div>
        <div className="card-pad" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 14 }}>
          {PLAN_IDS.map((id) => {
            const p = PLANS[id];
            const current = id === org.plan;
            return (
              <div key={id} className="tile" style={{ ['--c' as string]: current ? 'var(--green)' : 'transparent', background: id === 'plus' ? 'var(--navy)' : '#fff', borderColor: id === 'plus' ? 'var(--navy)' : undefined }}>
                <div className="lbl" style={{ color: id === 'plus' ? 'var(--mint)' : undefined }}>{p.name}{current ? ' · current' : ''}</div>
                <div className="v" style={{ fontSize: 26, color: id === 'plus' ? '#fff' : undefined }}>
                  {id === 'enterprise' ? `from ${naira(p.monthlyPriceKobo)}` : naira(p.monthlyPriceKobo)}
                </div>
                <ul style={{ listStyle: 'none', padding: 0, margin: '12px 0 0', fontSize: 13, color: id === 'plus' ? '#D3DBEA' : 'var(--ink-2)', display: 'grid', gap: 6 }}>
                  <li>{limit(p.maxProjects)} projects · {limit(p.maxSeats)} seats</li>
                  <li>{p.rulePacks.includes('fintech') ? 'Fintech rule pack' : 'Secrets and dependencies'}</li>
                  <li>{p.dashboard ? 'Findings dashboard' : 'Results stay local'}</li>
                  {p.dast !== 'none' ? <li>OWASP ZAP {p.dast === 'full' ? 'baseline + full scans' : 'baseline scans'} · {limit(p.maxTargets)} targets</li> : null}
                  {p.releaseGates ? <li>Release gates</li> : null}
                </ul>
              </div>
            );
          })}
        </div>
      </section>

      <section className="card reveal" style={{ ['--d' as string]: '160ms' }}>
        <div className="card-head">
          <h3>Team</h3>
          {isAdmin ? <button className="btn btn-outline btn-sm" onClick={() => setAdding(true)}><Plus /> Add teammate</button> : null}
        </div>
        {members && members.members.length === 0 ? (
          <Empty icon={<Users />} title="Just you" text="Add teammates so they can triage findings." />
        ) : (
          <ul className="list">
            {(members?.members ?? []).map((m, i) => (
              <li key={m.userId} className="row-in" style={{ ['--i' as string]: i }}>
                <span className="ic" style={{ borderRadius: '50%', background: 'var(--navy)', color: '#fff', fontWeight: 800, fontSize: 12 }}>{initials(m.name)}</span>
                <span style={{ minWidth: 0 }}>
                  <strong style={{ color: 'var(--ink)' }}>{m.name}{m.userId === user.id ? ' (you)' : ''}</strong>
                  <span className="small" style={{ display: 'block' }}>{m.email}</span>
                </span>
                <span className="meta" style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                  <span className="pill p-mute">{m.role}</span>
                  {isAdmin && m.userId !== user.id ? <button className="btn btn-danger btn-sm" onClick={() => remove(m)}>Remove</button> : null}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {isAdmin ? (
        <section id="audit" className="card reveal" style={{ ['--d' as string]: '200ms' }}>
          <div className="card-head"><h3>Audit log</h3><span className="small">Last 100 actions</span></div>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Action</th><th>By</th><th>When</th><th>IP</th></tr></thead>
              <tbody>
                {(auditLog?.entries ?? []).map((e, i) => (
                  <tr key={e.id} className="row-in" style={{ ['--i' as string]: Math.min(i, 12) }}>
                    <td><Check style={{ display: 'inline', width: 14, height: 14, color: 'var(--green)', marginRight: 8, verticalAlign: -2 }} /><span className="mono">{e.action}</span></td>
                    <td>{e.actor ?? 'Fortis'}</td>
                    <td className="muted" title={dateTime(e.createdAt)}>{timeAgo(e.createdAt)}</td>
                    <td className="mono muted">{e.ip ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {adding ? <AddMember onClose={() => setAdding(false)} onAdded={() => { refreshMembers(); refreshInfo(); }} /> : null}
    </div>
  );
}
