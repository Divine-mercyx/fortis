'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useEffect, useState } from 'react';
import useSWR from 'swr';

import { controlsFor, fixFor, FRAMEWORKS } from '@fortis/shared';

import { Alert, Check, Search, Shield } from '@/components/icons';
import { Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { CloseButton, Drawer, Empty, FormError, SecretTag, SeverityPill, Skeleton, StatusTag, useToast } from '@/components/ui';
import { api, fetcher } from '@/lib/api';
import { dateTime, STATUS_LABEL, timeAgo } from '@/lib/format';
import type { FindingRow, ProjectRow } from '@/lib/types';

type FindingDetail = {
  finding: FindingRow & { snippet: string | null; detail: string | null; statusReason: string | null; projectName: string; secretCheckedAt?: string | null };
  rule: { id: string; title: string; summary: string; fix: string } | null;
  events: { id: number; type: string; fromStatus: string | null; toStatus: string | null; reason: string | null; actor: string | null; createdAt: string }[];
};

const EVENT_TEXT: Record<string, { label: string; c: string }> = {
  detected: { label: 'Detected by a scan', c: 'var(--red)' },
  reopened: { label: 'Came back in a later scan', c: 'var(--red)' },
  fixed: { label: 'Fixed', c: 'var(--green)' },
  status_changed: { label: 'Status changed', c: 'var(--blue)' },
};

function FindingDrawer({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { org } = useSession();
  const toast = useToast();
  const { data, mutate } = useSWR<FindingDetail>(`/v1/orgs/${org.id}/findings/${id}`, fetcher);
  const [mode, setMode] = useState<null | 'accepted_risk' | 'false_positive'>(null);
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canEdit = org.role !== 'viewer';

  async function setStatus(status: string, why?: string) {
    setBusy(true);
    setError(null);
    try {
      await api(`/v1/orgs/${org.id}/findings/${id}`, { method: 'PATCH', body: { status, reason: why || undefined } });
      toast(`Marked as ${STATUS_LABEL[status]?.toLowerCase()}`);
      setMode(null);
      setReason('');
      await mutate();
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const f = data?.finding;
  return (
    <Drawer onClose={onClose}>
      <div className="drawer-head">
        <div style={{ minWidth: 0 }}>
          {f ? (
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
              <SeverityPill severity={f.severity} />
              <span className="mono muted">{f.ruleId}</span>
              <StatusTag status={f.status} />
              <SecretTag status={f.secretStatus} />
            </div>
          ) : null}
          <h3>{f ? f.title : <Skeleton h={22} w={280} />}</h3>
        </div>
        <CloseButton onClick={onClose} />
      </div>
      <div className="drawer-body">
        {!data || !f ? (
          <div className="stack"><Skeleton h={90} /><Skeleton h={60} /><Skeleton h={120} /></div>
        ) : (
          <>
            <dl className="kv">
              <dt>Project</dt><dd>{f.projectName}</dd>
              <dt>Source</dt><dd>{f.kind === 'dast' ? 'Running app · ZAP' : f.kind === 'access' ? 'Access check · two test users' : 'Code scan'}</dd>
              <dt>{f.kind === 'dast' ? 'URL path' : f.kind === 'access' ? 'Endpoint' : 'Location'}</dt><dd className="mono">{f.file}{f.line ? `:${f.line}` : ''}</dd>
              <dt>First seen</dt><dd>{dateTime(f.firstSeenAt)}</dd>
              <dt>Last seen</dt><dd>{timeAgo(f.lastSeenAt)}</dd>
              {f.statusReason ? (<><dt>Reason</dt><dd>{f.statusReason}</dd></>) : null}
              {f.secretStatus ? (<><dt>Key</dt><dd><SecretTag status={f.secretStatus} />{f.secretCheckedAt ? <span className="muted"> · checked {timeAgo(f.secretCheckedAt)} with fortis scan --verify</span> : null}</dd></>) : null}
            </dl>
            <div className="ctl-chips" aria-label="Compliance controls">
              {controlsFor(f.ruleId).map((ctl) => <span key={`${ctl.framework}-${ctl.ref}`} title={ctl.title}>{FRAMEWORKS[ctl.framework].short} {ctl.framework === 'cbn' ? `· ${ctl.ref}` : ctl.ref}</span>)}
            </div>
            {f.snippet ? <div className="snippet">{f.snippet}</div> : null}
            {data.rule ? (
              <div className="rule-box">
                <h4>Why it matters</h4>
                <p>{data.rule.summary}</p>
                <h4>How to fix it</h4>
                {/* Code findings can carry advice for this exact finding, such as the version to upgrade to. */}
                <p>{f.kind === 'code' && f.detail ? f.detail : fixFor(data.rule, f.file)}</p>
              </div>
            ) : f.detail ? (
              <div className="rule-box">
                <h4>{f.kind === 'access' ? 'What the access check found' : 'What ZAP found'}</h4>
                <p className="detail-text">{f.detail}</p>
              </div>
            ) : null}
            <h4 className="eyebrow" style={{ color: 'var(--muted)' }}>Evidence trail</h4>
            <ul className="timeline">
              {data.events.map((e, i) => {
                const meta = EVENT_TEXT[e.type] ?? { label: e.type, c: 'var(--muted)' };
                return (
                  <li key={e.id} style={{ ['--i' as string]: i, ['--c' as string]: meta.c }}>
                    <strong>
                      {e.type === 'status_changed' ? `Marked ${STATUS_LABEL[e.toStatus ?? '']?.toLowerCase()}` : meta.label}
                    </strong>
                    {e.actor ? ` by ${e.actor}` : ''}
                    <small>{dateTime(e.createdAt)}{e.reason ? ` · ${e.reason}` : ''}</small>
                  </li>
                );
              })}
            </ul>
            {mode ? (
              <div style={{ marginTop: 10 }}>
                <FormError message={error} />
                <label className="field">
                  <span>{mode === 'accepted_risk' ? 'Why is this risk acceptable?' : 'Why is this a false positive?'}</span>
                  <textarea className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="This reason is kept in the evidence trail." autoFocus />
                </label>
              </div>
            ) : (
              <FormError message={error} />
            )}
          </>
        )}
      </div>
      {f && canEdit ? (
        <div className="drawer-foot">
          {mode ? (
            <>
              <button className="btn btn-primary" disabled={busy || reason.trim().length < 3} onClick={() => setStatus(mode, reason)}>
                {busy ? <span className="spinner" /> : null} Save
              </button>
              <button className="btn btn-outline" onClick={() => setMode(null)}>Cancel</button>
            </>
          ) : f.status === 'open' ? (
            <>
              <button className="btn btn-primary" disabled={busy} onClick={() => setStatus('fixed')}><Check /> Mark fixed</button>
              <button className="btn btn-outline" disabled={busy} onClick={() => setMode('accepted_risk')}>Accept risk</button>
              <button className="btn btn-outline" disabled={busy} onClick={() => setMode('false_positive')}>False positive</button>
            </>
          ) : (
            <button className="btn btn-outline" disabled={busy} onClick={() => setStatus('open')}>Reopen</button>
          )}
        </div>
      ) : null}
    </Drawer>
  );
}

/** How long a finding has been (or was) open, coloured by urgency. */
function AgeTag({ from, to }: { from: string; to: string | null }) {
  const days = Math.max(0, Math.floor(((to ? new Date(to) : new Date()).getTime() - new Date(from).getTime()) / 86_400_000));
  const text = days === 0 ? 'Today' : `${days} day${days === 1 ? '' : 's'}`;
  const tone = to ? 'muted' : days > 14 ? 'age-red' : days > 3 ? 'age-amber' : 'age-ok';
  return <span className={`age ${tone}`} title={to ? 'Time it was open' : 'Open for'}>{text}</span>;
}

function FindingsInner() {
  const { org } = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const status = params.get('status') ?? 'open';
  const severity = params.get('severity') ?? '';
  const projectId = params.get('projectId') ?? '';
  const [q, setQ] = useState(params.get('q') ?? '');
  const [debounced, setDebounced] = useState(q);
  const [selected, setSelected] = useState<string | null>(params.get('id'));

  useEffect(() => {
    const t = setTimeout(() => setDebounced(q), 250);
    return () => clearTimeout(t);
  }, [q]);

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    router.replace(`/findings?${next.toString()}`, { scroll: false });
  };

  const query = new URLSearchParams();
  if (status !== 'all') query.set('status', status);
  if (severity) query.set('severity', severity);
  if (projectId) query.set('projectId', projectId);
  if (debounced) query.set('q', debounced);
  query.set('limit', '100');
  const key = `/v1/orgs/${org.id}/findings?${query.toString()}`;
  const { data, mutate } = useSWR<{ findings: FindingRow[]; total: number }>(key, fetcher, { keepPreviousData: true });
  const { data: projects } = useSWR<{ projects: ProjectRow[] }>(`/v1/orgs/${org.id}/projects`, fetcher);
  const { data: summary } = useSWR<{ open: Record<string, number> }>(`/v1/orgs/${org.id}/overview`, fetcher);

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <span className="eyebrow reveal">Findings</span>
          <h1 className="display"><Words>Every issue, <span className="it accent">one list.</span></Words></h1>
          <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>From pre-push checks and CI, de-duplicated, with the full history of each fix.</p>
        </div>
      </div>

      <div className="sev-chips reveal" style={{ ['--d' as string]: '180ms' }}>
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
          <button
            key={s}
            className={`sev-chip c-${s}${severity === s ? ' on' : ''}`}
            onClick={() => setParam('severity', severity === s ? '' : s)}
          >
            <b>{summary ? summary.open[s] ?? 0 : '–'}</b>
            <span>open {s}</span>
            <small>{s === 'critical' ? 'Blocks the push' : s === 'high' ? 'Fix this sprint' : s === 'medium' ? 'Plan a fix' : 'Hygiene'}</small>
          </button>
        ))}
      </div>

      <section className="card reveal" style={{ ['--d' as string]: '200ms' }}>
        <div className="toolbar">
          <label className="search">
            <Search />
            <span className="sr-only" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden' }}>Search findings</span>
            <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, file or rule" />
          </label>
          <div className="seg" role="group" aria-label="Status">
            {['open', 'fixed', 'accepted_risk', 'false_positive', 'all'].map((s) => (
              <button key={s} className={status === s ? 'on' : ''} onClick={() => setParam('status', s === 'open' ? '' : s)}>
                {s === 'all' ? 'All' : STATUS_LABEL[s]}
              </button>
            ))}
          </div>
          <select className="select" value={severity} onChange={(e) => setParam('severity', e.target.value)} aria-label="Severity">
            <option value="">All severities</option>
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s} value={s}>{s[0]!.toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select className="select" value={projectId} onChange={(e) => setParam('projectId', e.target.value)} aria-label="Project">
            <option value="">All projects</option>
            {(projects?.projects ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <span className="small" style={{ marginLeft: 'auto' }}>{data ? `${data.total} finding${data.total === 1 ? '' : 's'}` : ''}</span>
        </div>

        {data && data.findings.length === 0 ? (
          <Empty
            icon={status === 'open' ? <Shield /> : <Alert />}
            title={status === 'open' && !debounced && !severity ? 'No open findings' : 'Nothing matches'}
            text={status === 'open' && !debounced && !severity ? 'Every check is passing. New issues from pushes and CI runs will appear here.' : 'Try a different filter or search.'}
          />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Severity</th><th>Finding</th><th>Status</th><th>Project</th><th>Age</th><th>Last seen</th></tr>
              </thead>
              <tbody>
                {(data?.findings ?? Array.from({ length: 5 }, () => null)).map((f, i) =>
                  f ? (
                    <tr key={f.id} className={`click row-in${selected === f.id ? ' sel' : ''}`} style={{ ['--i' as string]: i }} onClick={() => setSelected(f.id)}>
                      <td><SeverityPill severity={f.severity} /></td>
                      <td>
                        <span className="t-title">{f.title}{f.secretStatus ? <> <SecretTag status={f.secretStatus} /></> : null}</span>
                        <span className="t-file">{f.file}{f.line ? `:${f.line}` : ''} · {f.ruleId}</span>
                      </td>
                      <td><StatusTag status={f.status} /></td>
                      <td>{f.projectName}</td>
                      <td><AgeTag from={f.firstSeenAt} to={f.status === 'open' ? null : f.fixedAt} /></td>
                      <td className="muted">{timeAgo(f.lastSeenAt)}</td>
                    </tr>
                  ) : (
                    <tr key={i}><td colSpan={6}><Skeleton h={30} /></td></tr>
                  ),
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selected ? <FindingDrawer id={selected} onClose={() => setSelected(null)} onChanged={() => mutate()} /> : null}
    </div>
  );
}

export default function FindingsPage() {
  return (
    <Suspense>
      <FindingsInner />
    </Suspense>
  );
}
