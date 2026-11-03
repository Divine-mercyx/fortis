'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import useSWR from 'swr';

import { controlsFor, FRAMEWORKS, PROGRAMME_CONTROLS, type FrameworkId } from '@fortis/shared';

import { File, Lock } from '@/components/icons';
import { Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { Empty, SeverityPill, Skeleton } from '@/components/ui';
import { ApiError, fetcher } from '@/lib/api';
import { dateTime, STATUS_LABEL } from '@/lib/format';
import type { ProjectRow } from '@/lib/types';

type EvFinding = {
  id: string; ruleId: string; kind: string; severity: string; title: string; file: string; line: number | null; status: string;
  statusReason: string | null; firstSeenAt: string; fixedAt: string | null; projectName: string;
};
type Evidence = {
  organisation: { name: string; plan: string };
  period: { from: string; to: string };
  level: 'basic' | 'full';
  generatedAt: string;
  generatedBy: string;
  summary: {
    scans: { kind: string; trigger: string; n: number }[];
    openBySeverity: Record<string, number>;
    detected: number;
    fixed: number;
    medianFixSeconds: { severity: string; seconds: number; n: number }[];
  };
  findings: EvFinding[];
  decisions: { at: string; decision: string; reason: string | null; by: string | null; title: string; ruleId: string; severity: string }[];
  trail: { at: string; type: string; from: string | null; to: string | null; reason: string | null; by: string | null; ruleId: string; title: string }[];
  authorisations: { url: string; environment: string; verifiedAt: string | null; signer: string | null; version: string | null; authorizedAt: string | null; pausedAt: string | null; lastRunAt: string | null; projectName: string }[];
  adminLog: { at: string; action: string; by: string | null }[];
  digest: string;
};

const PERIODS = [
  { days: 30, label: 'Last 30 days' },
  { days: 90, label: 'Last quarter' },
  { days: 365, label: 'Last 12 months' },
];

const KIND: Record<string, string> = { code: 'Code scans', dast: 'Running-app tests (ZAP)', access: 'Access checks' };
const TRIGGER: Record<string, string> = { 'pre-push': 'pre-push', ci: 'CI', manual: 'manual' };
const day = (v: string | null) => (v ? new Date(v).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : '—');

function duration(seconds: number | undefined) {
  if (seconds === undefined || seconds === null) return '—';
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} min`;
  if (seconds < 86_400 * 2) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86_400)} days`;
}

export default function EvidencePage() {
  const { org } = useSession();
  const [days, setDays] = useState(90);
  const [projectId, setProjectId] = useState('');
  const [to] = useState(() => new Date());
  const from = useMemo(() => new Date(to.getTime() - days * 86_400_000), [to, days]);
  const qs = new URLSearchParams({ from: from.toISOString(), to: to.toISOString(), ...(projectId ? { projectId } : {}) });
  const { data, error } = useSWR<Evidence>(`/v1/orgs/${org.id}/evidence?${qs}`, fetcher);
  const { data: projects } = useSWR<{ projects: ProjectRow[] }>(`/v1/orgs/${org.id}/projects`, fetcher);

  const coverage = useMemo(() => {
    const out: Record<FrameworkId, Map<string, { title: string; total: number; open: number; fixed: number; programme?: string }>> = { pci: new Map(), cbn: new Map(), ndpa: new Map() };
    for (const p of PROGRAMME_CONTROLS) out[p.control.framework].set(p.control.ref, { title: p.control.title, total: 0, open: 0, fixed: 0, programme: p.evidence });
    for (const f of data?.findings ?? []) {
      for (const ctl of controlsFor(f.ruleId)) {
        const row = out[ctl.framework].get(ctl.ref) ?? { title: ctl.title, total: 0, open: 0, fixed: 0 };
        row.total++;
        if (f.status === 'open') row.open++;
        if (f.status === 'fixed') row.fixed++;
        out[ctl.framework].set(ctl.ref, row);
      }
    }
    return out;
  }, [data]);

  if (error instanceof ApiError && error.status === 402) {
    return (
      <section className="card">
        <Empty icon={<Lock />} title="Evidence packs come with Fortis Core" text="Core adds a summary pack for auditors; Plus adds the full event trail, staging-test authorisations and the admin log." action={<Link href="/settings" className="btn btn-primary">See plans</Link>} />
      </section>
    );
  }

  const fixMedian = (sev: string) => data?.summary.medianFixSeconds.find((m) => m.severity === sev)?.seconds;
  const scansTotal = (data?.summary.scans ?? []).reduce((n, s) => n + s.n, 0);

  return (
    <div className="stack">
      <div className="page-head no-print">
        <div>
          <span className="eyebrow reveal">For auditors and compliance</span>
          <h1 className="display"><Words>Evidence, <span className="it accent">ready to hand over.</span></Words></h1>
          <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>
            What was checked, found, fixed and decided, mapped to PCI DSS, the CBN cybersecurity framework and the NDPA.
          </p>
        </div>
        <div className="ev-controls reveal" style={{ ['--d' as string]: '200ms' }}>
          <select className="select" value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Period">
            {PERIODS.map((p) => <option key={p.days} value={p.days}>{p.label}</option>)}
          </select>
          <select className="select" value={projectId} onChange={(e) => setProjectId(e.target.value)} aria-label="Project">
            <option value="">All projects</option>
            {(projects?.projects ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <button className="btn btn-primary" disabled={!data} onClick={() => window.print()}><File /> Download PDF</button>
        </div>
      </div>

      {!data ? (
        <section className="card card-pad"><Skeleton h={40} w="60%" /><div style={{ height: 16 }} /><Skeleton h={180} /></section>
      ) : (
        <article className="report">
          <header className="rp-cover">
            <div className="rp-brand">
              {/* Solid colours: the shared logo's gradient lives in the sidebar, which print hides. */}
              <svg viewBox="0 0 100 115" aria-hidden="true"><path d="M50 3 L93 19 V56 C93 83 74 101 50 112 C26 101 7 83 7 56 V19 Z" fill="#0E7A55" /><path d="M30 57 L45 72 L72 43" fill="none" stroke="#fff" strokeWidth="9" strokeLinecap="round" strokeLinejoin="round" /></svg>
              <span>Fortis</span>
            </div>
            <h2>Security evidence pack</h2>
            <p className="rp-org">{data.organisation.name}{projectId ? ` · ${projects?.projects.find((p) => p.id === projectId)?.name ?? ''}` : ''}</p>
            <dl className="rp-meta">
              <dt>Period</dt><dd>{day(data.period.from)} – {day(data.period.to)}</dd>
              <dt>Generated</dt><dd>{dateTime(data.generatedAt)} by {data.generatedBy}</dd>
              <dt>Plan</dt><dd>{data.organisation.plan} · {data.level === 'full' ? 'full pack' : 'summary pack'}</dd>
              <dt>Integrity</dt><dd className="mono">SHA-256 {data.digest.slice(0, 16)}…</dd>
            </dl>
          </header>

          <section className="rp-section">
            <h3>1. Summary</h3>
            <div className="rp-tiles">
              <div><b>{scansTotal}</b><span>scans and tests run</span></div>
              <div><b>{data.summary.detected}</b><span>issues found</span></div>
              <div><b>{data.summary.fixed}</b><span>issues fixed</span></div>
              <div className={data.summary.openBySeverity.critical ? 'bad' : ''}><b>{data.summary.openBySeverity.critical ?? 0}</b><span>critical open today</span></div>
              <div><b>{duration(fixMedian('critical'))}</b><span>median time to fix a critical</span></div>
            </div>
            <table className="rp-table">
              <thead><tr><th>Check</th><th>Trigger</th><th className="num">Runs</th></tr></thead>
              <tbody>
                {data.summary.scans.length ? data.summary.scans.map((s) => (
                  <tr key={`${s.kind}-${s.trigger}`}><td>{KIND[s.kind] ?? s.kind}</td><td>{TRIGGER[s.trigger] ?? s.trigger}</td><td className="num">{s.n}</td></tr>
                )) : <tr><td colSpan={3} className="muted">No scans in this period.</td></tr>}
              </tbody>
            </table>
          </section>

          <section className="rp-section">
            <h3>2. Compliance coverage</h3>
            <p className="rp-note">Each finding is evidence for the controls below. Programme rows describe what Fortis does continuously, whatever it finds.</p>
            {(Object.keys(FRAMEWORKS) as FrameworkId[]).map((fw) => (
              <div key={fw} className="rp-fw">
                <h4>{FRAMEWORKS[fw].name}</h4>
                <table className="rp-table">
                  <thead><tr><th style={{ width: '22%' }}>{fw === 'cbn' ? 'Domain' : fw === 'ndpa' ? 'Section' : 'Requirement'}</th><th>What it covers</th><th className="num">Found</th><th className="num">Open</th><th className="num">Fixed</th></tr></thead>
                  <tbody>
                    {[...coverage[fw].entries()].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true })).map(([ref, r]) => (
                      <tr key={ref}>
                        <td className="t-strong">{ref}</td>
                        <td>{fw === 'cbn' ? null : r.title}{r.programme ? <span className={fw === 'cbn' ? 'rp-prog rp-prog-only' : 'rp-prog'}>Programme: {r.programme}</span> : fw === 'cbn' ? <span className="rp-sub">Evidence from the findings in this domain</span> : null}</td>
                        <td className="num">{r.total}</td>
                        <td className={`num${r.open ? ' bad' : ''}`}>{r.open}</td>
                        <td className="num">{r.fixed}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </section>

          <section className="rp-section">
            <h3>3. Findings in the period ({data.findings.length})</h3>
            <table className="rp-table rp-findings">
              <thead><tr><th>Severity</th><th>Finding</th><th>Controls</th><th>Status</th><th>Found</th><th>Fixed</th></tr></thead>
              <tbody>
                {data.findings.length ? data.findings.map((f) => (
                  <tr key={f.id}>
                    <td><SeverityPill severity={f.severity} /></td>
                    <td><span className="t-strong">{f.title}</span><span className="rp-sub">{f.ruleId} · {f.projectName} · {f.file}{f.line ? `:${f.line}` : ''}</span></td>
                    <td className="rp-ctl">{[...new Set(controlsFor(f.ruleId).filter((ctl) => ctl.framework !== 'cbn').map((ctl) => `${FRAMEWORKS[ctl.framework].short} ${ctl.ref}`))].join(', ')}</td>
                    <td>{STATUS_LABEL[f.status] ?? f.status}{f.statusReason ? <span className="rp-sub">{f.statusReason}</span> : null}</td>
                    <td>{day(f.firstSeenAt)}</td>
                    <td>{day(f.fixedAt)}</td>
                  </tr>
                )) : <tr><td colSpan={6} className="muted">Nothing was found in this period.</td></tr>}
              </tbody>
            </table>
          </section>

          <section className="rp-section">
            <h3>4. Risk decisions</h3>
            <p className="rp-note">Findings a person accepted as a risk or marked as a false positive, with their reason.</p>
            <table className="rp-table">
              <thead><tr><th>Date</th><th>Decision</th><th>Finding</th><th>By</th><th>Reason</th></tr></thead>
              <tbody>
                {data.decisions.length ? data.decisions.map((d, i) => (
                  <tr key={i}><td>{day(d.at)}</td><td>{STATUS_LABEL[d.decision] ?? d.decision}</td><td>{d.title}<span className="rp-sub">{d.ruleId}</span></td><td>{d.by ?? '—'}</td><td>{d.reason ?? '—'}</td></tr>
                )) : <tr><td colSpan={5} className="muted">No risk decisions in this period.</td></tr>}
              </tbody>
            </table>
          </section>

          {data.level === 'full' ? (
            <>
              <section className="rp-section">
                <h3>5. Staging test authorisations</h3>
                <table className="rp-table">
                  <thead><tr><th>Target</th><th>Domain verified</th><th>Authorised by</th><th>Status</th><th>Last test</th></tr></thead>
                  <tbody>
                    {data.authorisations.length ? data.authorisations.map((t) => (
                      <tr key={t.url}>
                        <td><span className="t-strong">{t.url}</span><span className="rp-sub">{t.projectName} · {t.environment}</span></td>
                        <td>{day(t.verifiedAt)}</td>
                        <td>{t.signer ? `${t.signer}, ${day(t.authorizedAt)}` : '—'}{t.version ? <span className="rp-sub">wording v{t.version}</span> : null}</td>
                        <td>{t.pausedAt ? 'Paused' : t.authorizedAt ? 'Active' : 'Not authorised'}</td>
                        <td>{day(t.lastRunAt)}</td>
                      </tr>
                    )) : <tr><td colSpan={5} className="muted">No staging targets.</td></tr>}
                  </tbody>
                </table>
              </section>
              <section className="rp-section">
                <h3>6. Evidence trail ({data.trail.length} events)</h3>
                <table className="rp-table rp-compact">
                  <thead><tr><th>When</th><th>Event</th><th>Finding</th><th>By</th></tr></thead>
                  <tbody>
                    {data.trail.map((e, i) => (
                      <tr key={i}><td>{dateTime(e.at)}</td><td>{e.type.replace('_', ' ')}{e.to ? ` → ${STATUS_LABEL[e.to] ?? e.to}` : ''}{e.reason ? <span className="rp-sub">{e.reason}</span> : null}</td><td>{e.title}<span className="rp-sub">{e.ruleId}</span></td><td>{e.by ?? 'Fortis'}</td></tr>
                    ))}
                  </tbody>
                </table>
              </section>
              <section className="rp-section">
                <h3>7. Administrative changes ({data.adminLog.length})</h3>
                <table className="rp-table rp-compact">
                  <thead><tr><th>When</th><th>Action</th><th>By</th></tr></thead>
                  <tbody>
                    {data.adminLog.map((a, i) => <tr key={i}><td>{dateTime(a.at)}</td><td>{a.action}</td><td>{a.by ?? '—'}</td></tr>)}
                  </tbody>
                </table>
              </section>
            </>
          ) : (
            <section className="rp-section no-print">
              <p className="rp-note">Fortis Plus adds the full evidence trail, staging-test authorisations and the admin change log to this pack.</p>
            </section>
          )}

          <footer className="rp-foot">
            <p>Control mappings are guidance for auditors and compliance officers, not legal advice. Confirm them against your own control framework.</p>
            <p className="mono">SHA-256 of this pack&apos;s content: {data.digest}</p>
          </footer>
        </article>
      )}
    </div>
  );
}
