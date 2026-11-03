'use client';

import Link from 'next/link';
import useSWR from 'swr';

import { Alert, Arrow, Check, Folder, Git, Key, Pulse, Shield, Users } from '@/components/icons';
import { CountUp, Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { Empty, SeverityPill, Skeleton } from '@/components/ui';
import { fetcher } from '@/lib/api';
import { timeAgo } from '@/lib/format';
import type { ScanRow } from '@/lib/types';

type Overview = {
  open: Record<string, number>;
  openTotal: number;
  trend: { day: string; detected: number; fixed: number }[];
  totals: { scans30d: number; prePush30d: number; fixed30d: number; projects: number };
  medianCriticalFixHours: number | null;
  recentActivity: { action: string; targetType: string | null; createdAt: string; actor: string | null }[];
};

const SEV_COLOURS: Record<string, string> = { critical: 'var(--red)', high: 'var(--amber)', medium: '#2B5FD9', low: '#9AA6BD' };

const ACTIVITY: Record<string, { label: string; icon: typeof Key }> = {
  'org.created': { label: 'Workspace created', icon: Shield },
  'project.created': { label: 'Project added', icon: Folder },
  'project.deleted': { label: 'Project deleted', icon: Folder },
  'token.created': { label: 'CLI key created', icon: Key },
  'token.revoked': { label: 'CLI key revoked', icon: Key },
  'member.added': { label: 'Teammate added', icon: Users },
  'member.removed': { label: 'Teammate removed', icon: Users },
  'finding.status_changed': { label: 'Finding updated', icon: Check },
  'plan.changed': { label: 'Plan changed', icon: Shield },
};

function formatFixTime(hours: number | null) {
  if (hours === null) return 'No fixes yet';
  if (hours < 1) return 'Under an hour';
  if (hours < 24) return `${Math.round(hours)} hour${Math.round(hours) === 1 ? '' : 's'}`;
  const days = Math.round((hours / 24) * 10) / 10;
  return `${days} day${days === 1 ? '' : 's'}`;
}

function greeting() {
  const h = new Date().getHours();
  return h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening';
}

export default function OverviewPage() {
  const { user, org } = useSession();
  const { data } = useSWR<Overview>(`/v1/orgs/${org.id}/overview`, fetcher, { refreshInterval: 30_000 });
  const { data: scans } = useSWR<{ scans: ScanRow[] }>(`/v1/orgs/${org.id}/scans?limit=6`, fetcher, { refreshInterval: 30_000 });

  const maxDay = Math.max(1, ...(data?.trend ?? []).map((d) => d.detected + d.fixed));
  const maxSev = Math.max(1, ...Object.values(data?.open ?? {}));
  const firstName = user.name.split(' ')[0];
  const noScans = scans && scans.scans.length === 0;

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <span className="eyebrow reveal">{greeting()}, {firstName}</span>
          <h1 className="display">
            <Words>
              {data && data.open.critical > 0 ? 'Fix the criticals ' : 'Every release, '}
              <span className="it accent">{data && data.open.critical > 0 ? 'before they ship.' : 'checked.'}</span>
            </Words>
          </h1>
        </div>
        <Link href="/findings?status=open" className="btn btn-dark reveal" style={{ ['--d' as string]: '200ms' }}>
          Review open findings <Arrow className="arr" />
        </Link>
      </div>

      {org.plan === 'free' ? (
        <div className="card card-pad reveal" style={{ background: 'var(--tint-warm)', borderColor: '#F3E6DA', display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
          <Shield style={{ width: 22, height: 22, color: 'var(--green)' }} />
          <div style={{ flex: 1, minWidth: 240 }}>
            <strong style={{ color: 'var(--ink)' }}>You're on Fortis Free.</strong>{' '}
            <span className="muted">Scans run on your machine and stay there. Fortis Core adds the fintech rule pack and syncs findings here.</span>
          </div>
          <Link href="/settings" className="link-arrow">See plans <Arrow /></Link>
        </div>
      ) : null}

      <div className="tiles">
        {[
          { lbl: 'Open critical', v: data?.open.critical, cls: 'red', c: 'var(--red)', sub: 'Blocks the push' },
          { lbl: 'Open findings', v: data?.openTotal, cls: '', c: 'var(--amber)', sub: 'Across all projects' },
          { lbl: 'Fixed · 30 days', v: data?.totals.fixed30d, cls: 'green', c: 'var(--green)', sub: 'Closed by a re-scan or a person' },
          { lbl: 'Scans · 30 days', v: data?.totals.scans30d, cls: '', c: 'var(--blue)', sub: `${data?.totals.prePush30d ?? 0} caught before push` },
        ].map((t, i) => (
          <div className="tile reveal" key={t.lbl} style={{ ['--d' as string]: `${i * 70}ms`, ['--c' as string]: t.c }}>
            <div className="lbl">{t.lbl}</div>
            <div className={`v ${t.cls}`}>{t.v === undefined ? <Skeleton h={34} w={70} /> : <CountUp value={t.v} />}</div>
            <div className="sub">{t.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <section className="card reveal" style={{ ['--d' as string]: '150ms' }}>
          <div className="card-head">
            <h3>Detected vs fixed · last 30 days</h3>
            <div className="legend">
              <span><i style={{ background: '#F6C3BE' }} />Detected</span>
              <span><i style={{ background: 'var(--green)' }} />Fixed</span>
            </div>
          </div>
          <div className="card-pad">
            {data ? (
              <>
                <div className="bars">
                  {data.trend.map((d, k) => (
                    <div className="col" key={d.day} data-tip={`${d.day.slice(5)} · ${d.detected} new · ${d.fixed} fixed`} style={{ ['--k' as string]: k }}>
                      <i className="det" style={{ height: `${(d.detected / maxDay) * 100}%`, ['--k' as string]: k }} />
                      <i className="fix" style={{ height: `${(d.fixed / maxDay) * 100}%`, ['--k' as string]: k }} />
                    </div>
                  ))}
                </div>
                <div className="chart-x"><span>{data.trend[0]?.day.slice(5)}</span><span>Today</span></div>
              </>
            ) : (
              <Skeleton h={170} />
            )}
          </div>
        </section>

        <section className="card reveal" style={{ ['--d' as string]: '220ms' }}>
          <div className="card-head">
            <h3>Open by severity</h3>
            <Link href="/findings?status=open" className="link-arrow">View <Arrow /></Link>
          </div>
          <div className="card-pad">
            <div className="sev-bars">
              {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
                <div className="sev-row" key={s}>
                  <SeverityPill severity={s} />
                  <div className="sev-track">
                    <i style={{ ['--w' as string]: `${((data?.open[s] ?? 0) / maxSev) * 100}%`, background: SEV_COLOURS[s] }} />
                  </div>
                  <b>{data ? <CountUp value={data.open[s] ?? 0} /> : '–'}</b>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 22, paddingTop: 18, borderTop: '1px solid var(--line)', display: 'flex', alignItems: 'center', gap: 12 }}>
              <Pulse style={{ width: 22, height: 22, color: 'var(--green)' }} />
              <div>
                <div className="small">Median time to fix a critical</div>
                <strong style={{ color: 'var(--ink)', fontSize: 18 }}>
                  {formatFixTime(data?.medianCriticalFixHours ?? null)}
                </strong>
              </div>
            </div>
          </div>
        </section>
      </div>

      <div className="grid-2">
        <section className="card reveal" style={{ ['--d' as string]: '260ms' }}>
          <div className="card-head">
            <h3>Recent scans</h3>
            <Link href="/projects" className="link-arrow">Projects <Arrow /></Link>
          </div>
          {noScans ? (
            <Empty
              icon={<Git />}
              title="No scans yet"
              text="Create a project and a CLI key, then run Fortis in your repo. Every push and CI run will show up here."
              action={<Link href="/projects" className="btn btn-primary">Set up a project <Arrow className="arr" /></Link>}
            />
          ) : (
            <ul className="list">
              {(scans?.scans ?? Array.from({ length: 3 }, () => null)).map((s, i) =>
                s ? (
                  <li key={s.id} className="row-in" style={{ ['--i' as string]: i }}>
                    <span className={`ic${s.newCount > 0 ? ' red' : ''}`}>{s.newCount > 0 ? <Alert /> : <Check />}</span>
                    <span style={{ minWidth: 0 }}>
                      <strong style={{ color: 'var(--ink)' }}>{s.projectName}</strong>
                      <span className="small" style={{ display: 'block' }}>
                        {s.trigger === 'pre-push' ? 'Pre-push' : s.trigger === 'ci' ? 'CI' : 'Manual'} · {s.branch ?? 'unknown branch'}
                        {s.commit ? ` · ${s.commit.slice(0, 7)}` : ''} · {s.newCount} new · {s.fixedCount} fixed
                      </span>
                    </span>
                    <span className="meta">{timeAgo(s.createdAt)}</span>
                  </li>
                ) : (
                  <li key={i}><Skeleton h={34} /></li>
                ),
              )}
            </ul>
          )}
        </section>

        <section className="card reveal" style={{ ['--d' as string]: '320ms' }}>
          <div className="card-head"><h3>Activity</h3></div>
          <ul className="list">
            {(data?.recentActivity ?? []).map((a, i) => {
              const meta = ACTIVITY[a.action] ?? { label: a.action, icon: Shield };
              const Icon = meta.icon;
              return (
                <li key={`${a.createdAt}-${i}`} className="row-in" style={{ ['--i' as string]: i }}>
                  <span className="ic"><Icon /></span>
                  <span>
                    <strong style={{ color: 'var(--ink)' }}>{meta.label}</strong>
                    <span className="small" style={{ display: 'block' }}>{a.actor ?? 'Fortis'}</span>
                  </span>
                  <span className="meta">{timeAgo(a.createdAt)}</span>
                </li>
              );
            })}
            {data && data.recentActivity.length === 0 ? <li className="small">Nothing yet.</li> : null}
          </ul>
        </section>
      </div>
    </div>
  );
}
