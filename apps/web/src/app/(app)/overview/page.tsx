'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Suspense } from 'react';
import useSWR from 'swr';

import { Alert, Arrow, Check, Clock, Folder, Git, Key, Pulse, Shield, Users } from '@/components/icons';
import { CountUp, Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { Empty, SeverityPill, Skeleton } from '@/components/ui';
import { Checklist, computePosture, InfoTip, ReleaseLoop, ScoreRing } from '@/components/widgets';
import { fetcher } from '@/lib/api';
import { timeAgo } from '@/lib/format';
import type { ScanRow } from '@/lib/types';

type Overview = {
  open: Record<string, number>;
  openTotal: number;
  openByProject: { id: string; name: string; critical: number; high: number; total: number; oldestOpenAt: string }[];
  trend: { day: string; detected: number; fixed: number }[];
  totals: {
    scans30d: number; prePush30d: number; ci30d: number; fixed30d: number; projects: number; scansAllTime: number;
    activeKeys: number; members: number; resolvedAllTime: number; evidenceEvents: number; blockedPrePush30d: number;
    oldestOpenCriticalDays: number | null;
  };
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
  'org.renamed': { label: 'Workspace renamed', icon: Shield },
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

function OverviewInner() {
  const { user, org } = useSession();
  const params = useSearchParams();
  const { data } = useSWR<Overview>(`/v1/orgs/${org.id}/overview`, fetcher, { refreshInterval: 30_000 });
  const { data: scans } = useSWR<{ scans: ScanRow[] }>(`/v1/orgs/${org.id}/scans?limit=6`, fetcher, { refreshInterval: 30_000 });

  const maxDay = Math.max(1, ...(data?.trend ?? []).map((d) => d.detected + d.fixed));
  const maxSev = Math.max(1, ...Object.values(data?.open ?? {}));
  const firstName = user.name.split(' ')[0];
  const t = data?.totals;
  const scored = Boolean(t && t.scansAllTime > 0);
  const posture = data && scored ? computePosture(data.open, t?.oldestOpenCriticalDays ?? null) : null;
  const isAdmin = org.role === 'owner' || org.role === 'admin';
  const firstProject = data?.openByProject[0];

  const steps = t
    ? [
        { label: 'Create your workspace', hint: `${org.name} is ready.`, done: true },
        { label: 'Add a project', hint: 'One per repository or service.', done: t.projects > 0, href: '/projects', cta: 'Add project' },
        { label: 'Create a CLI key', hint: 'The CLI uses it to know which project it is checking.', done: t.activeKeys > 0, href: '/projects', cta: 'Create key' },
        { label: 'Run your first scan', hint: 'Install the CLI and push, or run it in CI.', done: t.scansAllTime > 0, href: '/projects', cta: 'See steps' },
        { label: 'Resolve a finding', hint: 'Fix it, or record why it is accepted.', done: t.resolvedAllTime > 0, href: '/findings', cta: 'Open findings' },
        { label: 'Invite a teammate', hint: 'Share the work with your developers and compliance lead.', done: t.members > 1, href: '/settings', cta: 'Invite' },
      ]
    : [];
  const setupDone = steps.length > 0 && steps.every((s) => s.done);
  const showChecklist = steps.length > 0 && (!setupDone || params.get('welcome') === '1');

  const headline = !data
    ? ['Loading your ', 'workspace.']
    : data.open.critical > 0
      ? ['Fix the criticals ', 'before they ship.']
      : t && t.scansAllTime === 0
        ? ['Welcome to Fortis. ', "Let's get you set up."]
        : ['Every release, ', 'checked.'];

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <span className="eyebrow reveal">{greeting()}, {firstName}</span>
          <h1 className="display">
            <Words>{headline[0]}<span className="it accent">{headline[1]}</span></Words>
          </h1>
          <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>
            {data && data.open.critical > 0
              ? `${data.open.critical} critical issue${data.open.critical === 1 ? ' is' : 's are'} open. Pushes with criticals are blocked until they're fixed.`
              : 'Here is what Fortis has checked across your projects, and what needs you next.'}
          </p>
        </div>
        <Link href="/findings?status=open" className="btn btn-dark reveal" style={{ ['--d' as string]: '200ms' }}>
          Review open findings <Arrow className="arr" />
        </Link>
      </div>

      {org.plan === 'free' ? (
        <div className="banner reveal">
          <Shield />
          <div>
            <strong>You're on Fortis Free.</strong> Scans run on your machine and the results stay there, so this dashboard fills up once
            you move to Fortis Core, which also adds the fintech rule pack.
          </div>
          <Link href="/settings" className="link-arrow">Compare plans <Arrow /></Link>
        </div>
      ) : null}

      {showChecklist ? <section className="card card-pad reveal" style={{ ['--d' as string]: '80ms' }}><Checklist steps={steps} /></section> : null}

      <div className="hero-row">
        <section className="card posture reveal" style={{ ['--d' as string]: '120ms' }}>
          <div className="card-head">
            <h3>Security posture <InfoTip text="A 0–100 guide to how risky your open findings are right now. Criticals weigh most. It helps you prioritise; it is not a certification." /></h3>
          </div>
          <div className="posture-body">
            {posture ? (
              <ScoreRing score={posture.score} colour={posture.colour} grade={posture.grade} />
            ) : data ? (
              <ScoreRing score={0} colour="var(--line-2)" grade="–" />
            ) : (
              <Skeleton h={130} w={130} />
            )}
            <div>
              <strong className="posture-label" style={{ color: posture?.colour ?? 'var(--ink)' }}>
                {posture ? posture.label : data ? 'Not scored yet' : '…'}
              </strong>
              <ul className="reasons">
                {posture
                  ? posture.reasons.map((r) => <li key={r}>{r}</li>)
                  : data
                    ? [<li key="n">Your score appears after the first scan uploads to Fortis.</li>]
                    : null}
              </ul>
            </div>
          </div>
        </section>

        <section className="card attention reveal" style={{ ['--d' as string]: '180ms' }}>
          <div className="card-head">
            <h3>Needs your attention</h3>
            <Link href="/findings" className="link-arrow">All findings <Arrow /></Link>
          </div>
          {data && data.openByProject.length === 0 ? (
            <Empty icon={<Check />} title="Nothing needs you right now" text="No open findings in any project. New issues from pushes and CI show up here first." />
          ) : (
            <ul className="todo">
              {(data?.openByProject ?? []).map((p, i) => (
                <li key={p.id} className="row-in" style={{ ['--i' as string]: i }}>
                  <span className={`todo-ic ${p.critical ? 'red' : p.high ? 'amber' : ''}`}>{p.critical ? <Alert /> : <Clock />}</span>
                  <span className="todo-txt">
                    <strong>
                      {p.critical
                        ? `${p.critical} critical in ${p.name}`
                        : p.high
                          ? `${p.high} high-severity in ${p.name}`
                          : `${p.total} open in ${p.name}`}
                    </strong>
                    <small>
                      {p.critical ? 'Pushes are blocked until fixed. ' : ''}
                      Oldest open since {timeAgo(p.oldestOpenAt)}.
                    </small>
                  </span>
                  <Link href={`/findings?projectId=${p.id}`} className="btn btn-outline btn-sm">Review</Link>
                </li>
              ))}
              {!data ? <li><Skeleton h={40} /></li> : null}
            </ul>
          )}
          {firstProject && t && t.oldestOpenCriticalDays !== null && t.oldestOpenCriticalDays > 3 ? (
            <p className="small warn-line"><Clock /> A critical has been open for {t.oldestOpenCriticalDays} days. Reviewers usually expect criticals fixed within a week.</p>
          ) : null}
        </section>
      </div>

      <div className="tiles">
        {[
          { lbl: 'Open critical', v: data?.open.critical, cls: 'red', c: 'var(--red)', sub: 'These block the push', tip: 'Critical findings, like a live payment key or a transfer anyone can read, are blocked before they leave the laptop.' },
          { lbl: 'Open findings', v: data?.openTotal, cls: '', c: 'var(--amber)', sub: 'All severities, all projects', tip: 'Everything not yet fixed, accepted as a risk, or marked a false positive.' },
          { lbl: 'Fixed · 30 days', v: t?.fixed30d, cls: 'green', c: 'var(--green)', sub: 'Closed by a re-scan or a person', tip: 'A finding closes itself when a full scan stops seeing it, or when someone marks it fixed.' },
          { lbl: 'Median fix time', v: undefined, text: formatFixTime(data?.medianCriticalFixHours ?? null), cls: '', c: 'var(--blue)', sub: 'For critical findings', tip: 'Half of your critical findings were fixed faster than this. Partner banks and auditors often ask for it.' },
        ].map((tile, i) => (
          <div className="tile reveal" key={tile.lbl} style={{ ['--d' as string]: `${200 + i * 60}ms`, ['--c' as string]: tile.c }}>
            <div className="lbl">{tile.lbl} <InfoTip text={tile.tip} /></div>
            <div className={`v ${tile.cls}`} style={tile.text ? { fontSize: 24, paddingTop: 6 } : undefined}>
              {tile.text ? (data ? tile.text : <Skeleton h={30} w={90} />) : tile.v === undefined ? <Skeleton h={34} w={70} /> : <CountUp value={tile.v} />}
            </div>
            <div className="sub">{tile.sub}</div>
          </div>
        ))}
      </div>

      <section className="card reveal" style={{ ['--d' as string]: '260ms' }}>
        <div className="card-head">
          <h3>Your release loop · last 30 days <InfoTip text="Fortis checks code at each step of a release, so problems are caught early and the proof builds up as you go." /></h3>
        </div>
        <div className="card-pad">
          <ReleaseLoop
            items={[
              { k: 'Write', title: 'Pre-push checks', value: t ? <CountUp value={t.prePush30d} /> : '–', hint: `${t?.blockedPrePush30d ?? 0} new issues caught on laptops` },
              { k: 'Push', title: 'CI scans', value: t ? <CountUp value={t.ci30d} /> : '–', hint: 'Full scans that also close fixed findings' },
              { k: 'Deploy', title: 'Staging checks', value: 'Soon', hint: 'Access checks with your test users, on Fortis Plus', soon: true },
              { k: 'Prove', title: 'Evidence records', value: t ? <CountUp value={t.evidenceEvents} /> : '–', hint: 'Every detection, fix and decision, timestamped' },
            ]}
          />
        </div>
      </section>

      <div className="grid-2">
        <section className="card reveal" style={{ ['--d' as string]: '300ms' }}>
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
                <p className="small" style={{ margin: '14px 0 0' }}>
                  {t && t.fixed30d >= (data.trend.reduce((a, d) => a + d.detected, 0) || 0)
                    ? 'You are fixing issues at least as fast as they appear.'
                    : 'More issues are appearing than being fixed. Start with the criticals.'}
                </p>
              </>
            ) : (
              <Skeleton h={170} />
            )}
          </div>
        </section>

        <section className="card reveal" style={{ ['--d' as string]: '340ms' }}>
          <div className="card-head">
            <h3>Open by severity <InfoTip text="Critical: exploitable now, blocks the push. High: serious, fix this sprint. Medium and low: plan a fix." /></h3>
          </div>
          <div className="card-pad">
            <div className="sev-bars">
              {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
                <Link className="sev-row" key={s} href={`/findings?severity=${s}`}>
                  <SeverityPill severity={s} />
                  <div className="sev-track">
                    <i style={{ ['--w' as string]: `${((data?.open[s] ?? 0) / maxSev) * 100}%`, background: SEV_COLOURS[s] }} />
                  </div>
                  <b>{data ? <CountUp value={data.open[s] ?? 0} /> : '–'}</b>
                </Link>
              ))}
            </div>
            <div style={{ marginTop: 22, paddingTop: 18, borderTop: '1px solid var(--line)', display: 'flex', alignItems: 'center', gap: 12 }}>
              <Pulse style={{ width: 22, height: 22, color: 'var(--green)' }} />
              <div className="small">Click a severity to see those findings.</div>
            </div>
          </div>
        </section>
      </div>

      <div className="grid-2">
        <section className="card reveal" style={{ ['--d' as string]: '380ms' }}>
          <div className="card-head">
            <h3>Recent scans</h3>
            <Link href="/projects" className="link-arrow">Projects <Arrow /></Link>
          </div>
          {scans && scans.scans.length === 0 ? (
            <Empty
              icon={<Git />}
              title="No scans yet"
              text="Create a project and a CLI key, then run Fortis in your repo. Every push and CI run shows up here."
              action={isAdmin ? <Link href="/projects" className="btn btn-primary">Set up a project <Arrow className="arr" /></Link> : undefined}
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

        <section className="card reveal" style={{ ['--d' as string]: '420ms' }}>
          <div className="card-head"><h3>Activity</h3>{isAdmin ? <Link href="/settings#audit" className="link-arrow">Audit log <Arrow /></Link> : null}</div>
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

export default function OverviewPage() {
  return (
    <Suspense>
      <OverviewInner />
    </Suspense>
  );
}
