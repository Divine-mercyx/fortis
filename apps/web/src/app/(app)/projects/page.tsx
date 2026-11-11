'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useMemo, useState } from 'react';
import useSWR from 'swr';

import { Arrow, Plus, Search, Terminal } from '@/components/icons';
import { CountUp, Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { Empty, FormError, Modal, Skeleton, useToast } from '@/components/ui';
import { StatTile } from '@/components/widgets';
import { api, fetcher } from '@/lib/api';
import { initials, timeAgo } from '@/lib/format';
import type { ProjectRow } from '@/lib/types';

function NewProject({ onClose }: { onClose: () => void }) {
  const { org } = useSession();
  const router = useRouter();
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const repoUrl = String(f.get('repoUrl') ?? '').trim();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ project: { id: string } }>(`/v1/orgs/${org.id}/projects`, {
        method: 'POST',
        body: { name: f.get('name'), repoUrl: repoUrl || undefined },
      });
      toast('Project created');
      router.push(`/projects/${res.project.id}?new=1`);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <Modal title="Add a project" lead="One project per repository or service. You'll get a CLI key next." onClose={onClose}>
      <form onSubmit={onSubmit}>
        <FormError message={error} />
        <label className="field">
          <span>Project name</span>
          <input className="input" name="name" placeholder="paywave-api" required minLength={2} autoFocus />
        </label>
        <label className="field">
          <span>Repository URL <span className="muted" style={{ fontWeight: 500 }}>(optional)</span></span>
          <input className="input" name="repoUrl" type="url" placeholder="https://github.com/your-org/paywave-api" />
        </label>
        <div className="modal-actions">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy}>
            {busy ? <span className="spinner" /> : null} Create project
          </button>
        </div>
      </form>
    </Modal>
  );
}

type Tone = 'bad' | 'warn' | 'good' | 'idle';

/** How a project is doing, in one word and one colour. */
function healthOf(p: ProjectRow): { tone: Tone; label: string } {
  if (!p.lastScanAt) return { tone: 'idle', label: 'No scans yet' };
  if (p.openCritical > 0) return { tone: 'bad', label: `${p.openCritical} critical` };
  if (p.openFindings > 0) return { tone: 'warn', label: `${p.openFindings} open` };
  return { tone: 'good', label: 'Clean' };
}

const repoLabel = (url: string | null) => (url ? url.replace(/^https?:\/\/(www\.)?/, '').replace(/\.git$/, '').replace(/\/+$/, '') : 'No repository linked');

/** Search and filters only appear once there are enough projects to need them. */
const TOOLS_FROM = 6;

const FILTERS = [
  { id: 'all', label: 'All', test: () => true },
  { id: 'critical', label: 'Critical', test: (p: ProjectRow) => p.openCritical > 0 },
  { id: 'open', label: 'Has findings', test: (p: ProjectRow) => p.openFindings > 0 },
  { id: 'clean', label: 'Clean', test: (p: ProjectRow) => healthOf(p).tone === 'good' },
  { id: 'idle', label: 'Not scanned', test: (p: ProjectRow) => !p.lastScanAt },
] as const;
type FilterId = (typeof FILTERS)[number]['id'];

const SORTS = [
  { id: 'attention', label: 'Needs attention first' },
  { id: 'name', label: 'Name A to Z' },
  { id: 'scan', label: 'Recently scanned' },
  { id: 'new', label: 'Newest' },
] as const;
type SortId = (typeof SORTS)[number]['id'];

function sortProjects(list: ProjectRow[], by: SortId): ProjectRow[] {
  const t = (v: string | null) => (v ? new Date(v).getTime() : 0);
  const out = [...list];
  if (by === 'name') return out.sort((a, b) => a.name.localeCompare(b.name));
  if (by === 'scan') return out.sort((a, b) => t(b.lastScanAt) - t(a.lastScanAt));
  if (by === 'new') return out.sort((a, b) => t(b.createdAt) - t(a.createdAt));
  return out.sort((a, b) => b.openCritical - a.openCritical || b.openFindings - a.openFindings || a.name.localeCompare(b.name));
}

function ProjectCard({ p, i }: { p: ProjectRow; i: number }) {
  const { tone, label } = healthOf(p);
  const other = Math.max(p.openFindings - p.openCritical, 0);
  return (
    <Link href={`/projects/${p.id}`} className={`project row-in ${tone}`} style={{ ['--i' as string]: Math.min(i, 12) }}>
      <div className="top">
        <span className="pic" aria-hidden="true">{initials(p.name)}</span>
        <div className="who">
          <h3>{p.name}</h3>
          <span className="repo">{repoLabel(p.repoUrl)}</span>
        </div>
        <span className="p-state">{label}</span>
      </div>
      <div className="stats3">
        <div><b className={p.openCritical ? 'red' : ''}>{p.openCritical}</b><span>Critical</span></div>
        <div><b>{p.openFindings}</b><span>Open findings</span></div>
        <div><b>{p.lastScanAt ? timeAgo(p.lastScanAt) : '–'}</b><span>Last scan</span></div>
      </div>
      <div className="meter" role="img" aria-label={tone === 'idle' ? 'Waiting for the first scan' : `${p.openCritical} critical and ${other} other findings open`}>
        {tone === 'idle' ? null : p.openFindings === 0 ? (
          <i className="m-ok" style={{ width: '100%' }} />
        ) : (
          <>
            <i className="m-crit" style={{ width: `${(p.openCritical / p.openFindings) * 100}%` }} />
            <i className="m-open" style={{ width: `${(other / p.openFindings) * 100}%` }} />
          </>
        )}
      </div>
      <div className="foot">
        <span>Added {new Date(p.createdAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}</span>
        <span className="go">Open project <Arrow /></span>
      </div>
    </Link>
  );
}

function ProjectsInner() {
  const { org } = useSession();
  const params = useSearchParams();
  const [creating, setCreating] = useState(false);
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState<FilterId>('all');
  const [sort, setSort] = useState<SortId>('attention');
  const { data } = useSWR<{ projects: ProjectRow[] }>(`/v1/orgs/${org.id}/projects`, fetcher);
  const canCreate = org.role === 'owner' || org.role === 'admin';
  const welcome = params.get('welcome') === '1';

  const all = data?.projects;
  const showTools = (all?.length ?? 0) >= TOOLS_FROM;
  const totals = useMemo(() => {
    const list = all ?? [];
    return {
      critical: list.reduce((n, p) => n + p.openCritical, 0),
      open: list.reduce((n, p) => n + p.openFindings, 0),
      clean: list.filter((p) => healthOf(p).tone === 'good').length,
    };
  }, [all]);
  const counts = useMemo(() => Object.fromEntries(FILTERS.map((f) => [f.id, (all ?? []).filter(f.test).length])) as Record<FilterId, number>, [all]);
  const shown = useMemo(() => {
    const test = FILTERS.find((f) => f.id === filter)!.test;
    const needle = q.trim().toLowerCase();
    const list = (all ?? []).filter((p) => test(p) && (!needle || p.name.toLowerCase().includes(needle) || (p.repoUrl ?? '').toLowerCase().includes(needle)));
    return sortProjects(list, sort);
  }, [all, filter, q, sort]);
  const filtered = showTools && (filter !== 'all' || q.trim() !== '');

  return (
    <div className="stack">
      <section className="band band-row reveal">
        <div className="band-txt">
          <span className="eyebrow">{welcome ? 'Welcome to Fortis' : 'Projects'}</span>
          <h1 className="display">
            <Words>{welcome ? 'Add your first ' : 'Your repos, '}<span className="it accent">{welcome ? 'project.' : 'watched.'}</span></Words>
          </h1>
          <p className="lead">Each project gets its own CLI key. Install the CLI in the repo and every push is checked.</p>
        </div>
        {canCreate ? (
          <div className="band-actions">
            <button className="btn btn-primary" onClick={() => setCreating(true)}>
              <Plus /> New project
            </button>
          </div>
        ) : null}
      </section>

      {all && all.length > 0 ? (
        <div className="tiles stagger">
          <StatTile label="Projects" accent="var(--blue)" value={<CountUp value={all.length} />} />
          <StatTile label="Open critical" tone={totals.critical ? 'red' : undefined} accent="var(--red)" value={<CountUp value={totals.critical} />} sub="These block the push" />
          <StatTile label="Open findings" accent="var(--amber)" value={<CountUp value={totals.open} />} sub="All severities" />
          <StatTile label="Clean" tone="green" accent="var(--green)" value={<CountUp value={totals.clean} />} sub={`of ${all.length} ${all.length === 1 ? 'project' : 'projects'}`} />
        </div>
      ) : null}

      {showTools ? (
        <div className="toolbar bare">
          <label className="search">
            <Search />
            <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search projects" aria-label="Search projects" />
          </label>
          <div className="seg" role="group" aria-label="Filter projects">
            {FILTERS.filter((f) => f.id === 'all' || counts[f.id] > 0 || f.id === filter).map((f) => (
              <button key={f.id} type="button" className={filter === f.id ? 'on' : ''} onClick={() => setFilter(f.id)}>
                {f.label} <span style={{ opacity: 0.6, fontWeight: 600 }}>{counts[f.id]}</span>
              </button>
            ))}
          </div>
          <select className="select" value={sort} onChange={(e) => setSort(e.target.value as SortId)} aria-label="Sort projects">
            {SORTS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
          {filtered ? <span className="count">Showing {shown.length} of {all!.length}</span> : null}
        </div>
      ) : null}

      {all && all.length === 0 ? (
        <section className="card reveal">
          <Empty
            icon={<Terminal />}
            title="No projects yet"
            text="Create a project for a repository, generate a key, and run one command. Results appear here within seconds."
            action={canCreate ? <button className="btn btn-primary" onClick={() => setCreating(true)}><Plus /> Create a project</button> : undefined}
          />
        </section>
      ) : all && shown.length === 0 ? (
        <section className="card reveal">
          <Empty
            icon={<Search />}
            title="No projects match"
            text="Try a different name, or clear the filter to see every project."
            action={<button className="btn btn-outline" onClick={() => { setQ(''); setFilter('all'); }}>Clear filters</button>}
          />
        </section>
      ) : (
        <div className="projects">
          {(all ? shown : Array.from({ length: 3 }, () => null)).map((p, i) =>
            p ? <ProjectCard key={p.id} p={p} i={i} /> : <div className="project" key={i}><Skeleton h={120} /></div>,
          )}
          {all && canCreate && !filtered ? (
            <button type="button" className="project-new" onClick={() => setCreating(true)}>
              <span className="plus"><Plus /></span>
              New project
            </button>
          ) : null}
        </div>
      )}

      {creating ? <NewProject onClose={() => setCreating(false)} /> : null}
    </div>
  );
}

export default function ProjectsPage() {
  return (
    <Suspense>
      <ProjectsInner />
    </Suspense>
  );
}
