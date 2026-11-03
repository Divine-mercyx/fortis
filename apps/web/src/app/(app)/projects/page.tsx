'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useState } from 'react';
import useSWR from 'swr';

import { Arrow, Folder, Plus, Terminal } from '@/components/icons';
import { Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { Empty, FormError, Modal, Skeleton, useToast } from '@/components/ui';
import { api, fetcher } from '@/lib/api';
import { timeAgo } from '@/lib/format';
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

function ProjectsInner() {
  const { org } = useSession();
  const params = useSearchParams();
  const [creating, setCreating] = useState(false);
  const { data } = useSWR<{ projects: ProjectRow[] }>(`/v1/orgs/${org.id}/projects`, fetcher);
  const canCreate = org.role === 'owner' || org.role === 'admin';
  const welcome = params.get('welcome') === '1';

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <span className="eyebrow reveal">{welcome ? 'Welcome to Fortis' : 'Projects'}</span>
          <h1 className="display">
            <Words>{welcome ? 'Add your first ' : 'Your repos, '}<span className="it accent">{welcome ? 'project.' : 'watched.'}</span></Words>
          </h1>
          <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>
            Each project gets its own CLI key. Install the CLI in the repo and every push is checked.
          </p>
        </div>
        {canCreate ? (
          <button className="btn btn-primary reveal" style={{ ['--d' as string]: '200ms' }} onClick={() => setCreating(true)}>
            <Plus /> New project
          </button>
        ) : null}
      </div>

      {data && data.projects.length === 0 ? (
        <section className="card reveal">
          <Empty
            icon={<Terminal />}
            title="No projects yet"
            text="Create a project for a repository, generate a key, and run one command. Results appear here within seconds."
            action={canCreate ? <button className="btn btn-primary" onClick={() => setCreating(true)}><Plus /> Create a project</button> : undefined}
          />
        </section>
      ) : (
        <div className="projects">
          {(data?.projects ?? Array.from({ length: 3 }, () => null)).map((p, i) =>
            p ? (
              <Link href={`/projects/${p.id}`} key={p.id} className="project row-in" style={{ ['--i' as string]: i }}>
                <div className="top">
                  <span className="pic"><Folder /></span>
                  <div style={{ minWidth: 0 }}>
                    <h3>{p.name}</h3>
                    <span className="small">{p.lastScanAt ? `Last scan ${timeAgo(p.lastScanAt)}` : 'No scans yet'}</span>
                  </div>
                  <Arrow style={{ marginLeft: 'auto', width: 18, height: 18, color: 'var(--green)' }} />
                </div>
                <div className="stats">
                  <span><b className={p.openCritical ? 'red' : ''}>{p.openCritical}</b>open critical</span>
                  <span><b>{p.openFindings}</b>open findings</span>
                </div>
              </Link>
            ) : (
              <div className="project" key={i}><Skeleton h={90} /></div>
            ),
          )}
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
