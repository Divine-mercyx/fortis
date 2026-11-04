'use client';

import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useState } from 'react';
import useSWR from 'swr';

import { Alert, Arrow, Check, Git, Key, Plus, Trash } from '@/components/icons';
import { CountUp, Words } from '@/components/motion';
import { useSession } from '@/components/session';
import { StagingTargets } from '@/components/targets';
import { CodeLine, CopyButton, Empty, FormError, Modal, SeverityPill, Skeleton, StatusTag, useToast } from '@/components/ui';
import { api, ApiError, fetcher } from '@/lib/api';
import { CLI_COMMAND, CLI_INSTALL_URL, CLI_PACKAGE, CLI_PYTHON_PACKAGE } from '@/lib/cli';
import { timeAgo } from '@/lib/format';
import type { FindingRow, ScanRow } from '@/lib/types';

type Project = { id: string; name: string; slug: string; repoUrl: string | null; createdAt: string };
type Token = { id: string; name: string; prefix: string; createdAt: string; lastUsedAt: string | null; revokedAt: string | null; createdBy: string | null };

/** npm for JavaScript projects; a standalone binary for every other stack, which may have no Node. */
function InstallCommands({ initArgs = '' }: { initArgs?: string }) {
  const [stack, setStack] = useState<'js' | 'python' | 'other'>('js');
  return (
    <>
      <div className="seg" role="group" aria-label="What your project is written in" style={{ marginBottom: 10 }}>
        <button type="button" className={stack === 'js' ? 'on' : ''} aria-pressed={stack === 'js'} onClick={() => setStack('js')}>JavaScript / TypeScript</button>
        <button type="button" className={stack === 'python' ? 'on' : ''} aria-pressed={stack === 'python'} onClick={() => setStack('python')}>Python</button>
        <button type="button" className={stack === 'other' ? 'on' : ''} aria-pressed={stack === 'other'} onClick={() => setStack('other')}>Java, PHP, Go, others</button>
      </div>
      {stack === 'js' ? (
        <>
          <CodeLine cmd={`npm i -D ${CLI_PACKAGE}`} />
          <CodeLine cmd={`npx ${CLI_COMMAND} init${initArgs}`} />
        </>
      ) : stack === 'python' ? (
        <>
          <CodeLine cmd={`pip install ${CLI_PYTHON_PACKAGE}`} />
          <CodeLine cmd={`${CLI_COMMAND} init${initArgs}`} />
          <p className="small" style={{ marginBottom: 0 }}>Needs no Node.js. The fintech rules cover Django, Django REST, Flask and FastAPI. Install it in your project&apos;s virtual environment or globally; the git hook finds it either way.</p>
        </>
      ) : (
        <>
          <CodeLine cmd={`curl -fsSL ${CLI_INSTALL_URL}/install.sh | sh`} />
          <p className="small" style={{ margin: '8px 0' }}>On Windows, in PowerShell:</p>
          <CodeLine cmd={`irm ${CLI_INSTALL_URL}/install.ps1 | iex`} />
          <p className="small" style={{ margin: '8px 0' }}>Then, in your repository:</p>
          <CodeLine cmd={`${CLI_COMMAND} init${initArgs}`} />
          <p className="small" style={{ marginBottom: 0 }}>In every language, Fortis checks for leaked secrets and vulnerable dependencies. The fintech code rules cover JavaScript, TypeScript and Python so far.</p>
        </>
      )}
    </>
  );
}

function NewKey({ projectId, onClose, onCreated }: { projectId: string; onClose: () => void; onCreated: () => void }) {
  const { org } = useSession();
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ token: { secret: string } }>(`/v1/orgs/${org.id}/projects/${projectId}/tokens`, {
        method: 'POST',
        body: { name: f.get('name') },
      });
      setSecret(res.token.secret);
      onCreated();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (secret) {
    return (
      <Modal title="Your new CLI key" onClose={onClose}>
        <div className="secret-box">
          <div className="warn"><Alert /> Copy it now. For your security, Fortis only shows it once.</div>
          <div className="code"><code>{secret}</code><CopyButton text={secret} /></div>
        </div>
        <p className="small" style={{ marginTop: 0 }}>In your repository, install the CLI and connect it with this key:</p>
        <InstallCommands initArgs={` --key ${secret}`} />
        <p className="small" style={{ marginBottom: 0 }}>For CI, save the key as a secret named <span className="mono">FORTIS_KEY</span> and run <span className="mono">{CLI_COMMAND} ci init</span> in the repository.</p>
        <div className="modal-actions" style={{ marginTop: 18 }}>
          <button className="btn btn-primary" onClick={onClose}><Check /> I've saved it</button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Create a CLI key" lead="Keys are scoped to this project. Use one per developer machine or CI system so you can revoke them separately." onClose={onClose}>
      <form onSubmit={onSubmit}>
        <FormError message={error} />
        <label className="field">
          <span>Key name</span>
          <input className="input" name="name" placeholder="GitHub Actions" required minLength={2} autoFocus />
        </label>
        <div className="modal-actions">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy}>{busy ? <span className="spinner" /> : null} Create key</button>
        </div>
      </form>
    </Modal>
  );
}

export default function ProjectPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const { org } = useSession();
  const router = useRouter();
  const toast = useToast();
  const isAdmin = org.role === 'owner' || org.role === 'admin';
  const canSeeKeys = org.role !== 'viewer';
  const [newKey, setNewKey] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const { data, error } = useSWR<{ project: Project }>(`/v1/orgs/${org.id}/projects/${projectId}`, fetcher);
  const { data: tokens, mutate: refreshTokens } = useSWR<{ tokens: Token[] }>(
    canSeeKeys ? `/v1/orgs/${org.id}/projects/${projectId}/tokens` : null,
    fetcher,
  );
  const { data: scans } = useSWR<{ scans: ScanRow[] }>(`/v1/orgs/${org.id}/scans?projectId=${projectId}&limit=8`, fetcher, { refreshInterval: 20_000 });
  const { data: open } = useSWR<{ findings: FindingRow[]; total: number }>(
    `/v1/orgs/${org.id}/findings?projectId=${projectId}&status=open&limit=6`,
    fetcher,
    { refreshInterval: 20_000 },
  );

  if (error instanceof ApiError && error.status === 404) {
    return <section className="card"><Empty icon={<Alert />} title="Project not found" text="It may have been deleted, or it belongs to another workspace." action={<Link href="/projects" className="btn btn-primary">All projects</Link>} /></section>;
  }

  const p = data?.project;
  const active = (tokens?.tokens ?? []).filter((t) => !t.revokedAt);
  const critical = (open?.findings ?? []).filter((f) => f.severity === 'critical').length;

  async function revoke(t: Token) {
    if (!window.confirm(`Revoke "${t.name}"? Anything using this key will stop working.`)) return;
    try {
      await api(`/v1/orgs/${org.id}/projects/${projectId}/tokens/${t.id}`, { method: 'DELETE' });
      toast('Key revoked');
      refreshTokens();
    } catch (err) {
      toast((err as Error).message, true);
    }
  }

  async function deleteProject() {
    try {
      await api(`/v1/orgs/${org.id}/projects/${projectId}`, { method: 'DELETE' });
      toast('Project deleted');
      router.replace('/projects');
    } catch (err) {
      toast((err as Error).message, true);
    }
  }

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <Link href="/projects" className="eyebrow reveal" style={{ display: 'inline-flex', gap: 6 }}>← Projects</Link>
          <h1 className="display">{p ? <Words>{p.name}</Words> : <Skeleton h={48} w={280} />}</h1>
          <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>
            {p?.repoUrl ? <a href={p.repoUrl} target="_blank" rel="noreferrer noopener" className="link-arrow">{p.repoUrl.replace(/^https?:\/\//, '')} <Arrow /></a> : 'Fintech checks on every push and CI run.'}
          </p>
        </div>
        {isAdmin ? (
          <button className="btn btn-primary reveal" style={{ ['--d' as string]: '200ms' }} onClick={() => setNewKey(true)}><Key /> New CLI key</button>
        ) : null}
      </div>

      <div className="tiles">
        {[
          { lbl: 'Open critical', v: critical, cls: 'red', c: 'var(--red)' },
          { lbl: 'Open findings', v: open?.total, cls: '', c: 'var(--amber)' },
          { lbl: 'Recent scans', v: scans?.scans.length, cls: '', c: 'var(--blue)' },
          { lbl: 'Active keys', v: canSeeKeys ? active.length : undefined, cls: 'green', c: 'var(--green)' },
        ].map((t, i) => (
          <div className="tile reveal" key={t.lbl} style={{ ['--d' as string]: `${i * 70}ms`, ['--c' as string]: t.c }}>
            <div className="lbl">{t.lbl}</div>
            <div className={`v ${t.cls}`}>{t.v === undefined ? '–' : <CountUp value={t.v} />}</div>
          </div>
        ))}
      </div>

      {scans && scans.scans.length === 0 ? (
        <section className="card card-pad reveal" style={{ ['--d' as string]: '150ms' }}>
          <span className="eyebrow">Connect this repository</span>
          <h2 className="h2" style={{ marginBottom: 20 }}>Three steps to your first scan.</h2>
          <ol className="steps">
            <li><strong>Create a CLI key</strong>{isAdmin ? <button className="btn btn-outline btn-sm" onClick={() => setNewKey(true)}><Plus /> New CLI key</button> : <span className="small">Ask an admin to create one.</span>}</li>
            <li><strong>Install Fortis in the repo</strong><InstallCommands /></li>
            <li><strong>Push as usual</strong><span className="small">The pre-push hook checks changed files; run <span className="mono">{CLI_COMMAND} ci init</span> to add full scans to CI, which also close fixed findings.</span></li>
          </ol>
          <p className="small" style={{ marginTop: 18 }}>The CLI is in early access; package and command names may change.</p>
        </section>
      ) : null}

      <div className="grid-2">
        <section className="card reveal" style={{ ['--d' as string]: '200ms' }}>
          <div className="card-head">
            <h3>Open findings</h3>
            <Link href={`/findings?projectId=${projectId}`} className="link-arrow">All <Arrow /></Link>
          </div>
          {open && open.findings.length === 0 ? (
            <Empty icon={<Check />} title="Nothing open" text="New issues found by pushes and CI runs will show up here." />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <tbody>
                  {(open?.findings ?? []).map((f, i) => (
                    <tr key={f.id} className="click row-in" style={{ ['--i' as string]: i }} onClick={() => router.push(`/findings?projectId=${projectId}&id=${f.id}`)}>
                      <td style={{ width: 90 }}><SeverityPill severity={f.severity} /></td>
                      <td><span className="t-title">{f.title}</span><span className="t-file">{f.file}{f.line ? `:${f.line}` : ''}</span></td>
                      <td><StatusTag status={f.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="card reveal" style={{ ['--d' as string]: '260ms' }}>
          <div className="card-head"><h3>Scans</h3></div>
          {scans && scans.scans.length === 0 ? (
            <Empty icon={<Git />} title="Waiting for the first scan" text="Install the CLI and push. This updates on its own." />
          ) : (
            <ul className="list">
              {(scans?.scans ?? []).map((s, i) => (
                <li key={s.id} className="row-in" style={{ ['--i' as string]: i }}>
                  <span className={`ic${s.newCount ? ' red' : ''}`}>{s.newCount ? <Alert /> : <Check />}</span>
                  <span>
                    <strong style={{ color: 'var(--ink)' }}>{s.kind === 'access' ? 'Access checks' : s.kind === 'dast' ? `ZAP ${s.dastMode === 'full' ? 'full scan' : 'baseline'}` : `${s.trigger === 'pre-push' ? 'Pre-push' : s.trigger === 'ci' ? 'CI' : 'Manual'} · ${s.scope === 'full' ? 'full scan' : 'changed files'}`}</strong>
                    <span className="small" style={{ display: 'block' }}>{s.branch ?? '—'}{s.commit ? ` · ${s.commit.slice(0, 7)}` : ''} · {s.newCount} new · {s.fixedCount} fixed</span>
                  </span>
                  <span className="meta">{timeAgo(s.createdAt)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <StagingTargets projectId={projectId} />

      {canSeeKeys ? (
        <section className="card reveal" style={{ ['--d' as string]: '300ms' }}>
          <div className="card-head">
            <h3>CLI keys</h3>
            {isAdmin ? <button className="btn btn-outline btn-sm" onClick={() => setNewKey(true)}><Plus /> New key</button> : null}
          </div>
          {tokens && tokens.tokens.length === 0 ? (
            <Empty icon={<Key />} title="No keys yet" text="Create a key for each developer machine or CI system." />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Name</th><th>Key</th><th>Last used</th><th>Created</th><th /></tr></thead>
                <tbody>
                  {(tokens?.tokens ?? []).map((t, i) => (
                    <tr key={t.id} className="row-in" style={{ ['--i' as string]: i, opacity: t.revokedAt ? 0.55 : undefined }}>
                      <td className="t-title">{t.name}{t.revokedAt ? <span className="pill p-mute" style={{ marginLeft: 8 }}>Revoked</span> : null}</td>
                      <td className="mono">{t.prefix}••••</td>
                      <td className="muted">{timeAgo(t.lastUsedAt)}</td>
                      <td className="muted">{timeAgo(t.createdAt)}{t.createdBy ? ` · ${t.createdBy}` : ''}</td>
                      <td style={{ textAlign: 'right' }}>
                        {isAdmin && !t.revokedAt ? <button className="btn btn-danger btn-sm" onClick={() => revoke(t)}>Revoke</button> : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      ) : null}

      {isAdmin && p ? (
        <section className="card card-pad reveal" style={{ ['--d' as string]: '340ms', display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: 1 }}>
            <strong style={{ color: 'var(--ink)' }}>Delete this project</strong>
            <p className="small" style={{ margin: '4px 0 0' }}>Removes its keys, scans, findings and evidence trail. This can't be undone.</p>
          </div>
          <button className="btn btn-danger" onClick={() => setConfirmDelete(true)}><Trash /> Delete project</button>
        </section>
      ) : null}

      {newKey ? <NewKey projectId={projectId} onClose={() => setNewKey(false)} onCreated={() => refreshTokens()} /> : null}
      {confirmDelete && p ? (
        <Modal title={`Delete ${p.name}?`} lead="Its keys stop working immediately and its findings and evidence are deleted." onClose={() => setConfirmDelete(false)}>
          <div className="modal-actions">
            <button className="btn btn-outline" onClick={() => setConfirmDelete(false)}>Cancel</button>
            <button className="btn btn-danger" onClick={deleteProject}><Trash /> Delete</button>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}
