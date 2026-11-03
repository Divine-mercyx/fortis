'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';
import useSWR from 'swr';

import { fetcher } from '@/lib/api';
import type { FindingRow, ProjectRow } from '@/lib/types';

import { Alert, Book, Folder, Home, Search, Settings } from './icons';
import { useSession } from './session';

type Item = { id: string; label: string; hint: string; href: string; icon: typeof Home; group: string };

const PAGES: Item[] = [
  { id: 'p-overview', label: 'Overview', hint: 'Posture, attention list and trends', href: '/overview', icon: Home, group: 'Pages' },
  { id: 'p-findings', label: 'Open findings', hint: 'Everything not yet fixed', href: '/findings', icon: Alert, group: 'Pages' },
  { id: 'p-critical', label: 'Critical findings', hint: 'What blocks the push', href: '/findings?severity=critical', icon: Alert, group: 'Pages' },
  { id: 'p-projects', label: 'Projects', hint: 'Repos, keys and scans', href: '/projects', icon: Folder, group: 'Pages' },
  { id: 'p-rules', label: 'Rules', hint: 'What Fortis checks and how to fix it', href: '/rules', icon: Book, group: 'Pages' },
  { id: 'p-settings', label: 'Settings', hint: 'Workspace, plan, team, audit log', href: '/settings', icon: Settings, group: 'Pages' },
];

/** ⌘K / Ctrl+K quick switcher for pages, projects and open findings. */
export function CommandPalette() {
  const { org } = useSession();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  const { data: projects } = useSWR<{ projects: ProjectRow[] }>(open ? `/v1/orgs/${org.id}/projects` : null, fetcher);
  const { data: findings } = useSWR<{ findings: FindingRow[] }>(
    open && q.trim().length > 1 ? `/v1/orgs/${org.id}/findings?status=open&limit=6&q=${encodeURIComponent(q.trim())}` : null,
    fetcher,
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === 'Escape') setOpen(false);
    };
    const onOpen = () => setOpen(true);
    document.addEventListener('keydown', onKey);
    window.addEventListener('fortis:palette', onOpen);
    return () => {
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('fortis:palette', onOpen);
    };
  }, []);

  useEffect(() => {
    if (open) {
      setQ('');
      setActive(0);
      setTimeout(() => input.current?.focus(), 10);
    }
  }, [open]);

  const items = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const pages = PAGES.filter((p) => !needle || p.label.toLowerCase().includes(needle) || p.hint.toLowerCase().includes(needle));
    const proj: Item[] = (projects?.projects ?? [])
      .filter((p) => !needle || p.name.toLowerCase().includes(needle))
      .slice(0, 5)
      .map((p) => ({ id: `pr-${p.id}`, label: p.name, hint: `${p.openFindings} open · ${p.openCritical} critical`, href: `/projects/${p.id}`, icon: Folder, group: 'Projects' }));
    const fnd: Item[] = (findings?.findings ?? []).map((f) => ({
      id: `f-${f.id}`, label: f.title, hint: `${f.severity} · ${f.projectName} · ${f.file}`, href: `/findings?projectId=${f.projectId}&id=${f.id}`, icon: Alert, group: 'Open findings',
    }));
    return [...pages, ...proj, ...fnd];
  }, [q, projects, findings]);

  if (!open) return null;

  const go = (item: Item | undefined) => {
    if (!item) return;
    setOpen(false);
    router.push(item.href);
  };

  let lastGroup = '';
  return (
    <>
      <div className="scrim" onClick={() => setOpen(false)} />
      <div className="palette" role="dialog" aria-modal="true" aria-label="Quick search">
        <div className="palette-input">
          <Search />
          <input
            ref={input}
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(items.length - 1, a + 1)); }
              if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
              if (e.key === 'Enter') go(items[active]);
            }}
            placeholder="Jump to a page, project or finding…"
            aria-label="Search"
          />
          <kbd>esc</kbd>
        </div>
        <ul className="palette-list">
          {items.map((it, i) => {
            const Icon = it.icon;
            const header = it.group !== lastGroup ? it.group : null;
            lastGroup = it.group;
            return (
              <li key={it.id}>
                {header ? <div className="palette-group">{header}</div> : null}
                <button className={i === active ? 'on' : ''} onMouseEnter={() => setActive(i)} onClick={() => go(it)}>
                  <Icon />
                  <span><strong>{it.label}</strong><small>{it.hint}</small></span>
                </button>
              </li>
            );
          })}
          {!items.length ? <li className="palette-empty">No matches.</li> : null}
        </ul>
      </div>
    </>
  );
}
