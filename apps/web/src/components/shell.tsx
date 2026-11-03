'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import useSWR from 'swr';

import { api, fetcher } from '@/lib/api';
import { initials } from '@/lib/format';

import { Alert, Chevron, Folder, Home, LogoMark, Logout, Menu, Settings } from './icons';
import { useSession } from './session';

const NAV = [
  { href: '/overview', label: 'Overview', icon: Home },
  { href: '/findings', label: 'Findings', icon: Alert, badge: true },
  { href: '/projects', label: 'Projects', icon: Folder },
  { href: '/settings', label: 'Settings', icon: Settings },
];

export function Logo({ light = false }: { light?: boolean }) {
  return (
    <span className={`logo${light ? ' light' : ''}`}>
      <LogoMark />
      fortis
    </span>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { user, orgs, org, setOrgId } = useSession();
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [orgMenu, setOrgMenu] = useState(false);
  const { data: overview } = useSWR<{ open: Record<string, number> }>(`/v1/orgs/${org.id}/overview`, fetcher, { refreshInterval: 30_000 });
  const critical = overview?.open.critical ?? 0;

  useEffect(() => setOpen(false), [pathname]);

  const logout = async () => {
    await api('/v1/auth/logout', { method: 'POST', body: {} }).catch(() => {});
    router.replace('/login');
  };

  const current = NAV.find((n) => pathname.startsWith(n.href));

  return (
    <div className="shell">
      <aside className={`side${open ? ' open' : ''}`}>
        <Link href="/overview" aria-label="Fortis home">
          <Logo light />
        </Link>

        <div style={{ position: 'relative' }}>
          <button className="org-switch" onClick={() => setOrgMenu((v) => !v)} aria-expanded={orgMenu}>
            <span className="av">{initials(org.name)}</span>
            <span style={{ minWidth: 0 }}>
              <strong>{org.name}</strong>
              <small>{org.planName}</small>
            </span>
            <Chevron className="chev" />
          </button>
          {orgMenu ? (
            <div className="org-menu" role="menu">
              {orgs.map((o) => (
                <button
                  key={o.id}
                  role="menuitem"
                  onClick={() => {
                    setOrgId(o.id);
                    setOrgMenu(false);
                  }}
                >
                  {o.name}
                  <span className="small">{o.role}</span>
                </button>
              ))}
            </div>
          ) : null}
        </div>

        <div className="nav-label">Workspace</div>
        <nav aria-label="Main">
          {NAV.map(({ href, label, icon: Icon, badge }) => (
            <Link key={href} href={href} className={`nav-link${pathname.startsWith(href) ? ' on' : ''}`}>
              <Icon />
              {label}
              {badge && critical > 0 ? <span className="count">{critical}</span> : null}
            </Link>
          ))}
        </nav>

        <div className="side-foot">
          <div className="plan-card">
            <strong>{org.planName}</strong>
            <span>{org.plan === 'free' ? 'Results stay on your machine. Upgrade to sync findings.' : 'Findings sync from every push and CI run.'}</span>
          </div>
          <div className="user-row">
            <span className="av">{initials(user.name)}</span>
            <span style={{ minWidth: 0 }}>
              <strong>{user.name}</strong>
              <small>{user.email}</small>
            </span>
            <button onClick={logout} aria-label="Sign out" title="Sign out">
              <Logout />
            </button>
          </div>
        </div>
      </aside>
      {open ? <div className="scrim" style={{ zIndex: 65 }} onClick={() => setOpen(false)} /> : null}

      <div className="main">
        <header className="topbar">
          <button className="burger" onClick={() => setOpen(true)} aria-label="Open menu">
            <Menu />
          </button>
          <div className="crumbs">
            <span>{org.name}</span>
            <span>/</span>
            <span className="cur">{current?.label ?? 'Fortis'}</span>
          </div>
          <div className="right">
            <span className="live">
              <span className="s-dot" />
              Watching every release
            </span>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
