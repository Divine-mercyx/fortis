'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import useSWR from 'swr';

import { api, fetcher } from '@/lib/api';
import { DOCS_URL } from '@/lib/cli';
import { initials } from '@/lib/format';

import { Alert, Book, Contrast, File, Folder, Help, Terminal, Home, LogoMark, Logout, Menu, Search, Settings, WallsMark } from './icons';
import { CommandPalette } from './palette';
import { useSession } from './session';

const NAV = [
  { href: '/overview', label: 'Overview', icon: Home },
  { href: '/findings', label: 'Findings', icon: Alert, badge: true },
  { href: '/projects', label: 'Projects', icon: Folder },
  { href: '/rules', label: 'Rules', icon: Book },
  { href: '/evidence', label: 'Evidence', icon: File },
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

type Theme = 'system' | 'light' | 'dark';
const THEME_KEY = 'fortis.theme';
const THEMES: { id: Theme; label: string }[] = [
  { id: 'system', label: 'System' },
  { id: 'light', label: 'Light' },
  { id: 'dark', label: 'Dark' },
];

/** System follows the device. Light and Dark are remembered and set data-theme on <html>. */
function useTheme() {
  const [theme, setThemeState] = useState<Theme>('system');

  useEffect(() => {
    try {
      const saved = localStorage.getItem(THEME_KEY);
      if (saved === 'light' || saved === 'dark') setThemeState(saved);
    } catch {
      /* storage unavailable */
    }
  }, []);

  const setTheme = (next: Theme) => {
    setThemeState(next);
    if (next === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', next);
    try {
      if (next === 'system') localStorage.removeItem(THEME_KEY);
      else localStorage.setItem(THEME_KEY, next);
    } catch {
      /* storage unavailable: the choice lasts for this page only */
    }
  };

  return [theme, setTheme] as const;
}

export function Shell({ children }: { children: ReactNode }) {
  const { user, orgs, org, setOrgId } = useSession();
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [orgMenu, setOrgMenu] = useState(false);
  const [themeMenu, setThemeMenu] = useState(false);
  const [theme, setTheme] = useTheme();
  const { data: overview } = useSWR<{ open: Record<string, number> }>(`/v1/orgs/${org.id}/overview`, fetcher, { refreshInterval: 30_000 });
  const critical = overview?.open.critical ?? 0;

  useEffect(() => setOpen(false), [pathname]);

  // Escape closes whichever rail menu is open.
  useEffect(() => {
    if (!orgMenu && !themeMenu) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      setOrgMenu(false);
      setThemeMenu(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [orgMenu, themeMenu]);

  const logout = async () => {
    await api('/v1/auth/logout', { method: 'POST', body: {} }).catch(() => {});
    router.replace('/login');
  };

  const current = NAV.find((n) => pathname.startsWith(n.href));

  return (
    <div className="shell">
      <aside className={`side${open ? ' open' : ''}`}>
        <Link href="/overview" aria-label="Fortis home" className="rail-logo">
          <WallsMark />
        </Link>

        <nav aria-label="Main">
          {NAV.map(({ href, label, icon: Icon, badge }) => {
            const on = pathname.startsWith(href);
            return (
              <Link key={href} href={href} className={`nav-link${on ? ' on' : ''}`} aria-current={on ? 'page' : undefined}>
                <Icon />
                <span className="tip">{label}</span>
                {badge && critical > 0 ? (
                  <span className="count" aria-label={`${critical} open critical`}>
                    {critical}
                  </span>
                ) : null}
              </Link>
            );
          })}
          <a href={DOCS_URL} className="nav-link" target="_blank" rel="noreferrer noopener">
            <Terminal />
            <span className="tip">Docs</span>
          </a>
        </nav>

        <div className="side-foot">
          <a className="nav-link" href="https://fortis.dev/faq.html" target="_blank" rel="noreferrer noopener">
            <Help />
            <span className="tip">Help</span>
          </a>
          <div style={{ position: 'relative' }}>
            <button className="nav-link" onClick={() => { setThemeMenu((v) => !v); setOrgMenu(false); }} aria-expanded={themeMenu} aria-haspopup="true">
              <Contrast />
              <span className="tip">Theme</span>
            </button>
            {themeMenu ? (
              <div className="org-menu" role="radiogroup" aria-label="Theme">
                <div className="org-plan">Theme</div>
                {THEMES.map((t) => (
                  <button
                    key={t.id}
                    role="radio"
                    aria-checked={theme === t.id}
                    onClick={() => {
                      setTheme(t.id);
                      setThemeMenu(false);
                    }}
                  >
                    {t.label}
                    {t.id === 'system' ? <span className="small">Follows your device</span> : null}
                  </button>
                ))}
              </div>
            ) : null}
          </div>
          <div style={{ position: 'relative' }}>
            <button className="org-switch" onClick={() => { setOrgMenu((v) => !v); setThemeMenu(false); }} aria-expanded={orgMenu} aria-label={`Organisation: ${org.name}`}>
              <span className="av">{initials(org.name)}</span>
              <span className="who">
                <strong>{org.name}</strong>
                <small>{org.planName}</small>
              </span>
              <span className="tip">
                {org.name} · {org.planName}
              </span>
            </button>
            {orgMenu ? (
              <div className="org-menu" role="menu">
                <div className="org-plan">{org.planName} plan</div>
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
          <div className="user-row" title={`${user.name} · ${user.email}`}>
            <span className="av">{initials(user.name)}</span>
            <span className="who">
              <strong>{user.name}</strong>
              <small>{user.email}</small>
            </span>
          </div>
          <button className="nav-link" onClick={logout}>
            <Logout />
            <span className="tip">Sign out</span>
          </button>
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
            <button className="kbar" onClick={() => window.dispatchEvent(new Event('fortis:palette'))}>
              <Search />
              <span>Search</span>
              <kbd>⌘K</kbd>
            </button>
            <span className="live">
              <span className="s-dot" />
              Watching every release
            </span>
          </div>
        </header>
        <main className="content">{children}</main>
        <CommandPalette />
      </div>
    </div>
  );
}
