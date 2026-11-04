import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactNode } from 'react';

import { Logo } from '@/components/shell';

export const metadata: Metadata = {
  title: 'Docs',
  description: 'Fortis Guard (fortis-watchdog): install, set up, every command, CI, staging tests, access checks and the HTTP API.',
};

/** Public: no sign-in needed, so the website and npm can link here. */
export default function DocsLayout({ children }: { children: ReactNode }) {
  return (
    <div className="docs">
      <header className="docs-top">
        <div className="docs-top-in">
          <Link href="/docs" className="docs-brand" aria-label="Fortis docs">
            <Logo /> <span className="docs-tag">Docs</span>
          </Link>
          <nav className="docs-top-links">
            <a href="https://fortis.dev">Website</a>
            <a href="https://www.npmjs.com/package/fortis-watchdog" target="_blank" rel="noreferrer noopener">npm</a>
            <Link href="/overview" className="btn btn-primary btn-sm">Open dashboard</Link>
          </nav>
        </div>
      </header>
      {children}
    </div>
  );
}
