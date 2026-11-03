import Link from 'next/link';
import type { ReactNode } from 'react';

import { Check } from '@/components/icons';
import { TypedTerminal, Words } from '@/components/motion';
import { Logo } from '@/components/shell';

const LINES = [
  '<span class="c-g">$</span> git push origin main',
  '<span class="c-m">fortis ▸ fintech rules · 214 files</span>',
  '<span class="c-r">✖ PUSH BLOCKED</span> · 2 critical',
  '  <span class="c-r">CRITICAL</span> live Paystack key · config.ts:4',
  '  <span class="c-r">CRITICAL</span> no ownership check · transfers.ts:41',
  '  <span class="c-g">fix</span> → fortis explain FX-OWN-001',
  '<span class="c-g">$</span> git push origin main',
  '<span class="c-g">✓ All checks passed</span> · 0 critical · pushed',
];

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="auth">
      <div className="auth-main">
        <Link href="/login" aria-label="Fortis">
          <Logo />
        </Link>
        {children}
        <p className="auth-foot">© 2026 Fortis. Made in Lagos.</p>
      </div>
      <aside className="auth-side" aria-hidden="true">
        <span className="orbit" />
        <span className="eyebrow accent-mint">Security on every release</span>
        <h2>
          <Words>
            Ship every day. <span className="it accent-mint">Prove it's safe.</span>
          </Words>
        </h2>
        <p className="reveal" style={{ ['--d' as string]: '300ms' }}>
          Fortis checks fintech code before every push and deploy, and turns every fix into evidence your
          pentester, partner banks and auditors can start from.
        </p>
        <div className="reveal" style={{ ['--d' as string]: '450ms' }}>
          <TypedTerminal lines={LINES} loop />
        </div>
        <div className="auth-points reveal" style={{ ['--d' as string]: '600ms' }}>
          {['Code stays on your machine', 'Production is never attacked', 'Naira pricing'].map((t) => (
            <span key={t}>
              <i><Check /></i>
              {t}
            </span>
          ))}
        </div>
      </aside>
    </div>
  );
}
