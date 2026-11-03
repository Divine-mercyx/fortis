import Link from 'next/link';
import type { ReactNode } from 'react';

import { Earth } from '@/components/earth';
import { Alert, File, Lock, Target } from '@/components/icons';
import { Words } from '@/components/motion';
import { Logo } from '@/components/shell';

const CARDS = [
  { cls: 'fc-1', icon: Alert, tone: 'red', k: 'Pre-push', title: 'Push blocked · live Paystack key', d: 'Caught on the laptop, fix included' },
  { cls: 'fc-2', icon: Target, tone: '', k: 'Staging', title: '37 routes access-checked', d: 'With your own test users' },
  { cls: 'fc-3', icon: File, tone: '', k: 'Evidence', title: 'Pack ready for your pentester', d: 'CBN · NDPA · PCI DSS mapped' },
];

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="auth">
      <div className="auth-main">
        <div className="auth-top">
          <Link href="/login" aria-label="Fortis">
            <Logo />
          </Link>
          <a href="https://fortis.dev" className="auth-back">fortis.dev ↗</a>
        </div>
        {children}
        <div className="auth-trust">
          <Lock />
          <span>Your source code never leaves your machine. Fortis only receives masked finding details.</span>
        </div>
        <p className="auth-foot">© 2026 Fortis. Made in Lagos.</p>
      </div>

      <aside className="auth-side" data-earth-stage aria-hidden="true">
        <div className="auth-side-copy">
          <span className="eyebrow accent-mint reveal">Security on every release</span>
          <h2>
            <Words delay={100}>
              Africa's fintech, <span className="it accent-mint">secured between pentests.</span>
            </Words>
          </h2>
        </div>

        <div className="auth-stage">
          <Earth />
          {CARDS.map(({ cls, icon: Icon, tone, k, title, d }, i) => (
            <div key={cls} className={`glass-card ${cls}`} style={{ ['--d' as string]: `${500 + i * 160}ms` }}>
              <span className={`gc-ic ${tone}`}><Icon /></span>
              <span>
                <span className={`gc-k ${tone}`}>{k}</span>
                <strong>{title}</strong>
                <span className="gc-d">{d}</span>
              </span>
            </div>
          ))}
        </div>

        <div className="auth-stats reveal" style={{ ['--d' as string]: '900ms' }}>
          <div><b>Every push</b><span>checked before code leaves the laptop</span></div>
          <div><b>0 bytes</b><span>of source code uploaded</span></div>
          <div><b>₦ pricing</b><span>billed locally, no dollar card</span></div>
        </div>
      </aside>
    </div>
  );
}
