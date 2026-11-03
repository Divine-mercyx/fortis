'use client';

import type { ReactNode } from 'react';

import { SessionProvider } from '@/components/session';
import { Shell } from '@/components/shell';
import { LogoMark } from '@/components/icons';

function Loading() {
  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: 'var(--navy)' }}>
      <LogoMark style={{ width: 44, height: 50, animation: 'bob 2.4s var(--ease-in-out) infinite' }} />
    </div>
  );
}

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <SessionProvider fallback={<Loading />}>
      <Shell>{children}</Shell>
    </SessionProvider>
  );
}
