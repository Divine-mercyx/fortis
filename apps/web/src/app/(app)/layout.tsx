'use client';

import { useCallback, useEffect, useState, type ReactNode } from 'react';

import { SessionProvider } from '@/components/session';
import { Shell } from '@/components/shell';
import { Splash } from '@/components/splash';
import { StatusScreen } from '@/components/status';

const SPLASH_KEY = 'fortis.splash';
/** Long enough for the lock-in animation to finish. */
const SPLASH_MIN_MS = 2200;

/** Rendered only once the session has loaded, so mounting it tells the layout the app is ready. */
function Ready({ onReady }: { onReady: () => void }) {
  useEffect(() => onReady(), [onReady]);
  return null;
}

export default function AppLayout({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [held, setHeld] = useState(true);
  const onReady = useCallback(() => setReady(true), []);

  // A reload, or the first load of a visit, holds the splash until the lock-in animation has played.
  // Any other full page load clears it as soon as the session is in. In-app clicks never show it:
  // they get the spinning mark from loading.tsx.
  useEffect(() => {
    let seen = false;
    try {
      seen = sessionStorage.getItem(SPLASH_KEY) === '1';
      sessionStorage.setItem(SPLASH_KEY, '1');
    } catch {
      /* storage unavailable: play it each time */
    }
    // With reduced motion the animation is skipped, so there is nothing to wait for.
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
    const full = !seen || nav?.type === 'reload';
    const t = setTimeout(() => setHeld(false), full && !still ? SPLASH_MIN_MS : 0);
    return () => clearTimeout(t);
  }, []);

  return (
    <>
      <Splash done={ready && !held} />
      <SessionProvider
        fallback={null}
        unavailable={(retry) => (
          <>
            <Ready onReady={onReady} />
            <StatusScreen kind="down" onRetry={retry} />
          </>
        )}
      >
        <Ready onReady={onReady} />
        <Shell>{children}</Shell>
      </SessionProvider>
    </>
  );
}
