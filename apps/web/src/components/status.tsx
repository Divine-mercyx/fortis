'use client';

import { useEffect, useState } from 'react';

import { WallsMark } from './icons';

/** The mark with both walls turning: the loader for moving between pages. */
export function MarkSpinner() {
  return (
    <svg className="mark-spin" viewBox="0 0 56 56" aria-hidden="true">
      <g fill="none" stroke="currentColor">
        <g className="spin-a">
          <circle cx="28" cy="28" r="23" strokeWidth="8" strokeDasharray="132.5 12" transform="rotate(105 28 28)" />
        </g>
        <g className="spin-b">
          <circle cx="28" cy="28" r="11.5" strokeWidth="7" strokeDasharray="63.3 9" transform="rotate(-22.6 28 28)" />
        </g>
      </g>
      <circle cx="28" cy="28" r="4.5" fill="#13955F" />
    </svg>
  );
}

const COPY = {
  offline: {
    title: "You're offline.",
    text: "Fortis can't reach the internet from this device. Check your Wi-Fi or mobile data.",
    note: "This clears by itself when you're back online.",
  },
  down: {
    title: 'Fortis is temporarily unavailable.',
    text: "Our server isn't responding right now. Nothing is wrong on your side, and your data is safe.",
    note: 'Trying again every 15 seconds.',
  },
} as const;

/** Full-screen notice for a lost connection or an unreachable server. Matches the pages the service worker shows. */
export function StatusScreen({ kind, onRetry }: { kind: keyof typeof COPY; onRetry?: () => void }) {
  const copy = COPY[kind];
  return (
    <div className="status" role="alert">
      <div>
        <WallsMark className="status-mark" />
        <h1>{copy.title}</h1>
        <p>{copy.text}</p>
        {onRetry ? (
          <button type="button" className="btn btn-primary" onClick={onRetry}>
            Try again
          </button>
        ) : null}
        <p className="status-note">{copy.note}</p>
      </div>
    </div>
  );
}

/**
 * Mounted once for the whole app. Covers the page with the offline screen while this device has no connection,
 * and registers the service worker that replaces the browser's error page on a failed page load.
 */
export function NetworkWatch() {
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    const sync = () => setOffline(navigator.onLine === false);
    sync();
    window.addEventListener('online', sync);
    window.addEventListener('offline', sync);
    return () => {
      window.removeEventListener('online', sync);
      window.removeEventListener('offline', sync);
    };
  }, []);

  useEffect(() => {
    // Production only: on a developer machine the worker would outlive the dev server and answer for
    // whatever else is later run on the same localhost port.
    if (process.env.NODE_ENV !== 'production' || !('serviceWorker' in navigator)) return;
    navigator.serviceWorker.register('/sw.js').catch(() => {
      /* the app works without it */
    });
  }, []);

  return offline ? <StatusScreen kind="offline" /> : null;
}
