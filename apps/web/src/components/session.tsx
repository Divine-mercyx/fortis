'use client';

import { usePathname, useRouter } from 'next/navigation';
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import useSWR from 'swr';

import { ApiError, fetcher } from '@/lib/api';
import type { Me, Org, User } from '@/lib/types';

type Session = {
  user: User;
  orgs: Org[];
  org: Org;
  setOrgId: (id: string) => void;
  refresh: () => Promise<unknown>;
};

const SessionCtx = createContext<Session | null>(null);
const ORG_KEY = 'fortis.org';

export function useSession(): Session {
  const s = useContext(SessionCtx);
  if (!s) throw new Error('useSession must be used inside <SessionProvider>');
  return s;
}

/**
 * Loads the signed-in user; sends anyone signed out to /login and back here afterwards.
 * If the session cannot be loaded for any other reason (server down, no connection), it renders `unavailable`
 * and keeps retrying, so nobody is left on the loading screen.
 */
export function SessionProvider({
  children,
  fallback,
  unavailable,
}: {
  children: ReactNode;
  fallback: ReactNode;
  unavailable: (retry: () => void) => ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const { data, error, mutate } = useSWR<Me>('/v1/auth/me', fetcher, { revalidateOnFocus: true, shouldRetryOnError: false });
  const [orgId, setOrgIdState] = useState<string | null>(null);

  useEffect(() => {
    try {
      setOrgIdState(localStorage.getItem(ORG_KEY));
    } catch {
      /* storage unavailable */
    }
  }, []);

  useEffect(() => {
    if (error instanceof ApiError && error.status === 401) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
    }
  }, [error, pathname, router]);

  // Anything but "signed out" means Fortis could not be reached.
  const down = Boolean(error) && !(error instanceof ApiError && error.status === 401);

  useEffect(() => {
    if (!down) return;
    const t = setInterval(() => void mutate(), 15_000);
    return () => clearInterval(t);
  }, [down, mutate]);

  const setOrgId = useCallback((id: string) => {
    setOrgIdState(id);
    try {
      localStorage.setItem(ORG_KEY, id);
    } catch {
      /* ignore */
    }
  }, []);

  const value = useMemo<Session | null>(() => {
    if (!data || !data.orgs.length) return null;
    const org = data.orgs.find((o) => o.id === orgId) ?? data.orgs[0]!;
    return { user: data.user, orgs: data.orgs, org, setOrgId, refresh: () => mutate() };
  }, [data, orgId, setOrgId, mutate]);

  if (!value) return <>{down ? unavailable(() => void mutate()) : fallback}</>;
  return (
    <SessionCtx.Provider value={value}>
      {/* Already signed in when the server stopped answering: keep the page, and say so. */}
      {down ? <div className="net-bar" role="status">Fortis can&apos;t reach its server. Retrying…</div> : null}
      {children}
    </SessionCtx.Provider>
  );
}
