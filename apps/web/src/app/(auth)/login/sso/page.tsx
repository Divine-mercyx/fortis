'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';

import { Words } from '@/components/motion';
import { FormError } from '@/components/ui';
import { api } from '@/lib/api';
import { safeNext } from '@/lib/format';

/**
 * Where the identity provider sends people back. The code and state go to the API, which checks
 * them with the provider and starts the session; then on to where they were going.
 */
export default function SsoReturnPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [testEmail, setTestEmail] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    // Don't leave the one-time code in the address bar or history.
    window.history.replaceState(null, '', '/login/sso');
    if (params.get('error')) {
      setError(params.get('error_description') || "Your company's sign-in didn't let you through.");
      return;
    }
    if (!code || !state) {
      setError('This page is for coming back from your company sign-in. Start again from the sign-in page.');
      return;
    }
    api<{ next: string; test?: boolean; email?: string }>('/v1/auth/sso/callback', { method: 'POST', body: { code, state } })
      .then((r) => {
        if (r.test) {
          setTestEmail(r.email ?? '');
          setTimeout(() => router.replace('/settings#sso'), 1800);
          return;
        }
        router.replace(safeNext(r.next));
      })
      .catch((err) => setError((err as Error).message));
  }, [router]);

  return (
    <div className="auth-form">
      <span className="eyebrow reveal">Single sign-on</span>
      {testEmail !== null ? (
        <>
          <h1><Words>It <span className="it accent">works.</span></Words></h1>
          <p className="lead">The test sign-in came back as {testEmail}. Taking you back to Settings…</p>
        </>
      ) : error ? (
        <>
          <h1><Words>Couldn't sign <span className="it accent">you in.</span></Words></h1>
          <FormError message={error} />
          <Link href="/login?sso=1" className="btn btn-primary btn-block btn-lg">Try again</Link>
          <Link href="/login" className="btn btn-block" style={{ marginTop: 8 }}>Sign in with a password</Link>
        </>
      ) : (
        <>
          <h1><Words>Signing you <span className="it accent">in…</span></Words></h1>
          <p className="lead"><span className="spinner" /> Checking with your company's sign-in.</p>
        </>
      )}
    </div>
  );
}
