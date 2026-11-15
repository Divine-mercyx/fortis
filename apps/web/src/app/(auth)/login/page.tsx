'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useState } from 'react';

import { Arrow } from '@/components/icons';
import { Words } from '@/components/motion';
import { PasswordField } from '@/components/password-field';
import { CodeField } from '@/components/two-factor';
import { FormError } from '@/components/ui';
import { api, type ApiError } from '@/lib/api';
import { safeNext } from '@/lib/format';

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Set when the password was right and the account asks for an authenticator code.
  const [challenge, setChallenge] = useState<string | null>(null);
  const [useRecovery, setUseRecovery] = useState(false);
  // Single sign-on: just the work email, then the company's identity provider.
  const [sso, setSso] = useState(params.get('sso') === '1');
  const [email, setEmail] = useState('');

  async function startSso(address: string) {
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ authorizationUrl: string }>('/v1/auth/sso/start', { method: 'POST', body: { email: address, next: safeNext(params.get('next')) } });
      window.location.assign(res.authorizationUrl);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ twoFactorRequired?: boolean; challenge?: string }>('/v1/auth/login', { method: 'POST', body: { email: form.get('email'), password: form.get('password') } });
      if (res.twoFactorRequired && res.challenge) {
        setChallenge(res.challenge);
        setBusy(false);
        return;
      }
      router.replace(safeNext(params.get('next')));
    } catch (err) {
      const e = err as ApiError;
      // This domain signs in through its identity provider: go straight there.
      if (e.code === 'SSO_REQUIRED') {
        setSso(true);
        setEmail(String(form.get('email') ?? ''));
        setError(null);
        void startSso(String(form.get('email') ?? ''));
        return;
      }
      setError(e.message);
      setBusy(false);
    }
  }

  async function submitCode(code: string) {
    if (busy || !challenge) return;
    setBusy(true);
    setError(null);
    try {
      await api('/v1/auth/login/2fa', { method: 'POST', body: { challenge, code } });
      router.replace(safeNext(params.get('next')));
    } catch (err) {
      const e = err as ApiError;
      setError(e.message);
      setBusy(false);
      // Expired or too many wrong codes: back to the password.
      if (e.code === 'CHALLENGE_EXPIRED') setChallenge(null);
    }
  }

  if (challenge) {
    return (
      <form className="auth-form" onSubmit={(e) => { e.preventDefault(); void submitCode(String(new FormData(e.currentTarget).get('code') ?? '')); }} noValidate>
        <span className="eyebrow reveal">Two-factor authentication</span>
        <h1><Words>One more <span className="it accent">step.</span></Words></h1>
        <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>
          {useRecovery
            ? 'Enter one of the recovery codes you saved when you turned on two-factor authentication. Each works once.'
            : 'Open your authenticator app and enter the six-digit code for Fortis.'}
        </p>
        <div className="reveal" style={{ ['--d' as string]: '220ms' }}>
          <FormError message={error} />
          <CodeField key={useRecovery ? 'recovery' : 'totp'} label={useRecovery ? 'Recovery code' : 'Six-digit code'} recovery={useRecovery} onComplete={(code) => void submitCode(code)} />
          <button className="btn btn-primary btn-block btn-lg" disabled={busy} type="submit">
            {busy ? <span className="spinner" /> : null}
            {busy ? 'Checking…' : 'Verify and sign in'}
            {!busy ? <Arrow className="arr" /> : null}
          </button>
          <div className="auth-divider"><span>{useRecovery ? 'Have your phone?' : 'Lost your phone?'}</span></div>
          <button type="button" className="btn btn-outline btn-block btn-lg" onClick={() => { setUseRecovery(!useRecovery); setError(null); }}>
            {useRecovery ? 'Use the authenticator app' : 'Use a recovery code'}
          </button>
          <button type="button" className="btn btn-block" style={{ marginTop: 8 }} onClick={() => { setChallenge(null); setUseRecovery(false); setError(null); }}>
            Back to email and password
          </button>
        </div>
      </form>
    );
  }

  if (sso) {
    return (
      <form className="auth-form" onSubmit={(e) => { e.preventDefault(); void startSso(email); }} noValidate>
        <span className="eyebrow reveal">Single sign-on</span>
        <h1><Words>Sign in with your <span className="it accent">company.</span></Words></h1>
        <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>
          Enter your work email and we'll send you to your company's sign-in: Google Workspace, Microsoft or Okta.
        </p>
        <div className="reveal" style={{ ['--d' as string]: '220ms' }}>
          <FormError message={error} />
          <label className="field">
            <span>Work email</span>
            <input className="input" name="email" type="email" autoComplete="email" placeholder="you@company.com" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <button className="btn btn-primary btn-block btn-lg" disabled={busy || !email.includes('@')} type="submit">
            {busy ? <span className="spinner" /> : null}
            {busy ? 'Opening your sign-in…' : 'Continue'}
            {!busy ? <Arrow className="arr" /> : null}
          </button>
          <button type="button" className="btn btn-block" style={{ marginTop: 8 }} onClick={() => { setSso(false); setError(null); }}>
            Sign in with a password instead
          </button>
        </div>
      </form>
    );
  }

  return (
    <form className="auth-form" onSubmit={onSubmit} noValidate>
      <span className="eyebrow reveal">Welcome back</span>
      <h1><Words>Sign in to <span className="it accent">Fortis.</span></Words></h1>
      <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>
        Pick up where your last push left off: open findings, fixes and the evidence trail.
      </p>
      <div className="reveal" style={{ ['--d' as string]: '220ms' }}>
        <FormError message={error} />
        <label className="field">
          <span>Work email</span>
          <input className="input" name="email" type="email" autoComplete="email" placeholder="you@company.com" required autoFocus />
        </label>
        <PasswordField name="password" label="Password" placeholder="Your password" autoComplete="current-password" />
        <button className="btn btn-primary btn-block btn-lg" disabled={busy} type="submit">
          {busy ? <span className="spinner" /> : null}
          {busy ? 'Signing in…' : 'Sign in'}
          {!busy ? <Arrow className="arr" /> : null}
        </button>
        <button type="button" className="btn btn-outline btn-block btn-lg" style={{ marginTop: 10 }} onClick={() => { setSso(true); setError(null); }}>
          Sign in with SSO
        </button>
        <div className="auth-divider"><span>New to Fortis?</span></div>
        <Link href="/signup" className="btn btn-outline btn-block btn-lg">Create a free workspace</Link>
      </div>
    </form>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
