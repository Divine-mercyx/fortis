'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useState } from 'react';

import { Arrow } from '@/components/icons';
import { Words } from '@/components/motion';
import { PasswordField } from '@/components/password-field';
import { FormError } from '@/components/ui';
import { api } from '@/lib/api';
import { safeNext } from '@/lib/format';

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api('/v1/auth/login', { method: 'POST', body: { email: form.get('email'), password: form.get('password') } });
      router.replace(safeNext(params.get('next')));
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
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
