'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';

import { Arrow } from '@/components/icons';
import { Words } from '@/components/motion';
import { FormError } from '@/components/ui';
import { api } from '@/lib/api';

export default function SignupPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api('/v1/auth/signup', {
        method: 'POST',
        body: { name: f.get('name'), email: f.get('email'), company: f.get('company'), password: f.get('password') },
      });
      router.replace('/projects?welcome=1');
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <form className="auth-form" onSubmit={onSubmit} noValidate>
      <span className="eyebrow reveal">Start free</span>
      <h1><Words>Create your <span className="it accent">workspace.</span></Words></h1>
      <p className="lead reveal" style={{ ['--d' as string]: '150ms' }}>Free forever for one project. No card needed.</p>
      <div className="reveal" style={{ ['--d' as string]: '220ms' }}>
        <FormError message={error} />
        <label className="field">
          <span>Full name</span>
          <input className="input" name="name" autoComplete="name" placeholder="Your name" required />
        </label>
        <label className="field">
          <span>Work email</span>
          <input className="input" name="email" type="email" autoComplete="email" placeholder="you@company.com" required />
        </label>
        <label className="field">
          <span>Company</span>
          <input className="input" name="company" autoComplete="organization" placeholder="Company name" required />
        </label>
        <label className="field">
          <span>Password</span>
          <input className="input" name="password" type="password" autoComplete="new-password" placeholder="At least 10 characters" minLength={10} required />
        </label>
        <button className="btn btn-primary btn-block" disabled={busy} type="submit">
          {busy ? <span className="spinner" /> : null}
          {busy ? 'Creating workspace…' : 'Create workspace'}
          {!busy ? <Arrow className="arr" /> : null}
        </button>
        <p className="auth-alt">
          Already have an account? <Link href="/login">Sign in</Link>
        </p>
      </div>
    </form>
  );
}
