'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';

import { Arrow, Check } from '@/components/icons';
import { Words } from '@/components/motion';
import { PasswordField } from '@/components/password-field';
import { FormError } from '@/components/ui';
import { api } from '@/lib/api';

const PERKS = ['Secret and dependency scans', 'Pre-push hook for one project', 'Free forever, no card'];

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
      router.replace('/overview?welcome=1');
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <form className="auth-form" onSubmit={onSubmit} noValidate>
      <span className="eyebrow reveal">Start free</span>
      <h1><Words>Create your <span className="it accent">workspace.</span></Words></h1>
      <div className="perks reveal" style={{ ['--d' as string]: '150ms' }}>
        {PERKS.map((p) => (
          <span key={p}><i><Check /></i>{p}</span>
        ))}
      </div>
      <div className="reveal" style={{ ['--d' as string]: '220ms' }}>
        <FormError message={error} />
        <div className="form-row">
          <label className="field">
            <span>Full name</span>
            <input className="input" name="name" autoComplete="name" placeholder="Ada Okafor" required autoFocus />
          </label>
          <label className="field">
            <span>Company</span>
            <input className="input" name="company" autoComplete="organization" placeholder="PayWave" required />
          </label>
        </div>
        <label className="field">
          <span>Work email</span>
          <input className="input" name="email" type="email" autoComplete="email" placeholder="you@company.com" required />
        </label>
        <PasswordField name="password" label="Password" placeholder="At least 10 characters" autoComplete="new-password" meter />
        <button className="btn btn-primary btn-block btn-lg" disabled={busy} type="submit">
          {busy ? <span className="spinner" /> : null}
          {busy ? 'Creating your workspace…' : 'Create workspace'}
          {!busy ? <Arrow className="arr" /> : null}
        </button>
        <p className="fine">By creating a workspace you agree to the Fortis terms and privacy policy.</p>
        <p className="auth-alt">Already have an account? <Link href="/login">Sign in</Link></p>
      </div>
    </form>
  );
}
