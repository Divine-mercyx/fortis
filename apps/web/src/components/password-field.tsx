'use client';

import { useState } from 'react';

import { Eye, EyeOff } from './icons';

/** Rough strength guide, shown only while typing a new password. */
export function passwordStrength(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string } {
  if (!pw) return { score: 0, label: '' };
  let score = 0;
  if (pw.length >= 10) score++;
  if (pw.length >= 14) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  if (pw.length < 10) score = Math.min(score, 1);
  const s = Math.min(4, score) as 0 | 1 | 2 | 3 | 4;
  return { score: s, label: ['Too short', 'Weak', 'Fair', 'Good', 'Strong'][s]! };
}

export function PasswordField({ name, label, placeholder, autoComplete, meter = false }: {
  name: string; label: string; placeholder: string; autoComplete: string; meter?: boolean;
}) {
  const [show, setShow] = useState(false);
  const [value, setValue] = useState('');
  const { score, label: strength } = passwordStrength(value);
  return (
    <label className="field">
      <span>{label}</span>
      <span className="pw-wrap">
        <input
          className="input"
          name={name}
          type={show ? 'text' : 'password'}
          autoComplete={autoComplete}
          placeholder={placeholder}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          minLength={meter ? 10 : undefined}
          required
        />
        <button type="button" className="pw-toggle" onClick={() => setShow((v) => !v)} aria-label={show ? 'Hide password' : 'Show password'}>
          {show ? <EyeOff /> : <Eye />}
        </button>
      </span>
      {meter && value ? (
        <span className="pw-meter" data-score={score}>
          <i /><i /><i /><i />
          <em>{strength}</em>
        </span>
      ) : null}
    </label>
  );
}
