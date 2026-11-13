'use client';

import QRCode from 'qrcode';
import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import useSWR from 'swr';

import { Lock, Shield } from '@/components/icons';
import { PasswordField } from '@/components/password-field';
import { CopyButton, FormError, Modal, Skeleton, useToast } from '@/components/ui';
import { api, fetcher } from '@/lib/api';
import { dateTime } from '@/lib/format';

type Status = { enabled: boolean; enabledAt: string | null; recoveryCodesLeft: number };

/**
 * The six-digit code from an authenticator app. Numbers only, filled in by the phone's keyboard
 * suggestion or a password manager (autocomplete="one-time-code"). Calls `onComplete` at six digits.
 * With `allowRecovery`, it also takes a recovery code (xxxx-xxxx).
 */
export function CodeField({ name = 'code', label, recovery = false, onComplete, autoFocus = true }: {
  name?: string;
  label: string;
  recovery?: boolean;
  onComplete?: (code: string) => void;
  autoFocus?: boolean;
}) {
  const [value, setValue] = useState('');
  return (
    <label className="field">
      <span>{label}</span>
      <input
        className={`input code-input${recovery ? ' recovery' : ''}`}
        name={name}
        value={value}
        onChange={(e) => {
          const next = recovery ? e.target.value.slice(0, 12) : e.target.value.replace(/\D/g, '').slice(0, 6);
          setValue(next);
          if (!recovery && next.length === 6) onComplete?.(next);
        }}
        inputMode={recovery ? 'text' : 'numeric'}
        autoComplete={recovery ? 'off' : 'one-time-code'}
        autoCapitalize="off"
        spellCheck={false}
        placeholder={recovery ? 'xxxx-xxxx' : '000000'}
        required
        autoFocus={autoFocus}
        aria-label={label}
      />
    </label>
  );
}

/** Recovery codes, shown once, with copy and download. */
function RecoveryCodes({ codes }: { codes: string[] }) {
  const text = `Fortis recovery codes\nEach code signs you in once if you lose your phone.\n\n${codes.join('\n')}\n`;
  return (
    <div className="recovery">
      <ol className="recovery-grid">{codes.map((c) => <li key={c} className="mono">{c}</li>)}</ol>
      <div className="recovery-actions">
        <CopyButton text={codes.join('\n')} label="Copy codes" />
        <a className="btn btn-outline btn-sm" download="fortis-recovery-codes.txt" href={`data:text/plain;charset=utf-8,${encodeURIComponent(text)}`}>Download</a>
      </div>
    </div>
  );
}

/** Scan, confirm with a code, then save the recovery codes. */
function SetUp({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; otpauthUrl: string } | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    api<{ secret: string; otpauthUrl: string }>('/v1/auth/2fa/setup', { method: 'POST' })
      .then(async (s) => {
        if (!live) return;
        setSetup(s);
        setQr(await QRCode.toDataURL(s.otpauthUrl, { margin: 1, width: 216, errorCorrectionLevel: 'M' }));
      })
      .catch((err) => live && setError((err as Error).message));
    return () => {
      live = false;
    };
  }, []);

  async function confirm(code: string) {
    if (busy || code.length !== 6) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ recoveryCodes: string[] }>('/v1/auth/2fa/enable', { method: 'POST', body: { code } });
      setCodes(res.recoveryCodes);
      onDone();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (codes) {
    return (
      <Modal title="Save your recovery codes" lead="Two-factor authentication is on. If you lose your phone, each of these codes signs you in once. Keep them somewhere safe, like a password manager. You won't see them again." onClose={onClose}>
        <RecoveryCodes codes={codes} />
        <div className="modal-actions"><button className="btn btn-primary" onClick={onClose}>I've saved them</button></div>
      </Modal>
    );
  }

  const key = setup?.secret.replace(/(.{4})/g, '$1 ').trim();
  return (
    <Modal title="Turn on two-factor authentication" lead="Use Google Authenticator, Microsoft Authenticator, 1Password or any authenticator app." onClose={onClose}>
      <ol className="steps-2fa">
        <li>
          <strong>Scan this QR code with the app</strong>
          <div className="qr-box">{qr ? <img src={qr} alt="QR code to add Fortis to your authenticator app" width={216} height={216} /> : <Skeleton h={216} w={216} />}</div>
          {key ? (
            <div className="small">
              Can't scan it? Enter this key instead:
              <div className="code" style={{ marginTop: 6 }}><code>{key}</code><CopyButton text={setup!.secret} /></div>
            </div>
          ) : null}
        </li>
        <li>
          <strong>Enter the six-digit code the app shows</strong>
          <form onSubmit={(e) => { e.preventDefault(); void confirm(String(new FormData(e.currentTarget).get('code') ?? '')); }}>
            <FormError message={error} />
            <CodeField label="Code from the app" autoFocus={false} onComplete={(code) => void confirm(code)} />
            <div className="modal-actions">
              <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
              <button className="btn btn-primary" disabled={busy || !setup}>{busy ? <span className="spinner" /> : null} Turn on</button>
            </div>
          </form>
        </li>
      </ol>
    </Modal>
  );
}

function TurnOff({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api('/v1/auth/2fa/disable', { method: 'POST', body: { password: f.get('password'), code: f.get('code') } });
      toast('Two-factor authentication is off');
      onDone();
      onClose();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }
  return (
    <Modal title="Turn off two-factor authentication?" lead="Your password alone will sign you in again. Enter it and a current code to confirm." onClose={onClose}>
      <form onSubmit={onSubmit}>
        <FormError message={error} />
        <PasswordField name="password" label="Password" placeholder="Your password" autoComplete="current-password" />
        <CodeField label="Code from your authenticator app, or a recovery code" recovery autoFocus={false} />
        <div className="modal-actions">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn btn-danger" disabled={busy}>{busy ? <span className="spinner" /> : null} Turn off</button>
        </div>
      </form>
    </Modal>
  );
}

function NewCodes({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ recoveryCodes: string[] }>('/v1/auth/2fa/recovery-codes', { method: 'POST', body: { code: new FormData(e.currentTarget).get('code') } });
      setCodes(res.recoveryCodes);
      onDone();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (codes) {
    return (
      <Modal title="Your new recovery codes" lead="The old codes no longer work. Save these somewhere safe; you won't see them again." onClose={onClose}>
        <RecoveryCodes codes={codes} />
        <div className="modal-actions"><button className="btn btn-primary" onClick={onClose}>I've saved them</button></div>
      </Modal>
    );
  }
  return (
    <Modal title="Get new recovery codes" lead="New codes replace all of the old ones, used or not." onClose={onClose}>
      <form onSubmit={onSubmit}>
        <FormError message={error} />
        <CodeField label="Code from your authenticator app" />
        <div className="modal-actions">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy}>{busy ? <span className="spinner" /> : null} Get new codes</button>
        </div>
      </form>
    </Modal>
  );
}

/** Settings card: whether the signed-in user's account asks for a code, and the ways to change it. */
export function TwoFactorCard({ onChange }: { onChange?: () => void }) {
  const { data, mutate } = useSWR<Status>('/v1/auth/2fa', fetcher);
  const [open, setOpen] = useState<'setup' | 'off' | 'codes' | null>(null);
  const changed = () => {
    void mutate();
    onChange?.();
  };
  return (
    <section className="card reveal" style={{ ['--d' as string]: '100ms' }}>
      <div className="card-head">
        <h3>Two-factor authentication</h3>
        {data ? <span className={`pill ${data.enabled ? 'p-ok' : 'p-mute'}`}>{data.enabled ? 'On' : 'Off'}</span> : null}
      </div>
      <div className="card-pad two-factor">
        <span className="ic">{data?.enabled ? <Shield /> : <Lock />}</span>
        {!data ? (
          <Skeleton h={40} />
        ) : data.enabled ? (
          <div>
            <p style={{ margin: 0 }}>
              Signing in to your account asks for a code from your authenticator app. On since {data.enabledAt ? dateTime(data.enabledAt) : 'setup'}.
            </p>
            <p className="small" style={{ margin: '6px 0 14px', color: data.recoveryCodesLeft <= 3 ? 'var(--red)' : undefined }}>
              {data.recoveryCodesLeft} of 10 recovery codes left{data.recoveryCodesLeft <= 3 ? '. Get new ones soon.' : '.'}
            </p>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <button className="btn btn-outline btn-sm" onClick={() => setOpen('codes')}>Get new recovery codes</button>
              <button className="btn btn-danger btn-sm" onClick={() => setOpen('off')}>Turn off</button>
            </div>
          </div>
        ) : (
          <div>
            <p style={{ margin: '0 0 14px' }}>
              Add a second step to signing in: after your password, a six-digit code from an authenticator app on your phone. A stolen password alone won't get anyone in.
            </p>
            <button className="btn btn-primary btn-sm" onClick={() => setOpen('setup')}>Turn on</button>
          </div>
        )}
      </div>
      {/* At page level: inside the animated card, later cards would draw over the dialog. */}
      {open
        ? createPortal(
            open === 'setup' ? <SetUp onClose={() => setOpen(null)} onDone={changed} />
            : open === 'off' ? <TurnOff onClose={() => setOpen(null)} onDone={changed} />
            : <NewCodes onClose={() => setOpen(null)} onDone={changed} />,
            document.body,
          )
        : null}
    </section>
  );
}
