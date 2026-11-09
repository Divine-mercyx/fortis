'use client';

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';

import { STATUS_LABEL } from '@/lib/format';

import { Alert, Check, Copy as CopyIcon, X } from './icons';

/* ---------- Toasts ---------- */

type Toast = { id: number; text: string; bad?: boolean };
const ToastCtx = createContext<(text: string, bad?: boolean) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, bad = false) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, bad }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3600);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast${t.bad ? ' bad' : ''}`}>
            {t.bad ? <Alert /> : <Check />}
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/* ---------- Overlays ---------- */

function useEscape(onClose: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);
}

export function Modal({ title, lead, onClose, children }: { title: string; lead?: string; onClose: () => void; children: ReactNode }) {
  useEscape(onClose);
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <h3>{title}</h3>
        {lead ? <p className="lead">{lead}</p> : null}
        {children}
      </div>
    </>
  );
}

export function Drawer({ onClose, children }: { onClose: () => void; children: ReactNode }) {
  useEscape(onClose);
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        {children}
      </aside>
    </>
  );
}

export const CloseButton = ({ onClick }: { onClick: () => void }) => (
  <button className="x-btn" onClick={onClick} aria-label="Close">
    <X />
  </button>
);

/* ---------- Small pieces ---------- */

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={`copy${done ? ' done' : ''}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1600);
        } catch {
          /* clipboard blocked */
        }
      }}
    >
      {done ? <Check /> : <CopyIcon />}
      {done ? 'Copied' : label}
    </button>
  );
}

export const CodeLine = ({ cmd }: { cmd: string }) => (
  <div className="code">
    <span className="p">$</span>
    <code>{cmd}</code>
    <CopyButton text={cmd} />
  </div>
);

export const SeverityPill = ({ severity }: { severity: string }) => <span className={`pill p-${severity}`}>{severity}</span>;

export const StatusTag = ({ status }: { status: string }) => (
  <span className={`st-${status}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontWeight: 800, fontSize: 12.5 }}>
    <span className="s-dot" />
    {STATUS_LABEL[status] ?? status}
  </span>
);

/** Whether a leaked key still works, from `fortis scan --verify`. */
const SECRET_TAG = {
  live: { label: 'Live key', cls: 'p-critical', title: 'The provider accepted this key on the last check: rotate it first.' },
  revoked: { label: 'Revoked', cls: 'p-ok', title: 'The provider rejected this key on the last check. Remove it from the code anyway.' },
  unknown: { label: 'Liveness unknown', cls: 'p-mute', title: 'The last check got no clear answer (timeout, rate limit or provider error). Treat it as live.' },
} as const;

export const SecretTag = ({ status }: { status?: string | null }) => {
  const tag = status ? SECRET_TAG[status as keyof typeof SECRET_TAG] : undefined;
  return tag ? <span className={`pill ${tag.cls}`} title={tag.title}>{tag.label}</span> : null;
};

export const Skeleton = ({ h = 16, w = '100%' }: { h?: number; w?: number | string }) => (
  <div className="skeleton" style={{ height: h, width: w }} />
);

export function Empty({ icon, title, text, action }: { icon: ReactNode; title: string; text: string; action?: ReactNode }) {
  return (
    <div className="empty">
      <div className="ic">{icon}</div>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}

export const FormError = ({ message }: { message: string | null }) =>
  message ? (
    <div className="form-error" role="alert">
      <Alert />
      {message}
    </div>
  ) : null;
