'use client';

import Link from 'next/link';
import type { ReactNode } from 'react';

import { Arrow, Check } from './icons';

/** Small "?" that explains a metric in plain language on hover or focus. */
export function InfoTip({ text }: { text: string }) {
  return (
    <span className="infotip" tabIndex={0} aria-label={text}>
      ?
      <span className="infotip-pop" role="tooltip">{text}</span>
    </span>
  );
}

/* ---------- Security posture score ---------- */

export type Posture = { score: number; grade: string; label: string; colour: string; reasons: string[] };

/**
 * A simple, explainable 0–100 score: start at 100 and subtract for what is open right now.
 * Criticals weigh most; old criticals cost extra. It's a guide for prioritising, not a certification.
 */
export function computePosture(open: Record<string, number>, oldestCriticalDays: number | null): Posture {
  const crit = open.critical ?? 0;
  const high = open.high ?? 0;
  const med = open.medium ?? 0;
  const reasons: string[] = [];
  let score = 100;
  const c = Math.min(60, crit * 25);
  const h = Math.min(24, high * 8);
  const m = Math.min(10, med * 2);
  const age = crit > 0 && oldestCriticalDays !== null && oldestCriticalDays > 3 ? 6 : 0;
  score -= c + h + m + age;
  if (crit) reasons.push(`−${c} for ${crit} open critical finding${crit === 1 ? '' : 's'}`);
  if (high) reasons.push(`−${h} for ${high} open high finding${high === 1 ? '' : 's'}`);
  if (med) reasons.push(`−${m} for ${med} open medium finding${med === 1 ? '' : 's'}`);
  if (age) reasons.push(`−${age} because a critical has been open for ${oldestCriticalDays} days`);
  if (!reasons.length) reasons.push('Nothing high-risk is open. Keep every push checked to stay here.');
  score = Math.max(0, score);
  const [grade, label, colour] =
    score >= 90 ? ['A', 'Strong', 'var(--green)'] :
    score >= 75 ? ['B', 'Good', '#4CB782'] :
    score >= 60 ? ['C', 'Needs work', 'var(--amber)'] :
    score >= 40 ? ['D', 'At risk', '#E07A2E'] : ['E', 'Critical risk', 'var(--red)'];
  return { score, grade, label, colour, reasons };
}

export function ScoreRing({ score, colour, grade }: { score: number; colour: string; grade: string }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  return (
    <div className="ring">
      <svg viewBox="0 0 130 130" aria-hidden="true">
        <circle cx="65" cy="65" r={r} className="ring-track" />
        <circle
          cx="65" cy="65" r={r} className="ring-fill"
          style={{ stroke: colour, strokeDasharray: c, ['--off' as string]: c - (c * score) / 100 }}
        />
      </svg>
      <div className="ring-center">
        <b style={{ color: colour }}>{grade}</b>
        <span>{score}/100</span>
      </div>
    </div>
  );
}

/* ---------- Setup checklist ---------- */

export type Step = { label: string; hint: string; done: boolean; href?: string; cta?: string };

export function Checklist({ steps }: { steps: Step[] }) {
  const done = steps.filter((s) => s.done).length;
  const pct = Math.round((done / steps.length) * 100);
  const next = steps.find((s) => !s.done);
  return (
    <div className="checklist">
      <div className="checklist-head">
        <div>
          <span className="eyebrow">Get set up</span>
          <h3>{done === steps.length ? 'You are fully set up.' : `${done} of ${steps.length} done. ${next ? `Next: ${next.label.toLowerCase()}.` : ''}`}</h3>
        </div>
        <div className="progress"><i style={{ width: `${pct}%` }} /></div>
      </div>
      <ol>
        {steps.map((s, i) => (
          <li key={s.label} className={`${s.done ? 'done' : ''}${s === next ? ' next' : ''}`} style={{ ['--i' as string]: i }}>
            <span className="tick">{s.done ? <Check /> : i + 1}</span>
            <span className="txt">
              <strong>{s.label}</strong>
              <small>{s.hint}</small>
            </span>
            {!s.done && s.href ? (
              <Link href={s.href} className="link-arrow">{s.cta ?? 'Start'} <Arrow /></Link>
            ) : null}
          </li>
        ))}
      </ol>
    </div>
  );
}

/* ---------- Release loop (same idea as the website) ---------- */

export function ReleaseLoop({ items }: { items: { k: string; title: string; value: ReactNode; hint: string; soon?: boolean }[] }) {
  return (
    <div className="loop">
      {items.map((it, i) => (
        <div key={it.k} className={`loop-step${it.soon ? ' soon' : ''}`} style={{ ['--i' as string]: i }}>
          <span className="loop-k">{String(i + 1).padStart(2, '0')} · {it.k}</span>
          <strong>{it.title}</strong>
          <b>{it.value}</b>
          <small>{it.hint}</small>
          {i < items.length - 1 ? <span className="loop-arrow" aria-hidden="true" /> : null}
        </div>
      ))}
    </div>
  );
}

/** Title row of a card, with an optional explainer beside the title and an action or legend on the right. */
export function SectionHead({ title, tip, children }: { title: ReactNode; tip?: string; children?: ReactNode }) {
  return (
    <div className="card-head">
      <h3>
        {title}
        {tip ? <> <InfoTip text={tip} /></> : null}
      </h3>
      {children}
    </div>
  );
}

/** One headline number with its label. Use inside a `.tiles stagger` row, which rises the tiles in one after another. */
export function StatTile({
  label,
  tip,
  value,
  tone,
  accent,
  sub,
  small = false,
}: {
  label: string;
  tip?: string;
  value: ReactNode;
  tone?: 'red' | 'green';
  /** Colour of the bar down the left edge. */
  accent?: string;
  sub?: string;
  /** For values that are words, not a number. */
  small?: boolean;
}) {
  return (
    <div className="tile" style={{ ['--c' as string]: accent }}>
      <div className="lbl">
        {label}
        {tip ? <> <InfoTip text={tip} /></> : null}
      </div>
      <div className={`v${tone ? ` ${tone}` : ''}${small ? ' sm' : ''}`}>{value}</div>
      {sub ? <div className="sub">{sub}</div> : null}
    </div>
  );
}
