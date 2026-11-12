import type { SVGProps } from 'react';

type P = SVGProps<SVGSVGElement>;
const base = { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round', strokeLinejoin: 'round' } as const;

export const LogoMark = (p: P) => (
  <svg viewBox="0 0 100 115" aria-hidden="true" {...p}>
    <defs>
      <linearGradient id="fortisShield" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="#13955F" />
        <stop offset="1" stopColor="#0B5D45" />
      </linearGradient>
    </defs>
    <path d="M50 3 L93 19 V56 C93 83 74 101 50 112 C26 101 7 83 7 56 V19 Z" fill="url(#fortisShield)" />
    <path d="M30 57 L45 72 L72 43" fill="none" stroke="#fff" strokeWidth="9" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

/** The three-walls mark: the "o" of the wordmark. Walls take the current colour; the core stays green. */
export const WallsMark = (p: P) => (
  <svg viewBox="0 0 56 56" aria-hidden="true" {...p}>
    <g fill="none" stroke="currentColor">
      <circle cx="28" cy="28" r="23" strokeWidth="8" strokeDasharray="132.5 12" transform="rotate(105 28 28)" />
      <circle cx="28" cy="28" r="11.5" strokeWidth="7" strokeDasharray="63.3 9" transform="rotate(-22.6 28 28)" />
    </g>
    <circle cx="28" cy="28" r="4.5" fill="#13955F" />
  </svg>
);

export const Contrast = (p: P) => <svg {...base} {...p}><circle cx="12" cy="12" r="9" /><path d="M12 3v18" /><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none" /></svg>;
export const Help = (p: P) => <svg {...base} {...p}><circle cx="12" cy="12" r="9" /><path d="M9.5 9.5a2.5 2.5 0 1 1 3.6 2.2c-.7.4-1.1 1-1.1 1.8M12 17h.01" /></svg>;
export const Arrow = (p: P) => <svg {...base} strokeWidth={2} {...p}><path d="M5 12h14M13 6l6 6-6 6" /></svg>;
export const Chevron = (p: P) => <svg {...base} strokeWidth={2} {...p}><path d="m6 9 6 6 6-6" /></svg>;
export const Check = (p: P) => <svg {...base} strokeWidth={3} {...p}><path d="M5 12.5 10 17 19 7" /></svg>;
export const Home = (p: P) => <svg {...base} {...p}><path d="m3 11 9-7 9 7M5 10v10h14V10" /></svg>;
export const Layers = (p: P) => <svg {...base} {...p}><path d="m12 3 9 5-9 5-9-5z" /><path d="m3 13 9 5 9-5" /></svg>;
export const Alert = (p: P) => <svg {...base} {...p}><path d="M12 3 2 20h20z" /><path d="M12 10v4M12 17h.01" /></svg>;
export const Folder = (p: P) => <svg {...base} {...p}><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></svg>;
export const Settings = (p: P) => <svg {...base} {...p}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z" /></svg>;
export const Terminal = (p: P) => <svg {...base} {...p}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="m7 9 3 3-3 3M13 15h4" /></svg>;
export const Key = (p: P) => <svg {...base} {...p}><circle cx="7.5" cy="15.5" r="4.5" /><path d="m10.7 12.3 9.3-9.3M17 6l3 3M15 8l2 2" /></svg>;
export const Shield = (p: P) => <svg {...base} {...p}><path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z" /><path d="m9 12 2 2 4-4" /></svg>;
export const Users = (p: P) => <svg {...base} {...p}><circle cx="9" cy="8" r="3.5" /><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6" /><circle cx="17.5" cy="9" r="2.5" /><path d="M16 14.2c2.9.3 5 2.6 5 5.8" /></svg>;
export const Clock = (p: P) => <svg {...base} {...p}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>;
export const Git = (p: P) => <svg {...base} {...p}><circle cx="6" cy="6" r="2.5" /><circle cx="6" cy="18" r="2.5" /><circle cx="18" cy="8" r="2.5" /><path d="M6 8.5v7M18 10.5c0 4-6 3-11 6" /></svg>;
export const Search = (p: P) => <svg {...base} {...p}><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></svg>;
export const Copy = (p: P) => <svg {...base} {...p}><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" /></svg>;
export const Plus = (p: P) => <svg {...base} strokeWidth={2} {...p}><path d="M12 5v14M5 12h14" /></svg>;
export const X = (p: P) => <svg {...base} strokeWidth={2} {...p}><path d="M6 6l12 12M18 6 6 18" /></svg>;
export const Menu = (p: P) => <svg {...base} strokeWidth={2} {...p}><path d="M4 7h16M4 12h16M4 17h16" /></svg>;
export const Logout = (p: P) => <svg {...base} {...p}><path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 17l5-5-5-5M15 12H3" /></svg>;
export const Trend = (p: P) => <svg {...base} {...p}><path d="m3 17 6-6 4 4 8-8M15 7h6v6" /></svg>;
export const File = (p: P) => <svg {...base} {...p}><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5M9 14l2 2 4-4" /></svg>;
export const Trash = (p: P) => <svg {...base} {...p}><path d="M4 7h16M10 11v6M14 11v6M5 7l1 13a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1l1-13M9 7V4h6v3" /></svg>;
export const Pulse = (p: P) => <svg {...base} {...p}><path d="M3 12h4l3-7 4 14 3-7h4" /></svg>;
export const Lock = (p: P) => <svg {...base} {...p}><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>;
export const Target = (p: P) => <svg {...base} {...p}><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1.2" fill="currentColor" /></svg>;
export const Eye = (p: P) => <svg {...base} {...p}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>;
export const EyeOff = (p: P) => <svg {...base} {...p}><path d="M3 3l18 18M10.6 5.1A10.7 10.7 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6C3.9 8.4 2 12 2 12s3.5 7 10 7c1.8 0 3.4-.5 4.8-1.3M9.9 9.9a3 3 0 0 0 4.2 4.2" /></svg>;
export const Book = (p: P) => <svg {...base} {...p}><path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z" /><path d="M4 19V5M8 7h7M8 11h7" /></svg>;
export const Command = (p: P) => <svg {...base} {...p}><path d="M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z" /></svg>;
export const Sparkle = (p: P) => <svg {...base} {...p}><path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6" /></svg>;
export const Phone = (p: P) => <svg {...base} {...p}><rect x="6.5" y="2.5" width="11" height="19" rx="2.5" /><path d="M10.5 18.5h3" /></svg>;
export const Globe = (p: P) => <svg {...base} {...p}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z" /></svg>;
export const Bank = (p: P) => <svg {...base} {...p}><path d="M3 10 12 4l9 6M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 20h18" /></svg>;
