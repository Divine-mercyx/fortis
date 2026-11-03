export function timeAgo(value: string | Date | null | undefined): string {
  if (!value) return 'Never';
  const d = typeof value === 'string' ? new Date(value) : value;
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const days = Math.round(h / 24);
  if (days < 30) return `${days} d ago`;
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

export const dateTime = (value: string | Date) =>
  new Date(value).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit' });

export const initials = (name: string) =>
  name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join('');

export const STATUS_LABEL: Record<string, string> = {
  open: 'Open',
  fixed: 'Fixed',
  accepted_risk: 'Accepted risk',
  false_positive: 'False positive',
};

export const naira = (kobo: number | null) =>
  kobo === null ? 'Custom' : `₦${(kobo / 100).toLocaleString('en-NG', { maximumFractionDigits: 0 })}`;

/** Only same-site relative paths are allowed as a post-login destination. */
export function safeNext(next: string | null) {
  return next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/overview';
}
