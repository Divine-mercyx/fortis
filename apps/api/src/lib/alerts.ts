import { and, eq, inArray, isNull } from 'drizzle-orm';

import { db } from '../db/client';
import { alertSettings, findings, memberships, organizations, projects, scans, users } from '../db/schema';
import { env } from '../config/env';
import { open, seal } from './secret-box';

/*
 * Alerts when a scan finds something serious: one email and one Slack message per scan, never one per
 * finding, and never twice for the same finding while it stays open (findings.alerted_at). They're sent
 * after the scan is saved, in the background, so an upload never waits on Slack or email.
 */

export type MinSeverity = 'critical' | 'high';
export type AlertConfig = { emailEnabled: boolean; emailTo: 'admins' | 'everyone'; minSeverity: MinSeverity; slackWebhook: string | null };
export const DEFAULT_ALERTS: AlertConfig = { emailEnabled: true, emailTo: 'admins', minSeverity: 'high', slackWebhook: null };

const SEVERITIES: Record<MinSeverity, string[]> = { critical: ['critical'], high: ['critical', 'high'] };
const SEND_TIMEOUT_MS = 6_000;
const MAX_LISTED = 8;

/** Only Slack's own webhook URLs: anything else would let a workspace make this server call any address. */
export function isSlackWebhook(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && u.hostname === 'hooks.slack.com' && /^\/(services|triggers|workflows)\/[\w/-]+$/.test(u.pathname) && !u.username && !u.password && !u.port;
  } catch {
    return false;
  }
}

/** A webhook URL with its secret part hidden, for showing in Settings. */
export const maskWebhook = (url: string) => url.replace(/^(https:\/\/hooks\.slack\.com\/\w+\/[^/]+\/)[\s\S]*$/, '$1••••••••');

export async function loadAlertSettings(orgId: string) {
  const [row] = await db.select().from(alertSettings).where(eq(alertSettings.orgId, orgId)).limit(1);
  if (!row) return { ...DEFAULT_ALERTS, lastSentAt: null as Date | null, lastError: null as string | null };
  let slackWebhook: string | null = null;
  try {
    slackWebhook = row.slackWebhook ? open(row.slackWebhook) : null;
  } catch {
    slackWebhook = null; // unreadable after a key change: treated as not set
  }
  return {
    emailEnabled: row.emailEnabled,
    emailTo: (row.emailTo === 'everyone' ? 'everyone' : 'admins') as AlertConfig['emailTo'],
    minSeverity: (row.minSeverity === 'critical' ? 'critical' : 'high') as MinSeverity,
    slackWebhook,
    lastSentAt: row.lastSentAt,
    lastError: row.lastError,
  };
}

export async function saveAlertSettings(orgId: string, next: Partial<AlertConfig>) {
  const values = {
    ...(next.emailEnabled !== undefined ? { emailEnabled: next.emailEnabled } : {}),
    ...(next.emailTo ? { emailTo: next.emailTo } : {}),
    ...(next.minSeverity ? { minSeverity: next.minSeverity } : {}),
    ...(next.slackWebhook !== undefined ? { slackWebhook: next.slackWebhook ? seal(next.slackWebhook) : null, lastError: null } : {}),
    updatedAt: new Date(),
  };
  await db.insert(alertSettings).values({ orgId, ...values }).onConflictDoUpdate({ target: alertSettings.orgId, set: values });
}

/* ---------------- delivery ---------------- */

type Sender = typeof fetch;
let send: Sender = (...args) => fetch(...args);
/** Tests replace the network call. */
export function setAlertTransport(fn: Sender | null) {
  send = fn ?? ((...args) => fetch(...args));
}

/** Alerts still being sent, so tests (and a graceful shutdown) can wait for them. */
const pending = new Set<Promise<unknown>>();
export async function alertsIdle() {
  while (pending.size) await Promise.allSettled([...pending]);
}

export type AlertFinding = { id: string; severity: string; title: string; file: string; line: number | null; ruleId: string; kind: string };
export type AlertMessage = { orgName: string; projectName: string; scanLabel: string; findings: AlertFinding[] };

const findingUrl = (id: string) => `${env.WEB_URL.replace(/\/+$/, '')}/findings?status=open&id=${id}`;
const where = (f: AlertFinding) => (f.line ? `${f.file}:${f.line}` : f.file);
export function headline(m: AlertMessage): string {
  const crit = m.findings.filter((f) => f.severity === 'critical').length;
  const n = m.findings.length;
  const what = crit === n ? 'critical' : crit ? 'critical and high' : 'high-severity';
  return `${n} new ${what} finding${n === 1 ? '' : 's'} in ${m.projectName}`;
}

export function slackPayload(m: AlertMessage) {
  const shown = m.findings.slice(0, MAX_LISTED);
  const lines = shown.map((f) => `• *${f.severity.toUpperCase()}* ${f.title}\n   \`${where(f)}\` · <${findingUrl(f.id)}|Open in Fortis>`);
  if (m.findings.length > shown.length) lines.push(`…and ${m.findings.length - shown.length} more.`);
  return {
    text: `Fortis: ${headline(m)}`,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: headline(m).slice(0, 150) } },
      { type: 'context', elements: [{ type: 'mrkdwn', text: `${m.orgName} · ${m.scanLabel}` }] },
      { type: 'section', text: { type: 'mrkdwn', text: lines.join('\n').slice(0, 2900) } },
      { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: 'Review findings' }, url: `${env.WEB_URL.replace(/\/+$/, '')}/findings?status=open` }] },
    ],
  };
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
export function emailContent(m: AlertMessage) {
  const shown = m.findings.slice(0, MAX_LISTED);
  const more = m.findings.length - shown.length;
  const text = [
    `${headline(m)}.`, `${m.orgName} · ${m.scanLabel}`, '',
    ...shown.map((f) => `${f.severity.toUpperCase()}  ${f.title}\n  ${where(f)}\n  ${findingUrl(f.id)}`),
    ...(more ? [`…and ${more} more.`] : []),
    '', `Review them: ${env.WEB_URL.replace(/\/+$/, '')}/findings?status=open`,
    'You get this because you are on the alert list for this workspace. An admin can change it in Fortis Settings → Alerts.',
  ].join('\n');
  const color = (s: string) => (s === 'critical' ? '#B42318' : '#B54708');
  const rows = shown.map((f) => `
    <tr><td style="padding:12px 0;border-bottom:1px solid #E7E9EF">
      <span style="display:inline-block;font:700 11px/1 Arial,sans-serif;letter-spacing:.06em;color:#fff;background:${color(f.severity)};padding:4px 7px;border-radius:4px">${esc(f.severity.toUpperCase())}</span>
      <a href="${esc(findingUrl(f.id))}" style="font:600 15px/1.4 Arial,sans-serif;color:#0B1B33;text-decoration:none;margin-left:8px">${esc(f.title)}</a>
      <div style="font:13px/1.5 Menlo,Consolas,monospace;color:#667085;margin-top:6px">${esc(where(f))}</div>
    </td></tr>`).join('');
  const html = `<!doctype html><html><body style="margin:0;background:#F6F7F9;padding:24px">
  <table role="presentation" width="100%" style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;padding:28px">
    <tr><td style="font:700 13px/1 Arial,sans-serif;color:#0E7A55;letter-spacing:.08em">FORTIS ALERT</td></tr>
    <tr><td style="font:700 22px/1.3 Arial,sans-serif;color:#0B1B33;padding:10px 0 4px">${esc(headline(m))}</td></tr>
    <tr><td style="font:14px/1.5 Arial,sans-serif;color:#667085;padding-bottom:12px">${esc(m.orgName)} · ${esc(m.scanLabel)}</td></tr>
    ${rows}
    ${more ? `<tr><td style="font:14px Arial,sans-serif;color:#667085;padding-top:12px">…and ${more} more.</td></tr>` : ''}
    <tr><td style="padding-top:22px"><a href="${esc(env.WEB_URL.replace(/\/+$/, '') + '/findings?status=open')}" style="display:inline-block;background:#0E7A55;color:#fff;font:600 14px Arial,sans-serif;padding:12px 18px;border-radius:8px;text-decoration:none">Review findings</a></td></tr>
    <tr><td style="font:12px/1.5 Arial,sans-serif;color:#98A2B3;padding-top:22px">You get this because you're on this workspace's alert list. An admin can change it in Fortis Settings → Alerts.</td></tr>
  </table></body></html>`;
  return { subject: `[Fortis] ${headline(m)}`, text, html };
}

/** A delivery problem in words an admin can act on. */
export function describeFailure(channel: 'slack' | 'email', err: unknown): string {
  const msg = (err as Error)?.message ?? String(err);
  const status = Number(/^HTTP (\d{3})/.exec(msg)?.[1] ?? 0);
  if (channel === 'slack') {
    if (status === 404 || status === 410 || status === 403) return `Slack rejected the webhook URL (HTTP ${status}). It may have been removed in Slack; paste a new one`;
    if (status >= 500) return `Slack had a problem on its side (HTTP ${status}); the next alert will try again`;
    if (status) return `Slack refused the message (HTTP ${status})`;
    return "Fortis couldn't reach Slack (no answer within 6 seconds)";
  }
  if (status === 401 || status === 403) return `the email service refused Fortis's key (HTTP ${status})`;
  if (status === 422) return 'the email service refused the sender address; its domain may not be verified';
  if (status) return `the email service refused the message (HTTP ${status})`;
  return "Fortis couldn't reach the email service";
}

async function post(url: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await send(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    redirect: 'error',
  });
  if (!res.ok) {
    const detail = (await res.text().catch(() => '')).slice(0, 120);
    throw new Error(`HTTP ${res.status}${detail ? ` ${detail}` : ''}`);
  }
}

async function recipients(orgId: string, to: AlertConfig['emailTo']) {
  const roles = to === 'everyone' ? ['owner', 'admin', 'developer', 'viewer'] : ['owner', 'admin'];
  const rows = await db
    .select({ email: users.email })
    .from(memberships)
    .innerJoin(users, eq(users.id, memberships.userId))
    .where(and(eq(memberships.orgId, orgId), inArray(memberships.role, roles)));
  return rows.map((r) => r.email);
}

export const emailAvailable = () => Boolean(env.RESEND_API_KEY);

/** Sends one alert through every channel the workspace has turned on. Returns what was sent and any errors. */
export async function deliver(orgId: string, cfg: AlertConfig, message: AlertMessage) {
  const sent: string[] = [];
  const errors: string[] = [];
  if (cfg.slackWebhook && isSlackWebhook(cfg.slackWebhook)) {
    try {
      await post(cfg.slackWebhook, slackPayload(message));
      sent.push('slack');
    } catch (err) {
      errors.push(describeFailure('slack', err));
    }
  }
  if (cfg.emailEnabled && env.RESEND_API_KEY) {
    const to = await recipients(orgId, cfg.emailTo);
    if (to.length) {
      const { subject, text, html } = emailContent(message);
      try {
        // One email per person: a shared To line would show every address to everyone.
        for (const address of to) {
          await post('https://api.resend.com/emails', { from: env.ALERTS_FROM, to: [address], subject, text, html }, { authorization: `Bearer ${env.RESEND_API_KEY}` });
        }
        sent.push('email');
      } catch (err) {
        errors.push(`Email didn't go out: ${describeFailure('email', err)}`);
      }
    }
  }
  await db
    .update(alertSettings)
    .set(errors.length ? { lastError: errors.join(' · ').slice(0, 300) } : sent.length ? { lastSentAt: new Date(), lastError: null } : {})
    .where(eq(alertSettings.orgId, orgId));
  return { sent, errors };
}

/**
 * Called after a scan is saved: picks its new and reopened findings at the workspace's severity, claims them
 * (alerted_at, so a concurrent call can't send them again) and sends one message. Never throws.
 */
export function queueScanAlerts(orgId: string, projectId: string, scanId: string, findingIds: string[]) {
  if (!findingIds.length) return;
  const job = (async () => {
    const cfg = await loadAlertSettings(orgId);
    if (!cfg.slackWebhook && !(cfg.emailEnabled && env.RESEND_API_KEY)) return;
    const claimed = await db
      .update(findings)
      .set({ alertedAt: new Date() })
      .where(and(inArray(findings.id, findingIds), eq(findings.status, 'open'), isNull(findings.alertedAt), inArray(findings.severity, SEVERITIES[cfg.minSeverity])))
      .returning({ id: findings.id, severity: findings.severity, title: findings.title, file: findings.file, line: findings.line, ruleId: findings.ruleId, kind: findings.kind });
    if (!claimed.length) return;
    const [ctx] = await db
      .select({ orgName: organizations.name, projectName: projects.name, trigger: scans.trigger, branch: scans.branch, commit: scans.commit, kind: scans.kind })
      .from(scans)
      .innerJoin(organizations, eq(organizations.id, scans.orgId))
      .innerJoin(projects, eq(projects.id, scans.projectId))
      .where(and(eq(scans.id, scanId), eq(scans.projectId, projectId)))
      .limit(1);
    const order = (s: string) => (s === 'critical' ? 0 : 1);
    claimed.sort((a, b) => order(a.severity) - order(b.severity));
    await deliver(orgId, cfg, {
      orgName: ctx?.orgName ?? 'Your workspace',
      projectName: ctx?.projectName ?? 'a project',
      scanLabel: scanLabel(ctx),
      findings: claimed,
    });
  })().catch((err) => console.error('[alerts] failed', err));
  pending.add(job);
  void job.finally(() => pending.delete(job));
}

function scanLabel(ctx?: { trigger: string; branch: string | null; commit: string | null; kind: string } | null) {
  if (!ctx) return 'Latest scan';
  const what = ctx.kind === 'exposure' ? 'Exposure check' : ctx.kind === 'dast' ? 'Running-app test' : ctx.kind === 'access' ? 'Access check' : 'Code scan';
  const how = ctx.trigger === 'pre-push' ? 'before a push' : ctx.trigger === 'ci' ? 'in CI' : ctx.trigger === 'schedule' ? 'on schedule' : 'by hand';
  const where = [ctx.branch, ctx.commit?.slice(0, 7)].filter(Boolean).join(' @ ');
  return `${what} ${how}${where ? ` · ${where}` : ''}`;
}
