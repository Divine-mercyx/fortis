import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { env } from '../src/config/env';
import { pool } from '../src/db/client';
import { alertsIdle, isSlackWebhook, setAlertTransport } from '../src/lib/alerts';
import { FAKE_LIVE_KEY, liveKeyFinding, ownershipFinding, projectWithKey, resetDb, scanPayload, setPlan, setupApp, signup, type Client } from './helpers';

let app: FastifyInstance;
type Call = { url: string; body: any; headers: Record<string, string> };
let calls: Call[] = [];
let fail: ((url: string) => number | null) | null = null;

beforeAll(async () => {
  app = await setupApp();
  env.RESEND_API_KEY = 're_test_key';
  setAlertTransport(async (url, init) => {
    const headers = Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>));
    calls.push({ url: String(url), body: JSON.parse(String(init?.body)), headers });
    const status = fail?.(String(url)) ?? 200;
    return new Response(status === 200 ? '{"id":"x"}' : 'invalid_token', { status });
  });
});
afterAll(async () => {
  setAlertTransport(null);
  env.RESEND_API_KEY = undefined;
  await app.close();
  await pool.end();
});
beforeEach(async () => {
  await resetDb();
  calls = [];
  fail = null;
});

const SLACK = 'https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx';
const upload = async (key: string, findings: Record<string, unknown>[], extra: Record<string, unknown> = {}) => {
  const res = await app.inject({ method: 'POST', url: '/v1/cli/scans', headers: { authorization: `Bearer ${key}` }, payload: scanPayload(findings, extra) });
  expect(res.statusCode).toBe(201);
  await alertsIdle();
  return res.json();
};
/** The title the server stored for a rule (known rules get the catalogue's own title). */
const titleOf = async (ruleId: string) => (await pool.query('select title from findings where rule_id = $1 limit 1', [ruleId])).rows[0].title as string;
const slackCalls = () => calls.filter((c) => c.url.startsWith('https://hooks.slack.com/'));
const emailCalls = () => calls.filter((c) => c.url === 'https://api.resend.com/emails');
const settings = (c: Client, body: Record<string, unknown>) => c.req({ method: 'PUT', url: `/v1/orgs/${c.orgId}/alerts`, payload: body });

async function coreWorkspace() {
  const owner = await signup(app, 'ada@paywave.ng');
  await setPlan(owner.orgId, 'core');
  const { key } = await projectWithKey(owner);
  return { owner, key };
}
const highFinding = { ruleId: 'DEP-OSV', severity: 'high', title: 'lodash 4.17.20: prototype pollution', file: 'package-lock.json', line: 1, snippet: 'lodash@4.17.20' };
const lowFinding = { ruleId: 'SEC-GEN-001', severity: 'low', title: 'Possible secret', file: 'README.md', line: 3, snippet: 'token = example' };

describe('alerts after a scan', () => {
  it('emails the owners and admins once per scan, with every new critical and high finding', async () => {
    const { owner, key } = await coreWorkspace();
    await upload(key, [liveKeyFinding, ownershipFinding, highFinding, lowFinding]);
    const emails = emailCalls();
    expect(emails).toHaveLength(1);
    expect(emails[0]!.headers.authorization).toBe('Bearer re_test_key');
    expect(emails[0]!.body.to).toEqual(['ada@paywave.ng']);
    expect(emails[0]!.body.subject).toBe('[Fortis] 3 new critical and high findings in paywave-api');
    for (const rule of ['FX-SEC-001', 'FX-OWN-001', 'DEP-OSV']) expect(emails[0]!.body.text).toContain(await titleOf(rule));
    expect(emails[0]!.body.text).not.toContain(await titleOf('SEC-GEN-001'));
    expect(emails[0]!.body.html).toContain('Review findings');
    expect(emails[0]!.body.text).toMatch(/\/findings\?status=open&id=[0-9a-f-]{36}/);
    expect(owner).toBeTruthy();
  });

  it('never puts the secret itself in an alert', async () => {
    const { owner, key } = await coreWorkspace();
    await settings(owner, { slackWebhookUrl: SLACK });
    await upload(key, [liveKeyFinding]);
    for (const c of calls) expect(JSON.stringify(c.body)).not.toContain(FAKE_LIVE_KEY);
  });

  it('does not repeat a finding that is still open, and alerts again when it reopens', async () => {
    const { key } = await coreWorkspace();
    await upload(key, [liveKeyFinding]);
    await upload(key, [liveKeyFinding]);
    expect(emailCalls()).toHaveLength(1);
    await upload(key, []); // full scan without it: fixed
    await upload(key, [liveKeyFinding]); // back again: reopened
    expect(emailCalls()).toHaveLength(2);
  });

  it('sends nothing for a scan with only lower findings, or for a retried upload', async () => {
    const { key } = await coreWorkspace();
    await upload(key, [lowFinding]);
    expect(calls).toHaveLength(0);
    const payload = scanPayload([liveKeyFinding]);
    for (let i = 0; i < 2; i++) await app.inject({ method: 'POST', url: '/v1/cli/scans', headers: { authorization: `Bearer ${key}` }, payload });
    await alertsIdle();
    expect(emailCalls()).toHaveLength(1);
  });

  it('follows the settings: critical only, everyone, email off, Slack on', async () => {
    const { owner, key } = await coreWorkspace();
    const dev = await signup(app, 'tunde@paywave.ng', 'Other');
    await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/members`, payload: { email: 'tunde@paywave.ng', role: 'developer' } });
    expect(dev).toBeTruthy();

    await settings(owner, { minSeverity: 'critical', emailTo: 'everyone' });
    await upload(key, [highFinding]);
    expect(calls).toHaveLength(0);
    await upload(key, [highFinding, liveKeyFinding]);
    expect(emailCalls().map((c) => c.body.to[0]).sort()).toEqual(['ada@paywave.ng', 'tunde@paywave.ng']);

    calls = [];
    await settings(owner, { emailEnabled: false, slackWebhookUrl: SLACK });
    await upload(key, [highFinding, liveKeyFinding, ownershipFinding]);
    expect(emailCalls()).toHaveLength(0);
    expect(slackCalls()).toHaveLength(1);
    const slack = slackCalls()[0]!.body;
    expect(slack.text).toBe('Fortis: 1 new critical finding in paywave-api');
    expect(JSON.stringify(slack.blocks)).toContain(await titleOf('FX-OWN-001'));
    expect(JSON.stringify(slack.blocks)).not.toContain(await titleOf('DEP-OSV'));
  });

  it('records a failed delivery and shows it in Settings until one succeeds', async () => {
    const { owner, key } = await coreWorkspace();
    await settings(owner, { slackWebhookUrl: SLACK, emailEnabled: false });
    fail = (url) => (url.startsWith('https://hooks.slack.com/') ? 404 : null);
    await upload(key, [liveKeyFinding]);
    let s = (await owner.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/alerts` })).json();
    expect(s.lastError).toBe('Slack rejected the webhook URL (HTTP 404). It may have been removed in Slack; paste a new one');
    fail = null;
    await upload(key, [ownershipFinding]);
    s = (await owner.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/alerts` })).json();
    expect(s.lastError).toBeNull();
    expect(s.lastSentAt).toBeTruthy();
  });
});

describe('alert settings', () => {
  it('starts with email to owners and admins for critical and high, and no Slack', async () => {
    const { owner } = await coreWorkspace();
    const res = await owner.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/alerts` });
    expect(res.json()).toMatchObject({ emailEnabled: true, emailTo: 'admins', minSeverity: 'high', slack: { connected: false }, emailAvailable: true });
  });

  it('only accepts Slack webhook URLs, and never sends the URL back', async () => {
    const { owner } = await coreWorkspace();
    for (const bad of ['https://evil.example/hook', 'http://hooks.slack.com/services/T/B/x', 'https://hooks.slack.com.evil.example/services/T/B/x', 'https://user@hooks.slack.com/services/T/B/x', 'https://hooks.slack.com:8443/services/T/B/x', 'https://169.254.169.254/latest']) {
      const res = await settings(owner, { slackWebhookUrl: bad });
      expect(res.statusCode, bad).toBe(400);
    }
    expect(isSlackWebhook(SLACK)).toBe(true);
    const ok = await settings(owner, { slackWebhookUrl: SLACK });
    expect(ok.json().slack).toEqual({ connected: true, display: 'https://hooks.slack.com/services/T0000000/••••••••' });
    expect(JSON.stringify(ok.json())).not.toContain('abcdefghijkl');
    const { rows } = await pool.query('select slack_webhook from alert_settings');
    expect(rows[0].slack_webhook).toMatch(/^v1\./);
    expect(rows[0].slack_webhook).not.toContain('hooks.slack.com');
    const removed = await settings(owner, { slackWebhookUrl: '' });
    expect(removed.json().slack.connected).toBe(false);
  });

  it('is for owners and admins only, and changes are audited', async () => {
    const { owner } = await coreWorkspace();
    const dev = await signup(app, 'tunde@paywave.ng', 'Other');
    await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/members`, payload: { email: 'tunde@paywave.ng', role: 'developer' } });
    const asDev = await dev.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/alerts` });
    expect(asDev.statusCode).toBe(403);
    await settings(owner, { minSeverity: 'critical' });
    const entries = (await owner.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/audit` })).json().entries as { action: string; meta: unknown }[];
    expect(entries.find((e) => e.action === 'org.alerts_updated')?.meta).toEqual({ minSeverity: 'critical' });
  });

  it('sends a test alert through the channels that are on', async () => {
    const { owner } = await coreWorkspace();
    await settings(owner, { slackWebhookUrl: SLACK });
    const res = await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/alerts/test` });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ sent: ['slack', 'email'], errors: [] });
    expect(slackCalls()[0]!.body.text).toContain('1 new critical finding');
    await settings(owner, { slackWebhookUrl: '', emailEnabled: false });
    const none = await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/alerts/test` });
    expect(none.json().error.code).toBe('NO_ALERT_CHANNEL');
  });
});
