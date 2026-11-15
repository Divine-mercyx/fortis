'use client';

import { useEffect, useState } from 'react';
import useSWR from 'swr';

import { Alert } from '@/components/icons';
import { FormError, Skeleton, useToast } from '@/components/ui';
import { api, fetcher } from '@/lib/api';
import { timeAgo } from '@/lib/format';

type Settings = {
  emailEnabled: boolean;
  emailTo: 'admins' | 'everyone';
  minSeverity: 'critical' | 'high';
  slack: { connected: boolean; display: string | null };
  emailAvailable: boolean;
  lastSentAt: string | null;
  lastError: string | null;
};

/** Settings card: who hears about new critical findings, and where. Owners and admins only. */
export function AlertsCard({ orgId }: { orgId: string }) {
  const toast = useToast();
  const { data, mutate } = useSWR<Settings>(`/v1/orgs/${orgId}/alerts`, fetcher);
  const [form, setForm] = useState<Omit<Settings, 'slack' | 'emailAvailable' | 'lastSentAt' | 'lastError'> | null>(null);
  const [slackUrl, setSlackUrl] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<'save' | 'test' | 'remove' | null>(null);

  useEffect(() => {
    if (data && !form) setForm({ emailEnabled: data.emailEnabled, emailTo: data.emailTo, minSeverity: data.minSeverity });
  }, [data, form]);

  async function save(e?: React.FormEvent) {
    e?.preventDefault();
    if (!form) return;
    setBusy('save');
    setError(null);
    try {
      const next = await api<Settings>(`/v1/orgs/${orgId}/alerts`, { method: 'PUT', body: { ...form, ...(slackUrl.trim() ? { slackWebhookUrl: slackUrl.trim() } : {}) } });
      await mutate(next, { revalidate: false });
      setSlackUrl('');
      toast('Alert settings saved');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function removeSlack() {
    setBusy('remove');
    try {
      await mutate(await api<Settings>(`/v1/orgs/${orgId}/alerts`, { method: 'PUT', body: { slackWebhookUrl: '' } }), { revalidate: false });
      toast('Slack disconnected');
    } catch (err) {
      toast((err as Error).message, true);
    } finally {
      setBusy(null);
    }
  }

  async function test() {
    setBusy('test');
    setError(null);
    try {
      const res = await api<{ sent: string[]; errors: string[] }>(`/v1/orgs/${orgId}/alerts/test`, { method: 'POST', body: {} });
      // A failed channel shows in the "didn't arrive" banner once Settings reloads.
      if (res.sent.length) toast(`Test alert sent to ${res.sent.map((s) => (s === 'email' ? 'email' : 'Slack')).join(' and ')}`);
      void mutate();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const set = <K extends keyof NonNullable<typeof form>>(k: K, v: NonNullable<typeof form>[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));

  return (
    <section className="card reveal" id="alerts" style={{ ['--d' as string]: '140ms' }}>
      <div className="card-head">
        <h3>Alerts</h3>
        <span className="small">When a scan finds something serious</span>
      </div>
      {!data || !form ? (
        <div className="card-pad"><Skeleton h={120} /></div>
      ) : (
        <form className="card-pad alerts" onSubmit={save}>
          <FormError message={error} />
          {data.lastError ? (
            <p className="alerts-warn" role="alert"><Alert /> <span>The last alert didn't arrive. {data.lastError}.</span></p>
          ) : null}

          <div className="alerts-row">
            <label className="field" htmlFor="alert-severity">
              <span>Alert on</span>
              <select id="alert-severity" className="select" value={form.minSeverity} onChange={(e) => set('minSeverity', e.target.value as Settings['minSeverity'])}>
                <option value="high">New critical and high findings</option>
                <option value="critical">New critical findings only</option>
              </select>
            </label>
            <p className="small alerts-note">One message per scan. A finding that stays open is never sent twice; it's sent again only if it comes back after being fixed.</p>
          </div>

          <fieldset className="alerts-channel">
            <legend>Email</legend>
            <label className="switch">
              <input id="alert-email" type="checkbox" checked={form.emailEnabled} onChange={(e) => set('emailEnabled', e.target.checked)} />
              <span>Send alerts by email</span>
            </label>
            <label className="field" htmlFor="alert-email-to">
              <span>Send to</span>
              <select id="alert-email-to" className="select" value={form.emailTo} disabled={!form.emailEnabled} onChange={(e) => set('emailTo', e.target.value as Settings['emailTo'])}>
                <option value="admins">Owners and admins</option>
                <option value="everyone">Everyone in this workspace</option>
              </select>
            </label>
            {!data.emailAvailable ? <p className="small alerts-note">Email isn't set up on this Fortis server yet, so only Slack alerts go out for now.</p> : null}
          </fieldset>

          <fieldset className="alerts-channel">
            <legend>Slack</legend>
            {data.slack.connected ? (
              <div className="alerts-slack">
                <span className="pill p-ok">Connected</span>
                <code className="mono small">{data.slack.display}</code>
                <button type="button" className="btn btn-outline btn-sm" onClick={removeSlack} disabled={busy !== null}>Disconnect</button>
              </div>
            ) : null}
            <label className="field" htmlFor="alert-slack">
              <span>{data.slack.connected ? 'Replace the webhook URL' : 'Incoming webhook URL'}</span>
              <input id="alert-slack" className="input" type="url" inputMode="url" autoComplete="off" spellCheck={false} placeholder="https://hooks.slack.com/services/…" value={slackUrl} onChange={(e) => setSlackUrl(e.target.value)} />
            </label>
            <p className="small alerts-note">In Slack, add the <b>Incoming Webhooks</b> app to the channel you want, then paste its URL here. Fortis stores it encrypted.</p>
          </fieldset>

          <div className="alerts-actions">
            <span className="small">{data.lastSentAt ? `Last alert sent ${timeAgo(data.lastSentAt)}` : 'No alerts sent yet'}</span>
            <button type="button" className="btn btn-outline btn-sm" onClick={test} disabled={busy !== null}>{busy === 'test' ? <span className="spinner" /> : null} Send test alert</button>
            <button className="btn btn-primary btn-sm" disabled={busy !== null}>{busy === 'save' ? <span className="spinner" /> : null} Save</button>
          </div>
        </form>
      )}
    </section>
  );
}
