'use client';

import { useState } from 'react';
import useSWR from 'swr';

import { useSession } from '@/components/session';
import { CopyButton, FormError, Skeleton, useToast } from '@/components/ui';
import { api, fetcher } from '@/lib/api';
import { timeAgo } from '@/lib/format';

type Provider = 'google' | 'entra' | 'okta' | 'oidc';
type Sso = {
  available: boolean;
  redirectUri: string;
  connection: null | {
    domain: string;
    verified: boolean;
    record: { name: string; value: string };
    provider: Provider;
    issuer: string | null;
    clientId: string | null;
    hasSecret: boolean;
    defaultRole: 'viewer' | 'developer';
    enabled: boolean;
    enforced: boolean;
    testedAt: string | null;
    testedEmail: string | null;
    configured: boolean;
    ssoMembers: number;
  };
};

const PROVIDERS: Record<Provider, { name: string; issuerLabel: string | null; placeholder: string; help: string }> = {
  google: { name: 'Google Workspace', issuerLabel: null, placeholder: '', help: 'In Google Cloud console, create an OAuth client (Web application) and add the redirect URI below.' },
  entra: { name: 'Microsoft Entra ID', issuerLabel: 'Directory (tenant) ID', placeholder: '00000000-0000-0000-0000-000000000000', help: 'In Entra ID, register an app (single tenant), add the redirect URI below as a Web redirect, and create a client secret.' },
  okta: { name: 'Okta', issuerLabel: 'Okta domain', placeholder: 'paywave.okta.com', help: 'In Okta, create an OIDC Web Application, add the redirect URI below as a sign-in redirect, and assign the people who should get in.' },
  oidc: { name: 'Another OIDC provider', issuerLabel: 'Issuer URL', placeholder: 'https://login.example.com', help: 'Any OpenID Connect provider with a published configuration. Add the redirect URI below.' },
};

function tenantOf(issuer: string | null) {
  return issuer?.match(/login\.microsoftonline\.com\/([^/]+)\/v2\.0/)?.[1] ?? issuer ?? '';
}

export function SsoCard() {
  const { org } = useSession();
  const toast = useToast();
  const isOwner = org.role === 'owner';
  const { data, mutate } = useSWR<Sso>(`/v1/orgs/${org.id}/sso`, fetcher);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [provider, setProvider] = useState<Provider | null>(null);

  async function save(body: Record<string, unknown>, done?: string) {
    setBusy(done ?? 'save');
    setError(null);
    try {
      const r = await api<Sso & { endedSessions?: number }>(`/v1/orgs/${org.id}/sso`, { method: 'PUT', body });
      void mutate(r, { revalidate: false });
      if (done) toast(done + (r.endedSessions ? ` · ${r.endedSessions} password session${r.endedSessions === 1 ? '' : 's'} ended` : ''));
      return true;
    } catch (err) {
      setError((err as Error).message);
      return false;
    } finally {
      setBusy(null);
    }
  }

  async function verify() {
    setBusy('verify');
    setError(null);
    try {
      const r = await api<Sso & { verified: boolean; error?: string }>(`/v1/orgs/${org.id}/sso/verify`, { method: 'POST' });
      void mutate(r, { revalidate: false });
      if (r.verified) toast('Domain verified');
      else setError(r.error ?? 'Not verified yet.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function test() {
    setBusy('test');
    setError(null);
    try {
      const r = await api<{ authorizationUrl: string }>(`/v1/orgs/${org.id}/sso/test`, { method: 'POST' });
      window.location.assign(r.authorizationUrl);
    } catch (err) {
      setError((err as Error).message);
      setBusy(null);
    }
  }

  async function remove() {
    if (!window.confirm("Remove single sign-on? People who joined through it have no Fortis password, so they can't sign in until it's set up again.")) return;
    await api(`/v1/orgs/${org.id}/sso`, { method: 'DELETE' });
    void mutate();
    toast('Single sign-on removed');
  }

  const c = data?.connection;
  const pill = !c ? <span className="pill p-mute">Off</span> : c.enforced ? <span className="pill p-ok">Required</span> : c.enabled ? <span className="pill p-ok">On</span> : <span className="pill p-mute">Setting up</span>;

  return (
    <section className="card reveal" id="sso">
      <div className="card-head"><h3>Single sign-on</h3>{data ? pill : null}</div>
      <div className="card-pad">
        {!data ? (
          <Skeleton h={80} />
        ) : !data.available && !c ? (
          <p className="small" style={{ margin: 0 }}>Sign in with Google Workspace, Microsoft Entra ID or Okta, and require it for your domain. Comes with Fortis Plus and Enterprise.</p>
        ) : !c ? (
          isOwner ? (
            <form className="sso-row" onSubmit={(e) => { e.preventDefault(); void save({ domain: new FormData(e.currentTarget).get('domain') }, 'Domain added'); }}>
              <p className="small" style={{ margin: 0, flex: '1 1 100%' }}>Let your team sign in with your company's identity provider. Start with the email domain they use at work.</p>
              <FormError message={error} />
              <input className="input" name="domain" placeholder="paywave.ng" required style={{ flex: '1 1 220px' }} />
              <button className="btn btn-primary" disabled={busy !== null}>{busy ? <span className="spinner" /> : null} Set up</button>
            </form>
          ) : (
            <p className="small" style={{ margin: 0 }}>Not set up. An owner can set it up here.</p>
          )
        ) : (
          <div className="sso-steps">
            <FormError message={error} />

            <div className={`sso-step ${c.verified ? 'done' : ''}`}>
              <div className="sso-num">1</div>
              <div className="sso-body">
                <strong>Prove you own {c.domain}</strong>
                {c.verified ? (
                  <p className="small">Verified.</p>
                ) : (
                  <>
                    <p className="small">Add this TXT record at your DNS provider, then check it.</p>
                    <dl className="sso-record">
                      <dt>Name</dt><dd><code>{c.record.name}</code> <CopyButton text={c.record.name} /></dd>
                      <dt>Value</dt><dd><code>{c.record.value}</code> <CopyButton text={c.record.value} /></dd>
                    </dl>
                    {isOwner ? <button className="btn btn-outline btn-sm" disabled={busy !== null} onClick={verify}>{busy === 'verify' ? <span className="spinner" /> : null} Check the record</button> : null}
                  </>
                )}
              </div>
            </div>

            <ProviderStep key={`${c.provider}-${c.issuer}-${c.clientId}`} sso={data} isOwner={isOwner} busy={busy} provider={provider ?? c.provider} setProvider={setProvider} onSave={(b) => save(b, 'Identity provider saved')} />

            <div className={`sso-step ${c.testedAt ? 'done' : ''}`}>
              <div className="sso-num">3</div>
              <div className="sso-body">
                <strong>Try a sign-in</strong>
                <p className="small">
                  {c.testedAt ? `Worked for ${c.testedEmail}, ${timeAgo(c.testedAt)}.` : 'Sign in once through your provider with a work account. It checks everything and signs nobody in.'}
                </p>
                {isOwner ? <button className="btn btn-outline btn-sm" disabled={busy !== null || !c.configured} onClick={test}>{busy === 'test' ? <span className="spinner" /> : null} {c.testedAt ? 'Test again' : 'Test sign-in'}</button> : null}
              </div>
            </div>

            <div className={`sso-step ${c.enabled ? 'done' : ''}`}>
              <div className="sso-num">4</div>
              <div className="sso-body">
                <strong>Switch it on</strong>
                <label className="sso-switch">
                  <input type="checkbox" checked={c.enabled} disabled={!isOwner || busy !== null || !c.configured || !c.verified} onChange={(e) => void save({ enabled: e.target.checked }, e.target.checked ? 'Single sign-on is on' : 'Single sign-on is off')} />
                  <span>People on {c.domain} can sign in with SSO{c.ssoMembers ? ` · ${c.ssoMembers} have` : ''}</span>
                </label>
                <label className="field sso-role">
                  <span>New people join as</span>
                  <select className="select" value={c.defaultRole} disabled={!isOwner || busy !== null} onChange={(e) => void save({ defaultRole: e.target.value }, 'Saved')}>
                    <option value="developer">Developer · triage and fix findings</option>
                    <option value="viewer">Viewer · read-only</option>
                  </select>
                </label>
                <label className="sso-switch">
                  <input type="checkbox" checked={c.enforced} disabled={!isOwner || busy !== null || !c.enabled || !c.testedAt} onChange={(e) => void save({ enforced: e.target.checked }, e.target.checked ? `SSO is required for ${c.domain}` : 'Passwords allowed again')} />
                  <span>Require SSO for {c.domain}</span>
                </label>
                <p className="small" style={{ margin: '4px 0 0' }}>
                  Passwords stop working for {c.domain} and their other sessions end. SSO sessions last 12 hours, so someone removed in your identity provider is out within a day.
                </p>
              </div>
            </div>

            {isOwner ? <button className="btn btn-danger btn-sm" style={{ justifySelf: 'start' }} onClick={remove}>Remove single sign-on</button> : null}
          </div>
        )}
      </div>
    </section>
  );
}

function ProviderStep({ sso, isOwner, busy, provider, setProvider, onSave }: { sso: Sso; isOwner: boolean; busy: string | null; provider: Provider; setProvider: (p: Provider) => void; onSave: (b: Record<string, unknown>) => Promise<boolean> }) {
  const c = sso.connection!;
  const p = PROVIDERS[provider];
  const [issuer, setIssuer] = useState(provider === 'entra' ? tenantOf(c.issuer) : provider === 'okta' ? (c.issuer ?? '').replace(/^https:\/\//, '') : (c.issuer ?? ''));
  const [clientId, setClientId] = useState(c.clientId ?? '');
  const [secret, setSecret] = useState('');

  return (
    <div className={`sso-step ${c.configured ? 'done' : ''}`}>
      <div className="sso-num">2</div>
      <form
        className="sso-body"
        onSubmit={async (e) => {
          e.preventDefault();
          const ok = await onSave({ provider, ...(p.issuerLabel ? { issuer } : {}), clientId, ...(secret ? { clientSecret: secret } : {}) });
          if (ok) setSecret('');
        }}
      >
        <strong>Connect your identity provider</strong>
        <p className="small">{p.help}</p>
        <div className="sso-grid">
          <label className="field">
            <span>Provider</span>
            <select className="select" value={provider} disabled={!isOwner} onChange={(e) => { setProvider(e.target.value as Provider); setIssuer(''); }}>
              {(Object.keys(PROVIDERS) as Provider[]).map((k) => <option key={k} value={k}>{PROVIDERS[k].name}</option>)}
            </select>
          </label>
          {p.issuerLabel ? (
            <label className="field">
              <span>{p.issuerLabel}</span>
              <input className="input" value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder={p.placeholder} disabled={!isOwner} required />
            </label>
          ) : null}
          <label className="field">
            <span>Client ID</span>
            <input className="input" value={clientId} onChange={(e) => setClientId(e.target.value)} disabled={!isOwner} required autoComplete="off" />
          </label>
          <label className="field">
            <span>Client secret</span>
            <input className="input" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder={c.hasSecret ? 'Saved · leave blank to keep' : ''} disabled={!isOwner} required={!c.hasSecret} autoComplete="new-password" />
          </label>
        </div>
        <div className="sso-redirect">
          <span className="small">Redirect URI to add in your provider</span>
          <span><code>{sso.redirectUri}</code> <CopyButton text={sso.redirectUri} /></span>
        </div>
        {isOwner ? <button className="btn btn-primary btn-sm" disabled={busy !== null}>{busy === 'Identity provider saved' ? <span className="spinner" /> : null} Save provider</button> : null}
      </form>
    </div>
  );
}
