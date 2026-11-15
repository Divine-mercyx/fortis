import { generateKeyPairSync, sign } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pool } from '../src/db/client';
import { clearSsoCaches, setSsoTransport } from '../src/lib/sso';
import { setTxtResolver } from '../src/modules/targets.routes';
import { ORIGIN, resetDb, setPlan, setupApp, signup, type Client } from './helpers';

/*
 * Single sign-on against a fake OpenID provider: real RSA-signed ID tokens, a discovery document,
 * published keys and a token endpoint. Each test says what the provider puts in the token.
 */

let app: FastifyInstance;
const ISSUER = 'https://idp.paywave.ng';
const DOMAIN = 'paywave.ng';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' };

let txt: Record<string, string[]> = {};
let addresses: string[] = ['34.120.1.1'];
/** What the next token carries, given the nonce from the authorization request. */
let claimsFor: (nonce: string) => Record<string, unknown>;
let signWith = privateKey;
let tokenCalls: { body: URLSearchParams; auth: string | null }[] = [];
let issuedNonce = '';

const jwt = (claims: Record<string, unknown>, key = signWith, kid = 'k1') => {
  const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`;
};
const now = () => Math.floor(Date.now() / 1000);
const goodClaims = (email = 'tunde@paywave.ng', sub = 'sub-tunde') => (nonce: string) => ({ iss: ISSUER, aud: 'fortis-client', sub, email, email_verified: true, name: 'Tunde Bello', nonce, iat: now(), exp: now() + 300 });

beforeAll(async () => {
  app = await setupApp();
  setTxtResolver(async (name) => {
    if (txt[name]) return txt[name]!;
    throw Object.assign(new Error('nope'), { code: 'ENOTFOUND' });
  });
  setSsoTransport(
    async (url, init) => {
      const u = new URL(String(url));
      const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
      if (u.pathname.endsWith('/.well-known/openid-configuration')) {
        const iss = `${u.protocol}//${u.host}${u.pathname.replace('/.well-known/openid-configuration', '')}`;
        return json(200, { issuer: iss, authorization_endpoint: `${iss}/authorize`, token_endpoint: `${iss}/token`, jwks_uri: `${iss}/keys`, token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'] });
      }
      if (u.pathname.endsWith('/keys')) return json(200, { keys: [jwk] });
      if (u.pathname.endsWith('/token')) {
        const body = new URLSearchParams(String(init?.body));
        tokenCalls.push({ body, auth: (init?.headers as Record<string, string>)?.authorization ?? null });
        if (body.get('code') !== 'good-code') return json(400, { error: 'invalid_grant', error_description: 'Bad code' });
        return json(200, { id_token: jwt(claimsFor(issuedNonce)), access_token: 'x' });
      }
      return json(404, {});
    },
    async () => addresses,
  );
});
afterAll(async () => {
  setTxtResolver(null);
  setSsoTransport(null);
  await app.close();
  await pool.end();
});
beforeEach(async () => {
  await resetDb();
  clearSsoCaches();
  txt = {};
  addresses = ['34.120.1.1'];
  claimsFor = goodClaims();
  signWith = privateKey;
  tokenCalls = [];
});

const put = (c: Client, body: Record<string, unknown>) => c.req({ method: 'PUT', url: `/v1/orgs/${c.orgId}/sso`, payload: body });
const cookieOf = (res: { headers: Record<string, unknown> }, name: string) => {
  const raw = res.headers['set-cookie'];
  const list = Array.isArray(raw) ? raw : raw ? [raw as string] : [];
  return list.map((c) => String(c).split(';')[0]!).find((c) => c.startsWith(`${name}=`)) ?? null;
};

/** A Plus workspace with a verified, configured, tested and switched-on connection. */
async function ready(opts: { enforce?: boolean; role?: string } = {}) {
  const owner = await signup(app, 'ada@paywave.ng');
  await setPlan(owner.orgId, 'plus');
  const created = (await put(owner, { domain: DOMAIN, provider: 'oidc', issuer: ISSUER, clientId: 'fortis-client', clientSecret: 'shh-secret', defaultRole: opts.role ?? 'developer' })).json();
  txt[created.connection.record.name] = [created.connection.record.value];
  expect((await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/sso/verify` })).json().verified).toBe(true);
  claimsFor = goodClaims('ada@paywave.ng', 'sub-ada');
  await test(owner);
  claimsFor = goodClaims();
  expect((await put(owner, { enabled: true, ...(opts.enforce ? { enforced: true } : {}) })).statusCode).toBe(200);
  return owner;
}

/** Runs a flow to the provider and back. Returns the callback response. */
async function flow(start: { url: string; cookie?: string; payload?: unknown }, code = 'good-code', opts: { dropBinder?: boolean } = {}) {
  const res = await app.inject({ method: 'POST', url: start.url, headers: { origin: ORIGIN, ...(start.cookie ? { cookie: start.cookie } : {}) }, payload: start.payload ?? {} });
  expect(res.statusCode, res.body).toBe(200);
  const auth = new URL(res.json().authorizationUrl);
  issuedNonce = auth.searchParams.get('nonce')!;
  const binder = cookieOf(res, 'fortis_sso');
  const cb = await app.inject({
    method: 'POST',
    url: '/v1/auth/sso/callback',
    headers: { origin: ORIGIN, ...(binder && !opts.dropBinder ? { cookie: binder } : {}) },
    payload: { code, state: auth.searchParams.get('state') },
  });
  return { cb, auth, state: auth.searchParams.get('state')!, binder };
}
const test = (owner: Client) => flow({ url: `/v1/orgs/${owner.orgId}/sso/test`, cookie: owner.cookie });
const login = (email = 'tunde@paywave.ng', code = 'good-code', opts: { dropBinder?: boolean } = {}) => flow({ url: '/v1/auth/sso/start', payload: { email, next: '/findings' } }, code, opts);
const actions = async (orgId: string) => (await pool.query('select action from audit_log where org_id = $1 order by created_at, id', [orgId])).rows.map((r) => r.action as string);

describe('setting up', () => {
  it('comes with Plus and Enterprise, for owners', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await setPlan(owner.orgId, 'core');
    expect((await owner.req({ method: 'GET', url: `/v1/orgs/${owner.orgId}/sso` })).json().available).toBe(false);
    const res = await put(owner, { domain: DOMAIN });
    expect(res.statusCode).toBe(402);
    expect(res.json().error.code).toBe('PLAN_SSO');
  });

  it('proves the domain with a TXT record, once per domain across Fortis', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await setPlan(owner.orgId, 'plus');
    const c = (await put(owner, { domain: 'PayWave.NG' })).json().connection;
    expect(c).toMatchObject({ domain: DOMAIN, verified: false, record: { name: `_fortis-verify.${DOMAIN}` } });
    expect(c.record.value).toMatch(/^fortis-verify=[A-Za-z0-9]{32}$/);
    const missing = (await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/sso/verify` })).json();
    expect(missing.verified).toBe(false);
    expect(missing.error).toContain('No TXT record found');
    txt[c.record.name] = ['something-else'];
    expect((await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/sso/verify` })).json().error).toContain("doesn't match");
    txt[c.record.name] = [c.record.value];
    expect((await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/sso/verify` })).json().verified).toBe(true);

    const rival = await signup(app, 'eve@rival.ng', 'Rival');
    await setPlan(rival.orgId, 'plus');
    const rc = (await put(rival, { domain: DOMAIN })).json().connection;
    txt[rc.record.name] = [rc.record.value];
    const taken = await rival.req({ method: 'POST', url: `/v1/orgs/${rival.orgId}/sso/verify` });
    expect(taken.statusCode).toBe(409);
    expect(await actions(owner.orgId)).toEqual(expect.arrayContaining(['sso.created', 'sso.domain_verified']));
  });

  it('checks the provider: real OIDC configuration, public https only, one Entra tenant', async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await setPlan(owner.orgId, 'plus');
    await put(owner, { domain: DOMAIN });

    const entra = await put(owner, { provider: 'entra', issuer: '00000000-1111-2222-3333-444444444444' });
    expect(entra.json().connection.issuer).toBe('https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0');
    const common = await put(owner, { provider: 'entra', issuer: 'https://login.microsoftonline.com/common/v2.0' });
    expect(common.json().error.code).toBe('SSO_MULTI_TENANT');
    expect((await put(owner, { provider: 'oidc', issuer: 'http://idp.paywave.ng' })).json().error.code).toBe('SSO_BAD_URL');
    addresses = ['10.0.0.5'];
    const inward = await put(owner, { provider: 'oidc', issuer: ISSUER });
    expect(inward.json().error.code).toBe('SSO_BAD_URL');
    expect(inward.json().error.message).toContain("isn't a public address");
    addresses = ['169.254.169.254'];
    expect((await put(owner, { provider: 'oidc', issuer: 'https://metadata.example' })).json().error.code).toBe('SSO_BAD_URL');
    addresses = ['34.120.1.1'];
    const ok = (await put(owner, { provider: 'oidc', issuer: ISSUER, clientId: 'fortis-client', clientSecret: 'shh-secret' })).json();
    expect(ok.connection).toMatchObject({ issuer: ISSUER, clientId: 'fortis-client', hasSecret: true, configured: true });
    expect(JSON.stringify(ok)).not.toContain('shh-secret');
    const stored = (await pool.query('select client_secret from sso_connections')).rows[0].client_secret as string;
    expect(stored).toMatch(/^v1\./);
  });

  it("won't require SSO until the domain is verified and a test sign-in worked, and new provider settings need a new test", async () => {
    const owner = await signup(app, 'ada@paywave.ng');
    await setPlan(owner.orgId, 'plus');
    const c = (await put(owner, { domain: DOMAIN, provider: 'oidc', issuer: ISSUER, clientId: 'fortis-client', clientSecret: 'shh-secret', enabled: true })).json().connection;
    expect((await put(owner, { enforced: true })).json().error.code).toBe('SSO_UNVERIFIED');
    txt[c.record.name] = [c.record.value];
    await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/sso/verify` });
    expect((await put(owner, { enforced: true })).json().error.code).toBe('SSO_UNTESTED');

    claimsFor = goodClaims('ada@paywave.ng', 'sub-ada');
    const t = await test(owner);
    expect(t.cb.statusCode, t.cb.body).toBe(200);
    expect(t.cb.json()).toMatchObject({ test: true, email: 'ada@paywave.ng' });
    expect(cookieOf(t.cb, 'fortis_session')).toBeNull();
    expect((await put(owner, { enforced: true })).json().connection).toMatchObject({ enforced: true, testedEmail: 'ada@paywave.ng' });

    const rotated = await put(owner, { clientSecret: 'rotated-secret' });
    expect(rotated.statusCode, rotated.body).toBe(200);
    const changed = rotated.json().connection;
    expect(changed).toMatchObject({ enforced: false, testedAt: null });
    expect(await actions(owner.orgId)).toEqual(expect.arrayContaining(['sso.tested', 'sso.updated']));
  });
});

describe('signing in', () => {
  it('sends the browser to the provider with PKCE, a nonce and a state', async () => {
    await ready();
    const { auth } = await login();
    expect(`${auth.origin}${auth.pathname}`).toBe(`${ISSUER}/authorize`);
    expect(Object.fromEntries(auth.searchParams)).toMatchObject({ response_type: 'code', client_id: 'fortis-client', redirect_uri: `${ORIGIN}/login/sso`, scope: 'openid email profile', code_challenge_method: 'S256', login_hint: 'tunde@paywave.ng' });
    expect(auth.searchParams.get('code_challenge')).toMatch(/^[\w-]{43}$/);
    expect(tokenCalls[0]!.body.get('code_verifier')).toMatch(/^[\w-]{64}$/);
    expect(tokenCalls[0]!.auth).toBe(`Basic ${Buffer.from('fortis-client:shh-secret').toString('base64')}`);
  });

  it('signs a new person in, adds them with the default role, and keeps the session short', async () => {
    const owner = await ready({ role: 'viewer' });
    const { cb } = await login();
    expect(cb.statusCode, cb.body).toBe(200);
    expect(cb.json()).toMatchObject({ user: { email: 'tunde@paywave.ng', name: 'Tunde Bello' }, orgId: owner.orgId, next: '/findings' });
    expect(cb.json().orgs[0]).toMatchObject({ id: owner.orgId, role: 'viewer' });
    const session = cookieOf(cb, 'fortis_session')!;
    const me = await app.inject({ method: 'GET', url: '/v1/auth/me', headers: { cookie: session } });
    expect(me.json().user.email).toBe('tunde@paywave.ng');
    const row = (await pool.query("select extract(epoch from (s.expires_at - s.created_at)) / 3600 as hours, sso_org_id from sessions s join users u on u.id = s.user_id where u.email = 'tunde@paywave.ng'")).rows[0];
    expect(Math.round(Number(row.hours))).toBe(12);
    expect(row.sso_org_id).toBe(owner.orgId);

    // Next time: same person by the provider's subject, no second membership.
    const again = await login();
    expect(again.cb.statusCode).toBe(200);
    expect((await pool.query('select count(*)::int as n from memberships where org_id = $1', [owner.orgId])).rows[0].n).toBe(2);
    expect(await actions(owner.orgId)).toEqual(expect.arrayContaining(['member.joined_sso', 'sso.login']));
  });

  it('links an existing Fortis account by its email', async () => {
    const owner = await ready();
    const tunde = await signup(app, 'tunde@paywave.ng', 'Side project');
    const { cb } = await login();
    expect(cb.json().user.id).toBe(tunde.userId);
    expect(cb.json().orgs.map((o: { id: string }) => o.id)).toEqual(expect.arrayContaining([owner.orgId, tunde.orgId]));
  });

  it('refuses a flow from another browser, a used or unknown state, and a bad code', async () => {
    await ready();
    expect((await login('tunde@paywave.ng', 'good-code', { dropBinder: true })).cb.json().error.code).toBe('SSO_WRONG_BROWSER');
    const first = await login();
    expect(first.cb.statusCode).toBe(200);
    const replay = await app.inject({ method: 'POST', url: '/v1/auth/sso/callback', headers: { origin: ORIGIN, cookie: first.binder! }, payload: { code: 'good-code', state: first.state } });
    expect(replay.json().error.code).toBe('SSO_EXPIRED');
    const bad = await login('tunde@paywave.ng', 'stolen-code');
    expect(bad.cb.statusCode).toBe(401);
    expect(bad.cb.json().error.message).toContain('Bad code');
    const none = await app.inject({ method: 'POST', url: '/v1/auth/sso/start', headers: { origin: ORIGIN }, payload: { email: 'x@nowhere.ng' } });
    expect(none.statusCode).toBe(404);
  });

  it.each([
    ['a token signed by another key', () => { signWith = other.privateKey; }, 'SSO_INVALID_TOKEN'],
    ['a token for another app', () => { claimsFor = (n) => ({ ...goodClaims()(n), aud: 'someone-else' }); }, 'SSO_INVALID_TOKEN'],
    ['a token from another issuer', () => { claimsFor = (n) => ({ ...goodClaims()(n), iss: 'https://evil.example' }); }, 'SSO_INVALID_TOKEN'],
    ['an expired token', () => { claimsFor = (n) => ({ ...goodClaims()(n), exp: now() - 600 }); }, 'SSO_INVALID_TOKEN'],
    ['a replayed nonce', () => { claimsFor = (n) => ({ ...goodClaims()(n), nonce: 'old' }); }, 'SSO_INVALID_TOKEN'],
    ['an email outside the domain', () => { claimsFor = goodClaims('tunde@gmail.com'); }, 'SSO_WRONG_DOMAIN'],
    ['an unverified email', () => { claimsFor = (n) => ({ ...goodClaims()(n), email_verified: false }); }, 'SSO_EMAIL_UNVERIFIED'],
  ])('refuses %s', async (_name, setup, code) => {
    await ready();
    setup();
    const { cb } = await login();
    expect(cb.json().error?.code).toBe(code);
    expect(cookieOf(cb, 'fortis_session')).toBeNull();
    expect((await pool.query("select count(*)::int as n from users where email = 'tunde@paywave.ng'")).rows[0].n).toBe(0);
  });

  it('respects the seat limit', async () => {
    const owner = await ready();
    await pool.query("update organizations set plan = 'plus' where id = $1", [owner.orgId]);
    // Fill every seat Plus has.
    for (let i = 0; i < 39; i++) {
      const u = await pool.query("insert into users (email, name, password_hash) values ($1, 'x', 'x') returning id", [`p${i}@x.ng`]);
      await pool.query("insert into memberships (org_id, user_id, role) values ($1, $2, 'viewer')", [owner.orgId, u.rows[0].id]);
    }
    const { cb } = await login();
    expect(cb.statusCode).toBe(402);
    expect(cb.json().error.code).toBe('SEATS_FULL');
  });
});

describe('requiring single sign-on', () => {
  it('turns off passwords for the domain, ends password sessions, and leaves other domains alone', async () => {
    const owner = await ready();
    const tunde = await signup(app, 'tunde@paywave.ng', 'Side project');
    await setPlan(owner.orgId, 'plus');
    await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/members`, payload: { email: 'tunde@paywave.ng', role: 'developer' } });
    const outsider = await signup(app, 'consultant@agency.ng', 'Agency');
    await owner.req({ method: 'POST', url: `/v1/orgs/${owner.orgId}/members`, payload: { email: 'consultant@agency.ng', role: 'viewer' } });

    const res = (await put(owner, { enforced: true })).json();
    expect(res.connection.enforced).toBe(true);
    expect(res.endedSessions).toBe(1); // Tunde's; Ada, switching it on, stays signed in
    expect((await owner.req({ method: 'GET', url: '/v1/auth/me' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/v1/auth/me', headers: { cookie: tunde.cookie } })).statusCode).toBe(401);
    expect((await app.inject({ method: 'GET', url: '/v1/auth/me', headers: { cookie: outsider.cookie } })).statusCode).toBe(200);

    const pw = await app.inject({ method: 'POST', url: '/v1/auth/login', headers: { origin: ORIGIN }, payload: { email: 'tunde@paywave.ng', password: 'correct-horse-battery' } });
    expect(pw.statusCode).toBe(403);
    expect(pw.json().error.code).toBe('SSO_REQUIRED');
    // A wrong password still says "incorrect", so the check doesn't help guess passwords.
    const wrong = await app.inject({ method: 'POST', url: '/v1/auth/login', headers: { origin: ORIGIN }, payload: { email: 'tunde@paywave.ng', password: 'nope-nope-nope' } });
    expect(wrong.statusCode).toBe(401);
    const sign = await app.inject({ method: 'POST', url: '/v1/auth/signup', headers: { origin: ORIGIN }, payload: { name: 'New Hire', email: 'new@paywave.ng', password: 'correct-horse-battery', company: 'Shadow IT' } });
    expect(sign.json().error.code).toBe('SSO_REQUIRED');
    expect((await app.inject({ method: 'POST', url: '/v1/auth/login', headers: { origin: ORIGIN }, payload: { email: 'consultant@agency.ng', password: 'correct-horse-battery' } })).statusCode).toBe(200);

    expect((await login()).cb.statusCode).toBe(200);
  });

  it('when an admin removes someone, their single sign-on sessions end', async () => {
    const owner = await ready();
    const { cb } = await login();
    const session = cookieOf(cb, 'fortis_session')!;
    const userId = cb.json().user.id;
    expect((await owner.req({ method: 'DELETE', url: `/v1/orgs/${owner.orgId}/members/${userId}` })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/v1/auth/me', headers: { cookie: session } })).statusCode).toBe(401);
  });

  it('a switched-off connection signs nobody in', async () => {
    const owner = await ready();
    await put(owner, { enabled: false });
    const res = await app.inject({ method: 'POST', url: '/v1/auth/sso/start', headers: { origin: ORIGIN }, payload: { email: 'tunde@paywave.ng' } });
    expect(res.statusCode).toBe(404);
  });
});
