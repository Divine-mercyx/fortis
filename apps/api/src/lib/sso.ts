import { constants, createHash, createPublicKey, randomBytes, verify as verifySignature, type JsonWebKey } from 'node:crypto';
import { lookup } from 'node:dns/promises';

import { and, eq, isNotNull } from 'drizzle-orm';

import { env } from '../config/env';
import { db } from '../db/client';
import { ssoConnections } from '../db/schema';
import { isPublicAddress } from '../modules/exposure.service';
import { AppError, badRequest } from './errors';

/*
 * Single sign-on with OpenID Connect: Google Workspace, Microsoft Entra ID, Okta, or any OIDC
 * provider. The authorization code flow with PKCE, a nonce and a state tied to the browser. ID
 * tokens are checked here with node:crypto (RS256, PS256 or ES256): signature against the
 * provider's published keys, issuer, audience, expiry and nonce.
 *
 * The issuer is typed by a workspace owner, so every request to it goes only to public https
 * addresses: a provider URL can't aim the API at its own network.
 */

export type SsoProvider = 'google' | 'entra' | 'okta' | 'oidc';
export const SSO_PROVIDERS: readonly SsoProvider[] = ['google', 'entra', 'okta', 'oidc'];
export const GOOGLE_ISSUER = 'https://accounts.google.com';
const MULTI_TENANT = /^https:\/\/login\.microsoftonline\.com\/(common|organizations|consumers)\//i;

export const ssoRedirectUri = () => `${env.WEB_URL.replace(/\/+$/, '')}/login/sso`;
const allowPrivate = () => env.SSO_ALLOW_PRIVATE_ISSUER && !env.isProd;

export const emailDomain = (email: string) => email.slice(email.lastIndexOf('@') + 1).toLowerCase();

/** The workspace whose verified, switched-on connection covers this email, if any. */
export async function connectionForEmail(email: string) {
  const [row] = await db
    .select()
    .from(ssoConnections)
    .where(and(eq(ssoConnections.domain, emailDomain(email)), isNotNull(ssoConnections.verifiedAt), eq(ssoConnections.enabled, true)))
    .limit(1);
  return row ?? null;
}

/** Password sign-in and sign-up are refused for a domain whose workspace requires single sign-on. */
export async function assertPasswordAllowed(email: string) {
  const c = await connectionForEmail(email);
  if (c?.enforced) throw new AppError(403, 'SSO_REQUIRED', `${emailDomain(email)} signs in with single sign-on. Use "Sign in with SSO".`);
}

/* ---------------- network ---------------- */

type Sender = typeof fetch;
let send: Sender = (...args) => fetch(...args);
type Resolver = (host: string) => Promise<string[]>;
let resolve: Resolver = async (host) => (await lookup(host, { all: true })).map((a) => a.address);
/** Tests replace the provider and DNS. */
export function setSsoTransport(fn: Sender | null, resolver: Resolver | null = null) {
  send = fn ?? ((...args) => fetch(...args));
  resolve = resolver ?? (async (host) => (await lookup(host, { all: true })).map((a) => a.address));
}

const providerError = (message: string) => new AppError(502, 'SSO_PROVIDER', message);

async function assertSafeUrl(raw: string) {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw badRequest(`${raw} isn't a URL.`, 'SSO_BAD_URL');
  }
  if (url.protocol !== 'https:' && !(allowPrivate() && url.protocol === 'http:')) throw badRequest('The identity provider must use https.', 'SSO_BAD_URL');
  if (url.username || url.password) throw badRequest("The provider URL can't contain a user name or password.", 'SSO_BAD_URL');
  if (allowPrivate()) return url;
  let addresses: string[];
  try {
    addresses = await resolve(url.hostname);
  } catch {
    throw badRequest(`${url.hostname} doesn't resolve.`, 'SSO_BAD_URL');
  }
  if (!addresses.length || !addresses.every(isPublicAddress)) throw badRequest(`${url.hostname} isn't a public address.`, 'SSO_BAD_URL');
  return url;
}

async function getJson<T>(raw: string): Promise<T> {
  const url = await assertSafeUrl(raw);
  let res: Response;
  try {
    res = await send(url, { headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(10_000) });
  } catch {
    throw providerError(`Couldn't reach ${url.host}.`);
  }
  if (!res.ok) throw providerError(`${url.host} answered ${res.status}.`);
  const text = await res.text();
  if (text.length > 512 * 1024) throw providerError(`${url.host} sent too much.`);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw providerError(`${url.host} didn't send JSON.`);
  }
}

/* ---------------- discovery ---------------- */

export type Discovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  token_endpoint_auth_methods_supported?: string[];
};

const discoveryCache = new Map<string, { at: number; doc: Discovery }>();
const jwksCache = new Map<string, { at: number; keys: JsonWebKey[] }>();
const CACHE_MS = 10 * 60 * 1000;
export function clearSsoCaches() {
  discoveryCache.clear();
  jwksCache.clear();
}

/** The provider's `.well-known/openid-configuration`, checked to belong to that issuer. */
export async function discover(issuer: string): Promise<Discovery> {
  const hit = discoveryCache.get(issuer);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.doc;
  let doc: Discovery;
  try {
    doc = await getJson<Discovery>(`${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`);
  } catch (e) {
    if (e instanceof AppError && e.code === 'SSO_PROVIDER') {
      throw providerError(`Couldn't load the sign-in settings for ${issuer} (${e.message.replace(/\.$/, '')}). Check the issuer, tenant ID or Okta domain.`);
    }
    throw e;
  }
  if (!doc || typeof doc !== 'object' || !doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw providerError("That provider's configuration is missing its sign-in, token or key addresses.");
  }
  if (doc.issuer?.replace(/\/+$/, '') !== issuer.replace(/\/+$/, '')) {
    throw badRequest(`The provider calls itself ${doc.issuer ?? 'nothing'}, not ${issuer}. Use exactly the issuer it publishes.`, 'SSO_ISSUER_MISMATCH');
  }
  for (const u of [doc.authorization_endpoint, doc.token_endpoint, doc.jwks_uri]) await assertSafeUrl(u);
  discoveryCache.set(issuer, { at: Date.now(), doc });
  return doc;
}

/** Normalises what an owner typed into the issuer for each provider, and refuses multi-tenant ones. */
export function issuerFor(provider: SsoProvider, input: string): string {
  const v = input.trim().replace(/\/+$/, '');
  if (provider === 'google') return GOOGLE_ISSUER;
  if (provider === 'entra') {
    if (/^[0-9a-f-]{36}$/i.test(v)) return `https://login.microsoftonline.com/${v.toLowerCase()}/v2.0`;
    if (MULTI_TENANT.test(`${v}/`)) throw badRequest("Use your organisation's tenant ID, not common, organizations or consumers: those let anyone with a Microsoft account in.", 'SSO_MULTI_TENANT');
    return v;
  }
  if (provider === 'okta') return /^https?:\/\//.test(v) ? v : `https://${v}`;
  return v;
}

/* ---------------- the flow ---------------- */

const b64url = (b: Buffer) => b.toString('base64url');
export const hashValue = (v: string) => createHash('sha256').update(v).digest('hex');

export function newFlowSecrets() {
  const codeVerifier = b64url(randomBytes(48));
  return {
    state: b64url(randomBytes(24)),
    nonce: b64url(randomBytes(24)),
    binder: b64url(randomBytes(24)),
    codeVerifier,
    challenge: b64url(createHash('sha256').update(codeVerifier).digest()),
  };
}

export function authorizationUrl(doc: Discovery, c: { clientId: string; provider: string; domain: string }, s: { state: string; nonce: string; challenge: string }, loginHint?: string) {
  const u = new URL(doc.authorization_endpoint);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', c.clientId);
  u.searchParams.set('redirect_uri', ssoRedirectUri());
  u.searchParams.set('scope', 'openid email profile');
  u.searchParams.set('state', s.state);
  u.searchParams.set('nonce', s.nonce);
  u.searchParams.set('code_challenge', s.challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  if (loginHint) u.searchParams.set('login_hint', loginHint);
  if (c.provider === 'google') u.searchParams.set('hd', c.domain);
  return u.toString();
}

/** Trades the code for tokens at the provider's token endpoint. */
export async function exchangeCode(doc: Discovery, c: { clientId: string; clientSecret: string }, code: string, codeVerifier: string): Promise<string> {
  const url = await assertSafeUrl(doc.token_endpoint);
  const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: ssoRedirectUri(), code_verifier: codeVerifier });
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  const methods = doc.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
  if (methods.includes('client_secret_basic')) {
    headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(c.clientId)}:${encodeURIComponent(c.clientSecret)}`).toString('base64')}`;
  } else {
    body.set('client_id', c.clientId);
    body.set('client_secret', c.clientSecret);
  }
  let res: Response;
  try {
    res = await send(url, { method: 'POST', headers, body, redirect: 'error', signal: AbortSignal.timeout(10_000) });
  } catch {
    throw providerError(`Couldn't reach ${url.host}.`);
  }
  const json = (await res.json().catch(() => null)) as { id_token?: string; error?: string; error_description?: string } | null;
  if (!res.ok || !json?.id_token) {
    const why = json?.error_description || json?.error || `status ${res.status}`;
    throw new AppError(401, 'SSO_EXCHANGE_FAILED', `The identity provider didn't accept the sign-in (${String(why).slice(0, 200)}). Check the client ID and secret.`);
  }
  return json.id_token;
}

export type IdClaims = {
  iss: string;
  sub: string;
  aud: string | string[];
  azp?: string;
  exp: number;
  iat?: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean | string;
  preferred_username?: string;
  name?: string;
  hd?: string;
  tid?: string;
};

const ALGS: Record<string, { hash: string; pss?: boolean; ec?: boolean }> = {
  RS256: { hash: 'sha256' },
  RS384: { hash: 'sha384' },
  RS512: { hash: 'sha512' },
  PS256: { hash: 'sha256', pss: true },
  ES256: { hash: 'sha256', ec: true },
  ES384: { hash: 'sha384', ec: true },
};

async function jwks(uri: string, refresh = false): Promise<JsonWebKey[]> {
  const hit = jwksCache.get(uri);
  if (!refresh && hit && Date.now() - hit.at < CACHE_MS) return hit.keys;
  const doc = await getJson<{ keys?: JsonWebKey[] }>(uri);
  const keys = Array.isArray(doc?.keys) ? doc.keys : [];
  jwksCache.set(uri, { at: Date.now(), keys });
  return keys;
}

const invalid = (why: string) => new AppError(401, 'SSO_INVALID_TOKEN', `The identity provider's answer didn't check out: ${why}.`);

/** Checks an ID token's signature and claims. Throws on anything off. */
export async function verifyIdToken(token: string, doc: Discovery, expect: { issuer: string; clientId: string; nonce: string }, now = Date.now()): Promise<IdClaims> {
  const parts = token.split('.');
  if (parts.length !== 3) throw invalid('not a JWT');
  const [h, p, s] = parts as [string, string, string];
  let header: { alg?: string; kid?: string };
  let claims: IdClaims;
  try {
    header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch {
    throw invalid('unreadable');
  }
  const alg = header.alg ? ALGS[header.alg] : undefined;
  if (!alg) throw invalid(`unsupported algorithm ${header.alg ?? 'none'}`);

  const pick = (keys: JsonWebKey[]) => keys.find((k) => (header.kid ? (k as { kid?: string }).kid === header.kid : true) && (k as { use?: string }).use !== 'enc');
  let jwk = pick(await jwks(doc.jwks_uri));
  if (!jwk) jwk = pick(await jwks(doc.jwks_uri, true)); // keys rotate
  if (!jwk) throw invalid('signed with a key the provider no longer publishes');

  let ok = false;
  try {
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    const data = Buffer.from(`${h}.${p}`);
    const sig = Buffer.from(s, 'base64url');
    ok = alg.ec
      ? verifySignature(alg.hash, data, { key, dsaEncoding: 'ieee-p1363' }, sig)
      : alg.pss
        ? verifySignature(alg.hash, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig)
        : verifySignature(alg.hash, data, key, sig);
  } catch {
    ok = false;
  }
  if (!ok) throw invalid('bad signature');

  const sec = Math.floor(now / 1000);
  if (claims.iss?.replace(/\/+$/, '') !== expect.issuer.replace(/\/+$/, '')) throw invalid('wrong issuer');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expect.clientId)) throw invalid('issued for another app');
  if (aud.length > 1 && claims.azp && claims.azp !== expect.clientId) throw invalid('issued for another app');
  if (typeof claims.exp !== 'number' || claims.exp < sec - 60) throw invalid('expired');
  if (typeof claims.iat === 'number' && claims.iat > sec + 300) throw invalid('issued in the future');
  if (claims.nonce !== expect.nonce) throw invalid('replayed or mismatched');
  if (!claims.sub) throw invalid('no subject');
  return claims;
}

/** The email the provider vouches for, if it is in the workspace's domain. */
export function verifiedEmail(claims: IdClaims, c: { provider: string; domain: string }): string {
  const raw = (claims.email ?? (c.provider === 'entra' ? claims.preferred_username : undefined) ?? '').trim().toLowerCase();
  if (!raw || !raw.includes('@')) throw new AppError(403, 'SSO_NO_EMAIL', "The identity provider didn't share an email address. Add the email claim to the app.");
  if (claims.email_verified === false || claims.email_verified === 'false') throw new AppError(403, 'SSO_EMAIL_UNVERIFIED', `${raw} isn't verified with your identity provider.`);
  if (emailDomain(raw) !== c.domain) throw new AppError(403, 'SSO_WRONG_DOMAIN', `${raw} isn't on ${c.domain}, so it can't sign in to this workspace.`);
  if (c.provider === 'google' && claims.hd?.toLowerCase() !== c.domain) throw new AppError(403, 'SSO_WRONG_DOMAIN', `${raw} isn't a Google Workspace account on ${c.domain}.`);
  return raw;
}
