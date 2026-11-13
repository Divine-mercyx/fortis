import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pool } from '../src/db/client';
import { stepAt, totpAt } from '../src/lib/totp';
import { ORIGIN, resetDb, setupApp, signup, type Client } from './helpers';

let app: FastifyInstance;
beforeAll(async () => {
  app = await setupApp();
});
afterAll(async () => {
  await app.close();
  await pool.end();
});
beforeEach(resetDb);

const PASSWORD = 'correct-horse-battery';
/** The code an authenticator app shows `offset` steps from now. */
const code = (secret: string, offset = 0) => totpAt(secret, stepAt(Date.now()) + offset);

const login = (email: string, password = PASSWORD) =>
  app.inject({ method: 'POST', url: '/v1/auth/login', headers: { origin: ORIGIN }, payload: { email, password } });
const secondStep = (challenge: string, c: string) =>
  app.inject({ method: 'POST', url: '/v1/auth/login/2fa', headers: { origin: ORIGIN }, payload: { challenge, code: c } });
const cookieOf = (res: { headers: Record<string, unknown> }) => {
  const raw = res.headers['set-cookie'];
  return raw ? String(Array.isArray(raw) ? raw[0] : raw).split(';')[0]! : null;
};

/** Signs up and turns 2FA on. Returns the client, the secret and the recovery codes. */
async function withTwoFactor(email = 'ada@paywave.ng'): Promise<{ client: Client; secret: string; recovery: string[]; email: string }> {
  const client = await signup(app, email);
  const setup = await client.req({ method: 'POST', url: '/v1/auth/2fa/setup' });
  expect(setup.statusCode).toBe(200);
  const { secret, otpauthUrl } = setup.json();
  expect(otpauthUrl).toContain(`secret=${secret}`);
  const enable = await client.req({ method: 'POST', url: '/v1/auth/2fa/enable', payload: { code: code(secret) } });
  expect(enable.statusCode).toBe(200);
  return { client, secret, recovery: enable.json().recoveryCodes, email };
}

describe('turning on two-factor authentication', () => {
  it('is off for a new account, and the password alone signs in', async () => {
    const client = await signup(app, 'ada@paywave.ng');
    expect((await client.req({ method: 'GET', url: '/v1/auth/2fa' })).json()).toMatchObject({ enabled: false, recoveryCodesLeft: 0 });
    expect((await client.req({ method: 'GET', url: '/v1/auth/me' })).json().user.twoFactorEnabled).toBe(false);
    const res = await login('ada@paywave.ng');
    expect(res.statusCode).toBe(200);
    expect(cookieOf(res)).toMatch(/^fortis_session=/);
  });

  it('needs a correct code from the app before it turns on, and gives ten recovery codes once', async () => {
    const client = await signup(app, 'ada@paywave.ng');
    const { secret } = (await client.req({ method: 'POST', url: '/v1/auth/2fa/setup' })).json();
    const wrong = await client.req({ method: 'POST', url: '/v1/auth/2fa/enable', payload: { code: code(secret, 5) } });
    expect(wrong.statusCode).toBe(401);
    expect(wrong.json().error.code).toBe('INVALID_CODE');
    expect((await client.req({ method: 'GET', url: '/v1/auth/2fa' })).json().enabled).toBe(false);

    const ok = await client.req({ method: 'POST', url: '/v1/auth/2fa/enable', payload: { code: code(secret) } });
    expect(ok.statusCode).toBe(200);
    const codes: string[] = ok.json().recoveryCodes;
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) expect(c).toMatch(/^[a-z2-9]{4}-[a-z2-9]{4}$/);
    expect((await client.req({ method: 'GET', url: '/v1/auth/2fa' })).json()).toMatchObject({ enabled: true, recoveryCodesLeft: 10 });
    expect((await client.req({ method: 'GET', url: '/v1/auth/me' })).json().user.twoFactorEnabled).toBe(true);

    // A second setup is refused while it's on.
    expect((await client.req({ method: 'POST', url: '/v1/auth/2fa/setup' })).statusCode).toBe(409);
  });

  it('gives the same secret to setups started together, so the QR code shown is the one stored', async () => {
    const client = await signup(app, 'ada@paywave.ng');
    const all = await Promise.all([1, 2, 3, 4].map(() => client.req({ method: 'POST', url: '/v1/auth/2fa/setup' })));
    const secrets = new Set(all.map((r) => r.json().secret));
    expect(secrets.size).toBe(1);
    const [secret] = [...secrets] as string[];
    expect((await client.req({ method: 'POST', url: '/v1/auth/2fa/enable', payload: { code: code(secret!) } })).statusCode).toBe(200);
  });

  it('stores the secret encrypted and the recovery codes only as hashes', async () => {
    const { secret, recovery } = await withTwoFactor();
    const { rows } = await pool.query('select two_factor_secret, two_factor_pending_secret from users');
    expect(rows[0].two_factor_secret).toMatch(/^v1\./);
    expect(rows[0].two_factor_secret).not.toContain(secret);
    expect(rows[0].two_factor_pending_secret).toBeNull();
    const hashes = (await pool.query('select code_hash from recovery_codes')).rows.map((r) => r.code_hash as string);
    expect(hashes).toHaveLength(10);
    for (const c of recovery) expect(hashes.join(' ')).not.toContain(c.replace('-', ''));
  });

  it('signs out the other browsers that got in with the password alone, and keeps this one', async () => {
    const client = await signup(app, 'ada@paywave.ng');
    const other = cookieOf(await login('ada@paywave.ng'))!;
    const { secret } = (await client.req({ method: 'POST', url: '/v1/auth/2fa/setup' })).json();
    await client.req({ method: 'POST', url: '/v1/auth/2fa/enable', payload: { code: code(secret) } });
    expect((await client.req({ method: 'GET', url: '/v1/auth/me' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/v1/auth/me', headers: { cookie: other } })).statusCode).toBe(401);
  });

  it('records it in the audit log of each workspace the user is in', async () => {
    const { client } = await withTwoFactor();
    const entries = (await client.req({ method: 'GET', url: `/v1/orgs/${client.orgId}/audit` })).json().entries as { action: string }[];
    expect(entries.map((e) => e.action)).toContain('user.two_factor_enabled');
  });

  it('shows admins which members use an authenticator', async () => {
    const { client } = await withTwoFactor();
    const members = (await client.req({ method: 'GET', url: `/v1/orgs/${client.orgId}/members` })).json().members;
    expect(members[0]).toMatchObject({ email: 'ada@paywave.ng', twoFactorEnabled: true });
  });
});

describe('signing in with two-factor on', () => {
  it('asks for a code after the right password, and only then sets the session cookie', async () => {
    const { secret, email } = await withTwoFactor();
    const first = await login(email);
    expect(first.statusCode).toBe(200);
    expect(first.json()).toEqual({ twoFactorRequired: true, challenge: expect.any(String) });
    expect(cookieOf(first)).toBeNull();

    const second = await secondStep(first.json().challenge, code(secret, 1));
    expect(second.statusCode).toBe(200);
    expect(second.json().user).toMatchObject({ email, twoFactorEnabled: true });
    expect(second.json().orgs).toHaveLength(1);
    const cookie = cookieOf(second)!;
    expect(cookie).toMatch(/^fortis_session=/);
    expect((await app.inject({ method: 'GET', url: '/v1/auth/me', headers: { cookie } })).statusCode).toBe(200);
  });

  it('still says only "incorrect" for a wrong password, without revealing that 2FA is on', async () => {
    const { email } = await withTwoFactor();
    const res = await login(email, 'wrong-password-here');
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe('INVALID_CREDENTIALS');
  });

  it('refuses a wrong code, and a code already used', async () => {
    const { secret, email } = await withTwoFactor();
    const { challenge } = (await login(email)).json();
    expect((await secondStep(challenge, code(secret, 4))).json().error.code).toBe('INVALID_CODE');
    // The code that turned 2FA on can't sign in again, even inside its half-minute.
    const used = Number((await pool.query('select two_factor_last_step from users')).rows[0].two_factor_last_step);
    expect((await secondStep(challenge, totpAt(secret, used))).json().error.code).toBe('INVALID_CODE');
    expect((await secondStep(challenge, totpAt(secret, used + 1))).statusCode).toBe(200);
    // The challenge is spent once used.
    expect((await secondStep(challenge, code(secret, 1))).json().error.code).toBe('CHALLENGE_EXPIRED');
  });

  it('ends the challenge after five wrong codes', async () => {
    const { secret, email } = await withTwoFactor();
    const { challenge } = (await login(email)).json();
    for (let i = 0; i < 4; i++) expect((await secondStep(challenge, '000000')).json().error.code).toBe('INVALID_CODE');
    expect((await secondStep(challenge, '000000')).json().error.code).toBe('CHALLENGE_EXPIRED');
    expect((await secondStep(challenge, code(secret, 1))).json().error.code).toBe('CHALLENGE_EXPIRED');
  });

  it('refuses an expired challenge and an unknown one', async () => {
    const { secret, email } = await withTwoFactor();
    const { challenge } = (await login(email)).json();
    await pool.query("update login_challenges set expires_at = now() - interval '1 second'");
    expect((await secondStep(challenge, code(secret, 1))).json().error.code).toBe('CHALLENGE_EXPIRED');
    expect((await secondStep('x'.repeat(43), code(secret, 1))).json().error.code).toBe('CHALLENGE_EXPIRED');
  });

  it('accepts each recovery code once, in any case and with or without the dash', async () => {
    const { client, recovery, email } = await withTwoFactor();
    const typed = recovery[0]!.toUpperCase().replace('-', ' ');
    const ok = await secondStep((await login(email)).json().challenge, typed);
    expect(ok.statusCode).toBe(200);
    expect(ok.json().recoveryCodesLeft).toBe(9);
    expect((await secondStep((await login(email)).json().challenge, recovery[0]!)).json().error.code).toBe('INVALID_CODE');
    const entries = (await client.req({ method: 'GET', url: `/v1/orgs/${client.orgId}/audit` })).json().entries as { action: string }[];
    expect(entries.map((e) => e.action)).toContain('user.recovery_code_used');
  });
});

describe('managing two-factor', () => {
  it('replaces the recovery codes with a current code, and the old ones stop working', async () => {
    const { client, secret, recovery, email } = await withTwoFactor();
    expect((await client.req({ method: 'POST', url: '/v1/auth/2fa/recovery-codes', payload: { code: '000000' } })).statusCode).toBe(401);
    const res = await client.req({ method: 'POST', url: '/v1/auth/2fa/recovery-codes', payload: { code: code(secret, 1) } });
    expect(res.statusCode).toBe(200);
    expect(res.json().recoveryCodes).toHaveLength(10);
    expect((await secondStep((await login(email)).json().challenge, recovery[1]!)).json().error.code).toBe('INVALID_CODE');
    expect((await secondStep((await login(email)).json().challenge, res.json().recoveryCodes[0])).statusCode).toBe(200);
  });

  it('turns off only with the password and a current code, then the password alone signs in again', async () => {
    const { client, secret, email } = await withTwoFactor();
    const noPassword = await client.req({ method: 'POST', url: '/v1/auth/2fa/disable', payload: { password: 'wrong-password-here', code: code(secret, 1) } });
    expect(noPassword.json().error.code).toBe('INVALID_CREDENTIALS');
    const noCode = await client.req({ method: 'POST', url: '/v1/auth/2fa/disable', payload: { password: PASSWORD, code: '000000' } });
    expect(noCode.json().error.code).toBe('INVALID_CODE');
    expect((await client.req({ method: 'GET', url: '/v1/auth/2fa' })).json().enabled).toBe(true);

    const off = await client.req({ method: 'POST', url: '/v1/auth/2fa/disable', payload: { password: PASSWORD, code: code(secret, 1) } });
    expect(off.statusCode).toBe(200);
    expect((await client.req({ method: 'GET', url: '/v1/auth/2fa' })).json()).toMatchObject({ enabled: false, recoveryCodesLeft: 0 });
    expect((await pool.query('select count(*)::int as n from recovery_codes')).rows[0].n).toBe(0);
    expect(cookieOf(await login(email))).toMatch(/^fortis_session=/);
    const entries = (await client.req({ method: 'GET', url: `/v1/orgs/${client.orgId}/audit` })).json().entries as { action: string }[];
    expect(entries.map((e) => e.action)).toContain('user.two_factor_disabled');
  });

  it('needs a signed-in session for every settings route', async () => {
    for (const url of ['/v1/auth/2fa/setup', '/v1/auth/2fa/enable', '/v1/auth/2fa/recovery-codes', '/v1/auth/2fa/disable']) {
      const res = await app.inject({ method: 'POST', url, headers: { origin: ORIGIN }, payload: { code: '123456', password: 'x' } });
      expect(res.statusCode).toBe(401);
    }
    expect((await app.inject({ method: 'GET', url: '/v1/auth/2fa' })).statusCode).toBe(401);
  });
});
