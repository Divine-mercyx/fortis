import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pool } from '../src/db/client';
import { ORIGIN, resetDb, setupApp, signup } from './helpers';

let app: FastifyInstance;
beforeAll(async () => {
  app = await setupApp();
});
afterAll(async () => {
  await app.close();
  await pool.end();
});
beforeEach(resetDb);

describe('accounts', () => {
  it('signs up, creates an owner org on the free plan, and sets an httpOnly session cookie', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/signup',
      headers: { origin: ORIGIN },
      payload: { name: 'Ada Okafor', email: 'Ada@Example.com', password: 'correct-horse-battery', company: 'PayWave Ltd' },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.user.email).toBe('ada@example.com');
    expect(body.orgs).toHaveLength(1);
    expect(body.orgs[0]).toMatchObject({ name: 'PayWave Ltd', role: 'owner', plan: 'free' });
    const cookie = String(res.headers['set-cookie']);
    expect(cookie).toMatch(/fortis_session=/);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Lax/i);
  });

  it('never stores the password in plain text', async () => {
    await signup(app, 'ada@example.com');
    const { rows } = await pool.query('select password_hash from users');
    expect(rows[0].password_hash).toMatch(/^\$argon2id\$/);
    expect(rows[0].password_hash).not.toContain('correct-horse-battery');
  });

  it('rejects a duplicate email regardless of case', async () => {
    await signup(app, 'ada@example.com');
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/signup',
      headers: { origin: ORIGIN },
      payload: { name: 'Ada', email: 'ADA@example.com', password: 'correct-horse-battery', company: 'Other' },
    });
    expect(res.statusCode).toBe(409);
    expect(res.json().error.code).toBe('EMAIL_TAKEN');
  });

  it('rejects short passwords', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/signup',
      headers: { origin: ORIGIN },
      payload: { name: 'Ada', email: 'a@example.com', password: 'short', company: 'Co' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('logs in with the right password only, with the same error for unknown emails', async () => {
    await signup(app, 'ada@example.com');
    const bad = await app.inject({ method: 'POST', url: '/v1/auth/login', payload: { email: 'ada@example.com', password: 'wrong-password' } });
    const unknown = await app.inject({ method: 'POST', url: '/v1/auth/login', payload: { email: 'nobody@example.com', password: 'wrong-password' } });
    expect(bad.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(bad.json().error.message).toBe(unknown.json().error.message);
    const ok = await app.inject({ method: 'POST', url: '/v1/auth/login', payload: { email: 'ADA@example.com', password: 'correct-horse-battery' } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().orgs).toHaveLength(1);
  });

  it('returns the current user from the session and forgets it after logout', async () => {
    const c = await signup(app);
    const me = await c.req({ method: 'GET', url: '/v1/auth/me' });
    expect(me.statusCode).toBe(200);
    expect(me.json().user.id).toBe(c.userId);
    const out = await c.req({ method: 'POST', url: '/v1/auth/logout' });
    expect(out.statusCode).toBe(200);
    const after = await c.req({ method: 'GET', url: '/v1/auth/me' });
    expect(after.statusCode).toBe(401);
  });

  it('blocks cookie-authenticated writes from another site', async () => {
    const c = await signup(app);
    const res = await c.req({
      method: 'POST',
      url: `/v1/orgs/${c.orgId}/projects`,
      headers: { origin: 'https://evil.example' },
      payload: { name: 'sneaky' },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('BAD_ORIGIN');
  });

  it('refuses form and text bodies that skip the browser preflight', async () => {
    const c = await signup(app);
    const res = await c.req({
      method: 'POST',
      url: `/v1/orgs/${c.orgId}/projects`,
      headers: { 'content-type': 'text/plain' },
      payload: '{"name":"sneaky"}',
    });
    expect(res.statusCode).toBe(415);
  });
});
