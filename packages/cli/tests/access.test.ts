import { describe, expect, it } from 'vitest';

import { checksFromOpenApi, extractIds, runAccessChecks, type AccessConfig } from '../src/access';

// A tiny fake API: loans belong to a user; `leaky` routes forget to check the owner.
function fakeApi(opts: { leaky?: boolean; anonymous?: boolean }) {
  const loans: Record<string, { id: string; owner: string; amount: number }> = {
    L1: { id: 'L1', owner: 'A', amount: 50000 },
    L2: { id: 'L2', owner: 'B', amount: 9000 },
  };
  const who = (h: Record<string, string>) => (h.Authorization === 'Bearer tok-a' ? 'A' : h.Authorization === 'Bearer tok-b' ? 'B' : null);
  const sent: string[] = [];
  const http = async (url: string, headers: Record<string, string>) => {
    sent.push(`${who(headers) ?? 'anon'} ${url}`);
    const u = new URL(url);
    const user = who(headers);
    if (u.pathname === '/api/loans') {
      if (!user) return { status: 401, body: '{"error":"login"}' };
      return { status: 200, body: JSON.stringify({ data: Object.values(loans).filter((l) => l.owner === user) }) };
    }
    const m = /^\/api\/loans\/(\w+)$/.exec(u.pathname);
    if (m) {
      const loan = loans[m[1]!];
      if (!user && !opts.anonymous) return { status: 401, body: '{"error":"login"}' };
      if (!loan || (!opts.leaky && loan.owner !== user)) return { status: 404, body: `{"error":"loan ${m[1]} not found"}` };
      return { status: 200, body: JSON.stringify(loan) };
    }
    return { status: 404, body: '' };
  };
  return { http, sent };
}

const config: AccessConfig = { checks: [{ name: 'Loan', list: '/api/loans', get: '/api/loans/{id}' }] };
const run = (api: ReturnType<typeof fakeApi>) =>
  runAccessChecks({ origin: 'https://staging.x.ng', config, tokenA: 'tok-a', tokenB: 'tok-b', delayMs: 0 }, api.http);

describe('access checks', () => {
  it('passes when B gets 404 for A’s record, even though the error echoes the ID', async () => {
    const res = await run(fakeApi({}));
    expect(res.findings).toEqual([]);
    expect(res.checked).toBe(1);
  });

  it('flags BOLA when B can read A’s loan', async () => {
    const res = await run(fakeApi({ leaky: true }));
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]).toMatchObject({ ruleId: 'FX-BOLA-001', severity: 'critical', file: 'GET /api/loans/{id}', evidence: { status: { a: 200, b: 200, anonymous: 401 }, id: 'L1' } });
  });

  it('flags a record readable with no login at all', async () => {
    const res = await run(fakeApi({ leaky: true, anonymous: true }));
    expect(res.findings[0]!.ruleId).toBe('FX-AUTH-001');
  });

  it('only sends GET requests and respects the request limit', async () => {
    const api = fakeApi({});
    await run(api);
    expect(api.sent).toHaveLength(4); // list as A, then A, B and anonymous for L1
    await expect(runAccessChecks({ origin: 'https://s.x.ng', config, tokenA: 'tok-a', tokenB: 'tok-b', delayMs: 0, maxRequests: 2 }, api.http)).rejects.toThrow(/safety limit/);
  });

  it('skips IDs user A cannot read, with a note', async () => {
    const res = await runAccessChecks(
      { origin: 'https://s.x.ng', config: { checks: [{ name: 'Loan', get: '/api/loans/{id}', ids: ['L2'] }] }, tokenA: 'tok-a', tokenB: 'tok-b', delayMs: 0 },
      fakeApi({}).http,
    );
    expect(res.findings).toEqual([]);
    expect(res.notes[0]).toMatch(/isn't A's record/);
  });

  it('finds IDs in common list shapes', () => {
    expect(extractIds('[{"id":1},{"id":2}]')).toEqual(['1', '2']);
    expect(extractIds('{"status":true,"data":{"loans":[{"loanId":"x9"}]}}', 'loanId')).toEqual(['x9']);
    expect(extractIds('not json')).toEqual([]);
  });

  it('builds checks from an OpenAPI spec', () => {
    const spec = { paths: { '/api/loans': { get: {} }, '/api/loans/{loanId}': { get: {} }, '/api/wallets/{id}': { get: {} }, '/api/users/{id}/cards/{cardId}': { get: {} } } };
    expect(checksFromOpenApi(spec)).toEqual([{ name: 'Loan', list: '/api/loans', get: '/api/loans/{id}' }]);
  });
});
