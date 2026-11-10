import { describe, expect, it } from 'vitest';

import { checksFromOpenApi, checksFromRoutes, looksLikeId, routesFromHar, routesFromOpenApi, routesFromPostman } from '../src/access-import';

describe('routes to checks', () => {
  it('adds a writes block only when create and write routes both exist', () => {
    const spec = {
      paths: {
        '/api/loans': { get: {}, post: {} },
        '/api/loans/{loanId}': { get: {}, put: {}, patch: {}, delete: {} },
        '/api/wallets/': { get: {} },
        '/api/wallets/{id}/': { get: {}, delete: {} },
      },
    };
    expect(checksFromOpenApi(spec)).toEqual([
      { name: 'Loan', list: '/api/loans', get: '/api/loans/{id}', writes: { create: { path: '/api/loans', body: {} }, put: { body: {} }, patch: { body: {} }, delete: {} } },
      { name: 'Wallet', list: '/api/wallets/', get: '/api/wallets/{id}/' },
    ]);
  });

  it('reads every method from OpenAPI', () => {
    expect(routesFromOpenApi({ paths: { '/a': { get: {}, post: {}, parameters: [] } } })).toEqual([{ method: 'GET', path: '/a' }, { method: 'POST', path: '/a' }]);
  });
});

describe('Postman collections', () => {
  it('reads nested folders, path variables and every URL form', () => {
    const routes = routesFromPostman({
      item: [
        { item: [{ request: { method: 'get', url: { raw: '{{base}}/api/loans?page=1', path: ['api', 'loans'] } } }] },
        { request: { method: 'GET', url: { raw: '{{base}}/api/loans/:loanId', path: ['api', 'loans', ':loanId'] } } },
        { request: { method: 'DELETE', url: '{{base}}/api/loans/{{loanId}}' } },
        { request: { method: 'POST', url: 'https://staging.x.ng/api/loans' } },
        { request: 'https://staging.x.ng/api/loans/123' },
      ],
    });
    expect(routes).toEqual([
      { method: 'GET', path: '/api/loans' },
      { method: 'GET', path: '/api/loans/{id}' },
      { method: 'DELETE', path: '/api/loans/{id}' },
      { method: 'POST', path: '/api/loans' },
      { method: 'GET', path: '/api/loans/{id}' },
    ]);
    expect(checksFromRoutes(routes)).toEqual([{ name: 'Loan', list: '/api/loans', get: '/api/loans/{id}', writes: { create: { path: '/api/loans', body: {} }, delete: {} } }]);
  });

  it('rejects a file that is not a collection', () => {
    expect(() => routesFromPostman({} as never)).toThrow(/not a Postman collection/);
  });
});

describe('HAR files', () => {
  const entry = (method: string, url: string) => ({ request: { method, url } });

  it('turns real IDs into {id}, drops query strings and static files, and keeps the target host', () => {
    const har = {
      log: {
        entries: [
          entry('GET', 'https://staging.x.ng/api/loans?token=abc'),
          entry('GET', 'https://staging.x.ng/api/loans/550e8400-e29b-41d4-a716-446655440000'),
          entry('GET', 'https://staging.x.ng/static/app.js'),
          entry('GET', 'https://analytics.example.com/api/events/1'),
          entry('GET', 'not a url'),
        ],
      },
    };
    expect(routesFromHar(har, 'https://staging.x.ng')).toEqual([{ method: 'GET', path: '/api/loans' }, { method: 'GET', path: '/api/loans/{id}' }]);
  });

  it('picks the busiest host when no target is given', () => {
    const har = { log: { entries: [entry('GET', 'https://a.example/x'), entry('GET', 'https://b.example/y'), entry('GET', 'https://b.example/z')] } };
    expect(routesFromHar(har).map((r) => r.path)).toEqual(['/y', '/z']);
  });

  it('rejects a file that is not a HAR', () => {
    expect(() => routesFromHar({} as never)).toThrow(/not a HAR file/);
  });

  it('recognises common ID shapes and leaves words alone', () => {
    for (const id of ['123', '550e8400-e29b-41d4-a716-446655440000', '507f1f77bcf86cd799439011', '01ARZ3NDEKTSV4RRFFQ69G5FAV', 'trf_01J9ZQ3']) expect(looksLikeId(id), id).toBe(true);
    for (const word of ['loans', 'api', 'v1', 'me', 'wallet-history', 'first_name']) expect(looksLikeId(word), word).toBe(false);
  });
});
