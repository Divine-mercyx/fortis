import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';

import { createdId, graphqlSucceeded, readAccessConfig, runAccessChecks, type AccessConfig } from '../src/access';
import { checksFromGraphqlSchema } from '../src/access-graphql';
import { sampleApi, SAMPLE_SCHEMA, TOKEN_A, TOKEN_B, type Holes } from './sample-api/vulnerable-api';

const execFileAsync = promisify(execFile);

const LOAN = { name: 'Loan', list: '/api/loans', get: '/api/loans/{id}' };
const WRITES = { create: { path: '/api/loans', body: { amount: 1, note: 'fortis-test' } }, put: { body: { amount: 2, note: 'put' } }, patch: { body: { note: 'patch' } }, delete: {} };
const GRAPHQL_CHECK = {
  name: 'Loan',
  list: 'query { loans { id } }',
  read: 'query($id: ID!) { loan(id: $id) { id amount note } }',
  writes: {
    create: { mutation: 'mutation($input: CreateLoanInput!) { createLoan(input: $input) { id } }', variables: { input: { amount: 1 } } },
    update: { mutation: 'mutation($id: ID!, $input: UpdateLoanInput!) { updateLoan(id: $id, input: $input) { id } }', variables: { input: { note: 'changed' } } },
    delete: { mutation: 'mutation($id: ID!) { deleteLoan(id: $id) }' },
  },
};
const FULL: AccessConfig = { checks: [{ ...LOAN, writes: WRITES }], graphql: { path: '/graphql', checks: [GRAPHQL_CHECK] } };

const started: ReturnType<typeof sampleApi>[] = [];
async function run(config: AccessConfig, holes: Holes | undefined, opts: { writes?: boolean; maxRequests?: number } = {}) {
  const api = sampleApi(holes);
  started.push(api);
  const origin = await api.start();
  const result = await runAccessChecks({ origin, config, tokenA: TOKEN_A, tokenB: TOKEN_B, delayMs: 0, ...opts });
  return { api, result };
}
afterEach(async () => {
  await Promise.all(started.splice(0).map((a) => a.stop()));
});

const labels = (r: { findings: { ruleId: string; file?: string }[] }) => r.findings.map((f) => `${f.ruleId} ${f.file}`).sort();
const SEEDED = ['L1', 'L2'];

describe('the deliberately vulnerable sample API', () => {
  it('is caught for read, update and delete over REST and GraphQL', async () => {
    const { result } = await run(FULL, undefined, { writes: true });
    expect(labels(result)).toEqual([
      'FX-BOLA-001 GET /api/loans/{id}',
      'FX-BOLA-001 GraphQL loan',
      'FX-BOLA-002 DELETE /api/loans/{id}',
      'FX-BOLA-002 GraphQL deleteLoan',
      'FX-BOLA-002 GraphQL updateLoan',
      'FX-BOLA-002 PATCH /api/loans/{id}',
      'FX-BOLA-002 PUT /api/loans/{id}',
    ].sort());
    expect(result.writesChecked).toBe(2);
    expect(result.writesIncomplete).toBe(false);
  });

  it('finds each hole on its own', async () => {
    expect(labels((await run(FULL, { update: true }, { writes: true })).result)).toEqual(['FX-BOLA-002 GraphQL updateLoan', 'FX-BOLA-002 PATCH /api/loans/{id}', 'FX-BOLA-002 PUT /api/loans/{id}']);
    expect(labels((await run(FULL, { delete: true }, { writes: true })).result)).toEqual(['FX-BOLA-002 DELETE /api/loans/{id}', 'FX-BOLA-002 GraphQL deleteLoan']);
    expect(labels((await run(FULL, { read: true }, { writes: true })).result)).toEqual(['FX-BOLA-001 GET /api/loans/{id}', 'FX-BOLA-001 GraphQL loan']);
  });

  it('reports nothing on the same API with the holes closed, and leaves no records behind', async () => {
    const { api, result } = await run(FULL, {}, { writes: true });
    expect(result.findings).toEqual([]);
    expect(result.writesChecked).toBe(2);
    expect([...api.loans.keys()]).toEqual(SEEDED);
  });
});

describe('the read-only default', () => {
  it('sends no writes at all, even with a "writes" block in the config and every hole open', async () => {
    const { api, result } = await run(FULL, undefined);
    expect(api.log.filter((e) => e.method !== 'GET' && !(e.method === 'POST' && e.path === '/graphql'))).toEqual([]);
    expect(api.log.map((e) => e.operation).filter((op) => op && !['loans', 'loan'].includes(op))).toEqual([]);
    expect(result.writesChecked).toBe(0);
    expect(result.findings.map((f) => f.ruleId)).toEqual(['FX-BOLA-001', 'FX-BOLA-001']);
    expect(api.loans.get('L1')).toEqual({ id: 'L1', owner: 'A', amount: 50000, note: 'seed' });
    expect([...api.loans.keys()]).toEqual(SEEDED);
  });

  it('refuses a mutation in a read or list query', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-access-'));
    try {
      const write = (cfg: object) => writeFileSync(join(dir, 'a.json'), JSON.stringify(cfg));
      write({ graphql: { path: '/graphql', checks: [{ name: 'Loan', read: 'mutation { deleteLoan(id: "1") }', ids: ['1'] }] } });
      expect(() => readAccessConfig(dir, 'a.json')).toThrow(/must be queries/);
      write({ graphql: { path: '/graphql', checks: [{ name: 'Loan', read: 'query { a }', list: '# x\nmutation { deleteLoan(id: "1") }' }] } });
      expect(() => readAccessConfig(dir, 'a.json')).toThrow(/must be queries/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('write safety', () => {
  it('only writes to the record it created, never to existing ones', async () => {
    const { api } = await run(FULL, undefined, { writes: true });
    const writes = api.log.filter((e) => ['PUT', 'PATCH', 'DELETE'].includes(e.method) || ['updateLoan', 'deleteLoan'].includes(e.operation ?? ''));
    expect(writes.length).toBeGreaterThan(0);
    expect(writes.filter((e) => e.id && SEEDED.includes(e.id))).toEqual([]);
    expect(api.loans.get('L1')?.note).toBe('seed');
    expect(api.loans.get('L2')?.note).toBe('seed');
  });

  it('removes the record as user A when user B could not, and at the safety limit', async () => {
    const config: AccessConfig = { checks: [{ ...LOAN, ids: ['L1'], list: undefined, writes: WRITES }] };
    // 3 reads, then create and read as A, then B's PUT and A's read are cut off by the limit.
    const api = sampleApi({});
    started.push(api);
    const origin = await api.start();
    await expect(runAccessChecks({ origin, config, tokenA: TOKEN_A, tokenB: TOKEN_B, delayMs: 0, writes: true, maxRequests: 7 })).rejects.toThrow(/safety limit/);
    expect([...api.loans.keys()]).toEqual(SEEDED);
  });

  it('notes a write that was accepted but changed nothing, rather than calling it a finding', async () => {
    const config: AccessConfig = { checks: [{ ...LOAN, writes: { create: WRITES.create, put: { body: { unknown: true } } } }] };
    const { api, result } = await run(config, { update: true }, { writes: true });
    expect(result.findings).toEqual([]);
    expect(result.notes.join('\n')).toMatch(/didn't change/);
    // No delete or cleanup was configured, so the user is told what's left behind.
    expect(result.notes.join('\n')).toMatch(/still on staging/);
    expect(api.loans.size).toBe(3);
  });

  it('marks the run incomplete when the throwaway record cannot be created', async () => {
    const config: AccessConfig = { checks: [{ ...LOAN, writes: { ...WRITES, create: { path: '/api/missing', body: {} } } }] };
    const { result } = await run(config, undefined, { writes: true });
    expect(result.writesIncomplete).toBe(true);
    expect(result.writesChecked).toBe(0);
    expect(result.notes.join('\n')).toMatch(/couldn't create a throwaway record/);
  });

  it('needs a create step and a {id} in write paths', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-access-'));
    try {
      const write = (writes: object) => writeFileSync(join(dir, 'a.json'), JSON.stringify({ checks: [{ ...LOAN, writes }] }));
      write({ put: { body: {} } });
      expect(() => readAccessConfig(dir, 'a.json')).toThrow(/throwaway/);
      write({ create: { path: '/x' } });
      expect(() => readAccessConfig(dir, 'a.json')).toThrow(/at least one of/);
      write({ create: { path: '/x' }, delete: { path: '/api/loans/L1' } });
      expect(() => readAccessConfig(dir, 'a.json')).toThrow(/must contain \{id\}/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('GraphQL', () => {
  it('builds working checks by introspecting the schema', async () => {
    const { checks, notes } = checksFromGraphqlSchema(SAMPLE_SCHEMA);
    expect(notes).toEqual([]);
    expect(checks).toHaveLength(1);
    expect(checks[0]).toMatchObject({ name: 'Loan', list: 'query { loans { id } }', read: 'query($id: ID!) { loan(id: $id) { id amount note } }' });
    expect(checks[0]!.writes?.create.variables).toEqual({ input: { amount: 1 } });
    expect(checks[0]!.writes?.update?.variables).toEqual({ input: { amount: 2, note: 'fortis-test-updated' } });

    const { result } = await run({ checks: [], graphql: { path: '/graphql', checks } }, undefined, { writes: true });
    expect(labels(result)).toEqual(['FX-BOLA-001 GraphQL loan', 'FX-BOLA-002 GraphQL deleteLoan', 'FX-BOLA-002 GraphQL updateLoan']);
  });

  it('says so when a mutation takes an ID but nothing creates a throwaway record', () => {
    const types = SAMPLE_SCHEMA.types.map((t) => (t.name === 'Mutation' ? { ...t, fields: t.fields!.filter((f) => f.name !== 'createLoan') } : t));
    const { checks, notes } = checksFromGraphqlSchema({ ...SAMPLE_SCHEMA, types } as never);
    expect(checks[0]!.writes).toBeUndefined();
    expect(notes[0]).toMatch(/updateLoan and deleteLoan take an ID/);
  });

  it('treats a 200 with errors or no data as refused', () => {
    expect(graphqlSucceeded({ status: 200, body: '{"data":{"loan":{"id":"1"}}}' })).toBe(true);
    expect(graphqlSucceeded({ status: 200, body: '{"data":{"loan":null},"errors":[{"message":"no"}]}' })).toBe(false);
    expect(graphqlSucceeded({ status: 200, body: '{"data":{"loan":null}}' })).toBe(false);
    expect(graphqlSucceeded({ status: 200, body: '{"data":{"deleteLoan":false}}' })).toBe(false);
    expect(graphqlSucceeded({ status: 500, body: '{"data":{"loan":{"id":"1"}}}' })).toBe(false);
    expect(graphqlSucceeded({ status: 200, body: 'not json' })).toBe(false);
  });

  it('finds the new ID in REST and GraphQL responses', () => {
    expect(createdId('{"id":"L9"}')).toBe('L9');
    expect(createdId('{"data":{"createLoan":{"id":12}}}')).toBe('12');
    expect(createdId('{"data":{"loan":{"loanId":"x"}}}', 'loanId')).toBe('x');
    expect(createdId('{"ok":true}')).toBeUndefined();
  });
});

describe('fortis access on the command line', () => {
  const cli = join(__dirname, '..', 'src', 'index.ts');
  const tsx = join(__dirname, '..', 'node_modules', 'tsx', 'dist', 'cli.mjs');
  const fortis = async (cwd: string, ...args: string[]) => {
    try {
      const { stdout } = await execFileAsync(process.execPath, [tsx, cli, ...args], { cwd, env: { ...process.env, FORTIS_USER_A_TOKEN: TOKEN_A, FORTIS_USER_B_TOKEN: TOKEN_B, FORCE_COLOR: '0', NO_COLOR: '1' } });
      return { code: 0, stdout, stderr: '' };
    } catch (e) {
      const x = e as { code: number; stdout: string; stderr: string };
      return { code: x.code, stdout: x.stdout, stderr: x.stderr };
    }
  };

  it('stays read-only by default, and --writes finds the rest', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-access-'));
    const api = sampleApi();
    started.push(api);
    try {
      const origin = await api.start();
      writeFileSync(join(dir, '.fortis-access.json'), JSON.stringify(FULL));

      const readOnly = await fortis(dir, 'access', '--target', origin, '--local', '--json');
      expect(readOnly.code).toBe(1);
      expect((JSON.parse(readOnly.stdout) as { findings: { ruleId: string }[] }).findings.map((f) => f.ruleId)).toEqual(['FX-BOLA-001', 'FX-BOLA-001']);
      expect(api.log.filter((e) => ['PUT', 'PATCH', 'DELETE'].includes(e.method))).toEqual([]);

      const withWrites = await fortis(dir, 'access', '--target', origin, '--local', '--writes', '--json');
      expect(withWrites.code).toBe(1);
      expect((JSON.parse(withWrites.stdout) as { findings: { ruleId: string }[] }).findings.filter((f) => f.ruleId === 'FX-BOLA-002')).toHaveLength(5);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it('refuses --writes when the config has nothing to write with', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-access-'));
    try {
      writeFileSync(join(dir, '.fortis-access.json'), JSON.stringify({ checks: [LOAN] }));
      const res = await fortis(dir, 'access', '--target', 'http://127.0.0.1:1', '--local', '--writes');
      expect(res.code).toBe(2);
      expect(res.stderr).toMatch(/needs a "writes" block/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it('builds a config from a live GraphQL server, a Postman collection and a HAR file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-access-'));
    const api = sampleApi();
    started.push(api);
    try {
      const origin = await api.start();
      const postman = { item: [{ name: 'Loans', item: [{ request: { method: 'GET', url: '{{base}}/api/loans' } }, { request: { method: 'GET', url: '{{base}}/api/loans/:id' } }] }] };
      const har = { log: { entries: [{ request: { method: 'GET', url: `${origin}/api/wallets?token=secret-value` } }, { request: { method: 'GET', url: `${origin}/api/wallets/4821` } }] } };
      writeFileSync(join(dir, 'p.json'), JSON.stringify(postman));
      writeFileSync(join(dir, 'h.har'), JSON.stringify(har));
      const res = await fortis(dir, 'access', 'init', '--postman', 'p.json', '--har', 'h.har', '--graphql', `${origin}/graphql`);
      expect(res.code).toBe(0);
      const file = join(dir, '.fortis-access.json');
      expect(existsSync(file)).toBe(true);
      const text = readFileSync(file, 'utf8');
      const cfg = JSON.parse(text) as AccessConfig;
      expect(cfg.checks.map((c) => c.get).sort()).toEqual(['/api/loans/{id}', '/api/wallets/{id}']);
      expect(cfg.graphql?.path).toBe('/graphql');
      expect(cfg.graphql?.checks[0]?.name).toBe('Loan');
      expect(text).not.toContain('secret-value');
      expect(text).not.toContain('4821');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
