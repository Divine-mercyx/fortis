import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';

import type { GraphqlSchema } from '../../src/access-graphql';

/*
 * A deliberately vulnerable sample API with the same loans over REST and GraphQL. Each hole can be
 * turned off on its own, and with all of them off it's a correctly protected API.
 * Never deploy this. It exists so tests can prove `fortis access` catches real holes.
 *
 *   tsx tests/sample-api/vulnerable-api.ts 3999
 */

export const TOKEN_A = 'sample-token-a';
export const TOKEN_B = 'sample-token-b';

export type Holes = { read?: boolean; update?: boolean; delete?: boolean };
type Loan = { id: string; owner: string; amount: number; note: string };
export type Logged = { method: string; path: string; user: string; operation?: string; id?: string };

type TypeRef = { kind: string; name: string | null; ofType: TypeRef | null };
const scalar = (name: string): TypeRef => ({ kind: 'SCALAR', name, ofType: null });
const nonNull = (ofType: TypeRef): TypeRef => ({ kind: 'NON_NULL', name: null, ofType });
const list = (ofType: TypeRef): TypeRef => ({ kind: 'LIST', name: null, ofType });
const obj = (name: string): TypeRef => ({ kind: 'OBJECT', name, ofType: null });
const input = (name: string): TypeRef => ({ kind: 'INPUT_OBJECT', name, ofType: null });

/** What a real server answers to the introspection query. */
export const SAMPLE_SCHEMA: GraphqlSchema = {
  queryType: { name: 'Query' },
  mutationType: { name: 'Mutation' },
  types: [
    {
      kind: 'OBJECT', name: 'Query', inputFields: null, enumValues: null,
      fields: [
        { name: 'loans', args: [], type: nonNull(list(nonNull(obj('Loan')))) },
        { name: 'loan', args: [{ name: 'id', type: nonNull(scalar('ID')) }], type: obj('Loan') },
        { name: 'health', args: [], type: scalar('String') },
      ],
    },
    {
      kind: 'OBJECT', name: 'Mutation', inputFields: null, enumValues: null,
      fields: [
        { name: 'createLoan', args: [{ name: 'input', type: nonNull(input('CreateLoanInput')) }], type: obj('Loan') },
        { name: 'updateLoan', args: [{ name: 'id', type: nonNull(scalar('ID')) }, { name: 'input', type: nonNull(input('UpdateLoanInput')) }], type: obj('Loan') },
        { name: 'deleteLoan', args: [{ name: 'id', type: nonNull(scalar('ID')) }], type: scalar('Boolean') },
      ],
    },
    {
      kind: 'OBJECT', name: 'Loan', inputFields: null, enumValues: null,
      fields: [
        { name: 'id', args: [], type: nonNull(scalar('ID')) },
        { name: 'amount', args: [], type: nonNull(scalar('Int')) },
        { name: 'note', args: [], type: scalar('String') },
      ],
    },
    { kind: 'INPUT_OBJECT', name: 'CreateLoanInput', fields: null, enumValues: null, inputFields: [{ name: 'amount', type: nonNull(scalar('Int')) }, { name: 'note', type: scalar('String') }] },
    { kind: 'INPUT_OBJECT', name: 'UpdateLoanInput', fields: null, enumValues: null, inputFields: [{ name: 'amount', type: scalar('Int') }, { name: 'note', type: scalar('String') }] },
  ],
};

export function sampleApi(holes: Holes = { read: true, update: true, delete: true }) {
  let next = 3;
  const loans = new Map<string, Loan>([
    ['L1', { id: 'L1', owner: 'A', amount: 50000, note: 'seed' }],
    ['L2', { id: 'L2', owner: 'B', amount: 9000, note: 'seed' }],
  ]);
  const log: Logged[] = [];
  const who = (req: IncomingMessage) => {
    const auth = req.headers.authorization;
    return auth === `Bearer ${TOKEN_A}` ? 'A' : auth === `Bearer ${TOKEN_B}` ? 'B' : null;
  };
  const show = ({ owner: _owner, ...loan }: Loan) => loan;
  const canReach = (loan: Loan | undefined, user: string, hole: boolean | undefined): loan is Loan => Boolean(loan && (hole || loan.owner === user));
  const create = (user: string, data: Partial<Loan>) => {
    const loan: Loan = { id: `L${next++}`, owner: user, amount: Number(data.amount ?? 1), note: String(data.note ?? '') };
    loans.set(loan.id, loan);
    return loan;
  };

  const rest = (req: IncomingMessage, res: ServerResponse, path: string, body: Record<string, unknown>, user: string | null) => {
    const send = (status: number, json?: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(json === undefined ? '' : JSON.stringify(json));
    };
    if (!user) return send(401, { error: 'login required' });
    if (path === '/api/loans') {
      if (req.method === 'GET') return send(200, { data: [...loans.values()].filter((l) => l.owner === user).map(show) });
      if (req.method === 'POST') return send(201, show(create(user, body)));
      return send(405, { error: 'method not allowed' });
    }
    const id = decodeURIComponent(path.slice('/api/loans/'.length));
    const loan = loans.get(id);
    const hole = req.method === 'GET' ? holes.read : req.method === 'DELETE' ? holes.delete : holes.update;
    log[log.length - 1]!.id = id;
    if (!canReach(loan, user, hole)) return send(404, { error: `loan ${id} not found` });
    if (req.method === 'GET') return send(200, show(loan));
    if (req.method === 'PUT' || req.method === 'PATCH') {
      if (body.amount !== undefined) loan.amount = Number(body.amount);
      if (body.note !== undefined) loan.note = String(body.note);
      return send(200, show(loan));
    }
    if (req.method === 'DELETE') {
      loans.delete(id);
      return send(204);
    }
    return send(405, { error: 'method not allowed' });
  };

  // GraphQL refuses with HTTP 200 and an errors list, as most servers do.
  const graphql = (res: ServerResponse, body: { query?: string; variables?: Record<string, unknown> }, user: string | null) => {
    const send = (json: unknown) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(json));
    };
    const query = body.query ?? '';
    if (query.includes('__schema')) return send({ data: { __schema: SAMPLE_SCHEMA } });
    const field = /\{\s*(\w+)/.exec(query)?.[1] ?? '';
    const vars = body.variables ?? {};
    const id = String(vars.id ?? '');
    const data = (vars.input ?? {}) as Partial<Loan>;
    const entry = log[log.length - 1]!;
    entry.operation = field;
    if (id) entry.id = id;
    const refuse = () => send({ data: { [field]: null }, errors: [{ message: 'not found' }] });
    if (!user) return send({ data: null, errors: [{ message: 'login required' }] });
    if (field === 'loans') return send({ data: { loans: [...loans.values()].filter((l) => l.owner === user).map(show) } });
    if (field === 'createLoan') return send({ data: { createLoan: show(create(user, data)) } });
    const loan = loans.get(id);
    if (field === 'loan') return canReach(loan, user, holes.read) ? send({ data: { loan: show(loan) } }) : refuse();
    if (field === 'updateLoan') {
      if (!canReach(loan, user, holes.update)) return refuse();
      if (data.amount !== undefined) loan.amount = Number(data.amount);
      if (data.note !== undefined) loan.note = String(data.note);
      return send({ data: { updateLoan: show(loan) } });
    }
    if (field === 'deleteLoan') {
      if (!canReach(loan, user, holes.delete)) return send({ data: { deleteLoan: false } });
      loans.delete(id);
      return send({ data: { deleteLoan: true } });
    }
    return refuse();
  };

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const path = new URL(req.url ?? '/', 'http://sample').pathname;
      const user = who(req);
      log.push({ method: req.method ?? 'GET', path, user: user ?? 'anonymous' });
      let body: Record<string, unknown> = {};
      try {
        body = chunks.length ? (JSON.parse(Buffer.concat(chunks).toString()) as Record<string, unknown>) : {};
      } catch {
        /* not JSON: treated as an empty body */
      }
      if (path === '/graphql' && req.method === 'POST') return graphql(res, body, user);
      if (path === '/api/loans' || path.startsWith('/api/loans/')) return rest(req, res, path, body, user);
      res.writeHead(path === '/' ? 200 : 404, { 'content-type': 'text/html' });
      res.end('<html><body><a href="/about">Sample API</a></body></html>');
    });
  });

  const start = (port = 0) =>
    new Promise<string>((resolve) => {
      server.listen(port, '127.0.0.1', () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`));
    });
  const stop = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { start, stop, loans, log };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.argv[2] ?? 3999);
  void sampleApi()
    .start(port)
    .then((url) => console.log(`Sample API on ${url}`));
}
