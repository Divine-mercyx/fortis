import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { CliFinding } from '@fortis/shared';

export { checksFromOpenApi } from './access-import';

/*
 * Access checks with two test users (BOLA / IDOR). For each resource, Fortis finds records that
 * belong to test user A, then asks for each one as test user B and with no login at all. If B or
 * an anonymous request gets A's record back, the API is leaking customer data.
 *
 * By default this is read-only: REST checks send GET, GraphQL checks send queries, and nothing is
 * created, changed or deleted. `fortis access --writes` also checks updates and deletes, but only
 * on throwaway records that user A creates during the run, never on A's existing records.
 */

export const ACCESS_CONFIG = '.fortis-access.json';

/** An update sent as user B. `path` defaults to the check's `get` path; "{id}" in `body` becomes the record's ID. */
export type WriteStep = { path?: string; body?: unknown };

/** Used only with --writes. */
export type AccessWrites = {
  /** Creates one throwaway record as user A. */
  create: { path: string; body?: unknown; idField?: string };
  put?: WriteStep;
  patch?: WriteStep;
  delete?: { path?: string };
  /** Path user A deletes the record with afterwards. Defaults to the `delete` path. */
  cleanup?: string;
};

export type AccessCheck = {
  /** Shown in findings, e.g. "Loan". */
  name: string;
  /** Path to read one record, with {id} where the ID goes: /api/loans/{id} */
  get: string;
  /** Optional list path that returns user A's records; IDs are taken from it. */
  list?: string;
  /** Field holding the record ID in list responses (default: id). */
  idField?: string;
  /** Or: record IDs known to belong to user A. */
  ids?: string[];
  writes?: AccessWrites;
};

/** A GraphQL mutation sent with --writes. "{id}" in `variables` becomes the record's ID. */
export type GraphqlMutation = { mutation: string; variables?: Record<string, unknown> };

export type GraphqlCheck = {
  name: string;
  /** Query that reads one record, taking the ID as a variable. */
  read: string;
  /** The variable holding the ID (default: id). */
  idArg?: string;
  /** Query that returns user A's records. */
  list?: string;
  idField?: string;
  ids?: string[];
  writes?: {
    create: GraphqlMutation & { idField?: string };
    update?: GraphqlMutation;
    delete?: GraphqlMutation;
    /** Mutation user A deletes the record with afterwards. Defaults to `delete`. */
    cleanup?: GraphqlMutation;
  };
};

export type AccessConfig = {
  target?: string;
  /** Header that carries each user's credential (default Authorization; "Bearer " added if missing). */
  header?: string;
  /** Environment variables holding the two test users' tokens. Never put tokens in this file. */
  users?: { a?: { tokenEnv?: string }; b?: { tokenEnv?: string } };
  checks: AccessCheck[];
  graphql?: { path: string; checks: GraphqlCheck[] };
};

export type AccessFinding = CliFinding & { evidence: { status: { a: number; b: number; anonymous?: number }; id: string } };
export type AccessResult = {
  findings: AccessFinding[];
  checked: number;
  requests: number;
  notes: string[];
  /** Throwaway records tested with --writes. */
  writesChecked: number;
  /** A write check couldn't finish, so "no finding" doesn't mean "fixed". */
  writesIncomplete: boolean;
};

type HttpInit = { method: string; body?: string };
type Http = (url: string, headers: Record<string, string>, init?: HttpInit) => Promise<{ status: number; body: string }>;

const defaultHttp: Http = async (url, headers, init) => {
  const res = await fetch(url, {
    method: init?.method ?? 'GET',
    headers: { accept: 'application/json', 'user-agent': 'fortis-access', ...(init?.body === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
    body: init?.body,
    redirect: 'manual',
    signal: AbortSignal.timeout(15_000),
  });
  return { status: res.status, body: (await res.text()).slice(0, 200_000) };
};

const withoutComments = (doc: string) => doc.replace(/#.*$/gm, '');
/** A read check must never be able to change anything, because it also runs in the default mode. */
const isReadOnlyGraphql = (doc: string) => !/\b(mutation|subscription)\b/i.test(withoutComments(doc));
const isMutation = (doc: string) => /^\s*mutation\b/i.test(withoutComments(doc));

function validateWrites(file: string, c: AccessCheck) {
  const w = c.writes;
  if (!w) return;
  if (!w.create?.path) throw new Error(`${file}: check "${c.name}": "writes" needs a "create" with a "path", because only throwaway records are written to.`);
  if (!w.put && !w.patch && !w.delete) throw new Error(`${file}: check "${c.name}": "writes" needs at least one of "put", "patch" or "delete".`);
  for (const path of [w.put?.path, w.patch?.path, w.delete?.path, w.cleanup]) {
    if (path !== undefined && !path.includes('{id}')) throw new Error(`${file}: check "${c.name}": write path "${path}" must contain {id}.`);
  }
}

function validateGraphql(file: string, c: GraphqlCheck) {
  if (!c.name || !c.read) throw new Error(`${file}: every GraphQL check needs a "name" and a "read" query.`);
  if (!c.list && !c.ids?.length) throw new Error(`${file}: GraphQL check "${c.name}" needs a "list" query or "ids" owned by user A.`);
  for (const doc of [c.read, c.list]) {
    if (doc && !isReadOnlyGraphql(doc)) throw new Error(`${file}: GraphQL check "${c.name}": "read" and "list" must be queries. Mutations belong under "writes".`);
  }
  const w = c.writes;
  if (!w) return;
  if (!w.create?.mutation) throw new Error(`${file}: GraphQL check "${c.name}": "writes" needs a "create" mutation, because only throwaway records are written to.`);
  if (!w.update && !w.delete) throw new Error(`${file}: GraphQL check "${c.name}": "writes" needs an "update" or "delete" mutation.`);
  for (const m of [w.create, w.update, w.delete, w.cleanup]) {
    if (m && !isMutation(m.mutation)) throw new Error(`${file}: GraphQL check "${c.name}": everything under "writes" must be a mutation.`);
  }
}

export function readAccessConfig(root: string, file = ACCESS_CONFIG): AccessConfig | null {
  const p = join(root, file);
  if (!existsSync(p)) return null;
  const cfg = JSON.parse(readFileSync(p, 'utf8').replace(/^﻿/, '')) as AccessConfig;
  const graphql = cfg.graphql?.checks ?? [];
  if (cfg.checks === undefined && graphql.length) cfg.checks = [];
  if (!Array.isArray(cfg.checks) || (!cfg.checks.length && !graphql.length)) throw new Error(`${file} needs at least one entry in "checks".`);
  for (const c of cfg.checks) {
    if (!c.name || !c.get?.includes('{id}')) throw new Error(`${file}: every check needs a "name" and a "get" path containing {id}.`);
    if (!c.list && !c.ids?.length) throw new Error(`${file}: check "${c.name}" needs a "list" path or "ids" owned by user A.`);
    validateWrites(file, c);
  }
  if (graphql.length && !cfg.graphql?.path) throw new Error(`${file}: "graphql" needs a "path", for example /graphql.`);
  for (const c of graphql) validateGraphql(file, c);
  return cfg;
}

/** True when --writes has something to test. */
export const hasWriteChecks = (cfg: AccessConfig) => cfg.checks.some((c) => c.writes) || Boolean(cfg.graphql?.checks.some((c) => c.writes));

export function writeAccessTemplate(root: string, target: string | undefined, checks: AccessCheck[], graphql?: AccessConfig['graphql']) {
  const cfg: AccessConfig = {
    target,
    header: 'Authorization',
    users: { a: { tokenEnv: 'FORTIS_USER_A_TOKEN' }, b: { tokenEnv: 'FORTIS_USER_B_TOKEN' } },
    checks: checks.length || graphql
      ? checks
      : [
          { name: 'Loan', list: '/api/loans', get: '/api/loans/{id}' },
          { name: 'Wallet', list: '/api/wallets', get: '/api/wallets/{id}' },
          { name: 'Transfer', list: '/api/transfers', get: '/api/transfers/{id}' },
        ],
    ...(graphql ? { graphql } : {}),
  };
  writeFileSync(join(root, ACCESS_CONFIG), `${JSON.stringify(cfg, null, 2)}\n`);
}

/** The first array of objects in a list response: the root, or data / items / results / any key. */
export function extractIds(body: string, idField = 'id', max = 3): string[] {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return [];
  }
  const arrays: unknown[][] = [];
  const visit = (v: unknown, depth: number) => {
    if (depth > 3 || !v) return;
    if (Array.isArray(v)) {
      if (v.some((x) => x && typeof x === 'object')) arrays.push(v);
      return;
    }
    if (typeof v === 'object') for (const x of Object.values(v as Record<string, unknown>)) visit(x, depth + 1);
  };
  visit(json, 0);
  for (const arr of arrays) {
    const ids = arr
      .map((x) => (x && typeof x === 'object' ? (x as Record<string, unknown>)[idField] : undefined))
      .filter((x): x is string | number => typeof x === 'string' || typeof x === 'number')
      .map(String);
    if (ids.length) return [...new Set(ids)].slice(0, max);
  }
  return [];
}

const ok = (s: number) => s >= 200 && s < 300;
const join2 = (origin: string, path: string) => `${origin}${path.startsWith('/') ? '' : '/'}${path}`;

/** True when B's (or the anonymous) response is the same record A sees, not an error page or an empty shell. */
function sameRecord(a: string, other: string, id: string): boolean {
  if (!other.trim()) return false;
  if (other === a) return true;
  try {
    const o = JSON.parse(other) as unknown;
    const s = JSON.stringify(o);
    // An error body that merely echoes the ID back ("loan 123 not found") is not a leak.
    if (/"(error|errors|message|detail)"\s*:/i.test(s) && s.length < 400) return false;
    return s.includes(`"${id}"`) || s.includes(`:${id},`) || s.includes(`:${id}}`);
  } catch {
    return false;
  }
}

/** Replaces "{id}" in every string of a request body. */
function fill<T>(value: T, id: string): T {
  if (typeof value === 'string') return value.split('{id}').join(id) as T;
  if (Array.isArray(value)) return value.map((v) => fill(v as unknown, id)) as T;
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, fill(v as unknown, id)])) as T;
  return value;
}

/** The ID of a record just created: the field itself, or inside a wrapper such as data.createLoan. */
export function createdId(body: string, idField = 'id'): string | undefined {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return undefined;
  }
  const queue: { v: unknown; depth: number }[] = [{ v: json, depth: 0 }];
  while (queue.length) {
    const { v, depth } = queue.shift()!;
    if (!v || typeof v !== 'object' || depth > 4) continue;
    const id = (v as Record<string, unknown>)[idField];
    if (typeof id === 'string' || typeof id === 'number') return String(id);
    for (const x of Object.values(v as Record<string, unknown>)) queue.push({ v: x, depth: depth + 1 });
  }
  return undefined;
}

/** GraphQL answers 200 even when it refuses, so success means no errors and data in every root field. */
export function graphqlSucceeded(res: { status: number; body: string }): boolean {
  if (!ok(res.status)) return false;
  try {
    const json = JSON.parse(res.body) as { data?: Record<string, unknown> | null; errors?: unknown[] };
    if (json.errors?.length || !json.data) return false;
    const values = Object.values(json.data);
    return values.length > 0 && values.every((v) => v !== null && v !== undefined && v !== false);
  } catch {
    return false;
  }
}

type Req = { method: string; path: string; body?: string };
type Res = { status: number; body: string };
type Attack = { verb: 'update' | 'delete'; label: string; request: (id: string) => Req };
type ResourceWrites = { create: Req; idField: string; attacks: Attack[]; cleanup?: (id: string) => Req };

/** One REST or GraphQL resource, so both follow the same steps and the same rules. */
type Resource = {
  name: string;
  /** How findings name the read, e.g. "GET /api/loans/{id}". */
  where: string;
  /** Keeps a finding's identity stable across runs. */
  key: string;
  list?: Req;
  listLabel?: string;
  idField: string;
  ids: string[];
  read: (id: string) => Req;
  succeeded: (res: Res) => boolean;
  /** How a finding shows the read without the real ID. */
  readSnippet: string;
  writes?: ResourceWrites;
};

function restResource(check: AccessCheck): Resource {
  const w = check.writes;
  const at = (path: string, id: string) => path.replace('{id}', encodeURIComponent(id));
  const update = (method: 'PUT' | 'PATCH', step: WriteStep | undefined): Attack[] => {
    if (!step) return [];
    const path = step.path ?? check.get;
    return [{ verb: 'update', label: `${method} ${path}`, request: (id) => ({ method, path: at(path, id), body: JSON.stringify(fill(step.body ?? {}, id)) }) }];
  };
  const deletePath = w?.delete ? (w.delete.path ?? check.get) : undefined;
  const cleanupPath = w?.cleanup ?? deletePath;
  return {
    name: check.name,
    where: `GET ${check.get}`,
    key: check.get,
    list: check.list ? { method: 'GET', path: check.list } : undefined,
    listLabel: check.list ? `GET ${check.list}` : undefined,
    idField: check.idField ?? 'id',
    ids: check.ids?.map(String) ?? [],
    read: (id) => ({ method: 'GET', path: at(check.get, id) }),
    succeeded: (res) => ok(res.status),
    readSnippet: `GET ${check.get.replace('{id}', '<A’s id>')}`,
    writes: w && {
      create: { method: 'POST', path: w.create.path, body: JSON.stringify(w.create.body ?? {}) },
      idField: w.create.idField ?? check.idField ?? 'id',
      attacks: [
        ...update('PUT', w.put),
        ...update('PATCH', w.patch),
        ...(deletePath ? [{ verb: 'delete' as const, label: `DELETE ${deletePath}`, request: (id: string) => ({ method: 'DELETE', path: at(deletePath, id) }) }] : []),
      ],
      cleanup: cleanupPath ? (id) => ({ method: 'DELETE', path: at(cleanupPath, id) }) : undefined,
    },
  };
}

/** The operation's first field: what a finding is called, e.g. "updateLoan". */
const rootField = (doc: string) => /\{\s*(?:\w+\s*:\s*)?(\w+)/.exec(doc)?.[1] ?? 'operation';

function graphqlResource(path: string, check: GraphqlCheck): Resource {
  const idArg = check.idArg ?? 'id';
  const post = (query: string, variables?: Record<string, unknown>): Req => ({ method: 'POST', path, body: JSON.stringify({ query, ...(variables ? { variables } : {}) }) });
  // A variable declared Int must be sent as a number.
  const idValue = (doc: string, id: string): string | number => (new RegExp(`\\$${idArg}\\s*:\\s*Int\\b`).test(doc) && /^\d+$/.test(id) ? Number(id) : id);
  const mutate = (m: GraphqlMutation, id: string) => post(m.mutation, { [idArg]: idValue(m.mutation, id), ...fill(m.variables ?? {}, id) });
  const w = check.writes;
  const attacks: Attack[] = [];
  if (w?.update) attacks.push({ verb: 'update', label: `GraphQL ${rootField(w.update.mutation)}`, request: (id) => mutate(w.update!, id) });
  if (w?.delete) attacks.push({ verb: 'delete', label: `GraphQL ${rootField(w.delete.mutation)}`, request: (id) => mutate(w.delete!, id) });
  const cleanup = w?.cleanup ?? w?.delete;
  const field = rootField(check.read);
  return {
    name: check.name,
    where: `GraphQL ${field}`,
    key: `graphql:${field}`,
    list: check.list ? post(check.list) : undefined,
    listLabel: check.list ? `GraphQL ${rootField(check.list)}` : undefined,
    idField: check.idField ?? 'id',
    ids: check.ids?.map(String) ?? [],
    read: (id) => post(check.read, { [idArg]: idValue(check.read, id) }),
    succeeded: graphqlSucceeded,
    readSnippet: `GraphQL ${field}(<A’s id>)`,
    writes: w && {
      create: post(w.create.mutation, w.create.variables),
      idField: w.create.idField ?? check.idField ?? 'id',
      attacks,
      cleanup: cleanup ? (id) => mutate(cleanup, id) : undefined,
    },
  };
}

function writeFinding(res: Resource, attack: Attack, status: number, evidence: AccessFinding['evidence']): AccessFinding {
  const lower = res.name.toLowerCase();
  const did = attack.verb === 'update' ? 'changed' : 'deleted';
  return {
    ruleId: 'FX-BOLA-002', severity: 'critical', title: `User B can ${attack.verb} user A's ${lower}`, file: attack.label,
    snippet: `user B ${attack.label.replace('{id}', '<A’s id>')} → ${status}`,
    detail: `Test user B sent ${attack.label} for a throwaway ${lower} that belongs to test user A (HTTP ${status}), and user A's copy was ${did}.\n\nFix: check that the record belongs to the signed-in customer before writing (UPDATE … WHERE id = $1 AND customer_id = $2) and return 404 when it isn't theirs.`,
    fingerprint: `access:bola-write:${attack.label}`, evidence,
  };
}

export async function runAccessChecks(
  opts: { origin: string; config: AccessConfig; tokenA: string; tokenB: string; maxRequests?: number; delayMs?: number; writes?: boolean },
  http: Http = defaultHttp,
): Promise<AccessResult> {
  const header = opts.config.header ?? 'Authorization';
  const cred = (t: string) => (header.toLowerCase() === 'authorization' && !/^(bearer|basic|token)\s/i.test(t) ? `Bearer ${t}` : t);
  const asA = { [header]: cred(opts.tokenA) };
  const asB = { [header]: cred(opts.tokenB) };
  const max = opts.maxRequests ?? 200;
  const delay = opts.delayMs ?? 150;
  let requests = 0;
  let writesChecked = 0;
  let writesIncomplete = false;
  const notes: string[] = [];
  const findings: AccessFinding[] = [];

  const send = async (req: Req, headers: Record<string, string>): Promise<Res> => {
    requests++;
    if (delay) await new Promise((r) => setTimeout(r, delay));
    try {
      const url = join2(opts.origin, req.path);
      return await (req.method === 'GET' ? http(url, headers) : http(url, headers, { method: req.method, body: req.body }));
    } catch (e) {
      return { status: 0, body: String((e as Error).message) };
    }
  };
  const call = (req: Req, headers: Record<string, string>) => {
    if (requests >= max) throw new Error(`Stopped after ${max} requests (the safety limit).`);
    return send(req, headers);
  };

  /** Tests one throwaway record that user A creates here. Returns false when the check couldn't finish. */
  const checkWrites = async (res: Resource, w: ResourceWrites): Promise<boolean> => {
    const created = await call(w.create, asA);
    if (!res.succeeded(created)) {
      notes.push(`${res.name}: user A couldn't create a throwaway record (${created.status || 'no response'}), so writes weren't tested. Check "create" in the config.`);
      return false;
    }
    const id = createdId(created.body, w.idField);
    if (!id) {
      notes.push(`${res.name}: the create response has no "${w.idField}", so writes weren't tested, and a throwaway record may be left on staging. Set "idField" under "create".`);
      return false;
    }
    let gone = false;
    let finished = true;
    try {
      let before = await call(res.read(id), asA);
      if (!res.succeeded(before)) {
        notes.push(`${res.name} ${id}: user A can't read the record they just created (${before.status || 'no response'}), so writes weren't tested.`);
        return false;
      }
      writesChecked++;
      for (const attack of w.attacks) {
        const b = await call(attack.request(id), asB);
        const after = await call(res.read(id), asA);
        const evidence = { status: { a: after.status, b: b.status }, id };
        // A server error or a dropped connection isn't evidence of anything.
        if (after.status === 0 || after.status >= 500) {
          notes.push(`${res.name}: user A couldn't read the record after ${attack.label} (${after.status || 'no response'}), so that check is unconfirmed.`);
          finished = false;
          continue;
        }
        if (attack.verb === 'delete') {
          gone = !res.succeeded(after);
          if (res.succeeded(b) && gone) findings.push(writeFinding(res, attack, b.status, evidence));
          else if (res.succeeded(b)) notes.push(`${res.name}: ${attack.label} as user B returned ${b.status}, but user A can still read the record. Check whether this is a soft delete.`);
          continue;
        }
        if (!res.succeeded(after)) {
          notes.push(`${res.name}: user A couldn't read the record after ${attack.label} (${after.status}), so that check is unconfirmed.`);
          finished = false;
          continue;
        }
        if (res.succeeded(b) && after.body !== before.body) findings.push(writeFinding(res, attack, b.status, evidence));
        else if (res.succeeded(b)) notes.push(`${res.name}: ${attack.label} as user B returned ${b.status}, but the record didn't change. If that body can't change a record, edit it in the config.`);
        before = after;
      }
    } finally {
      if (!gone) {
        // Runs even at the safety limit, so a stopped run still tidies up its own record.
        const removed = w.cleanup ? await send(w.cleanup(id), asA) : null;
        if (!removed) notes.push(`${res.name} ${id}: this throwaway record is still on staging. Add a "delete" or "cleanup" to the config to remove it automatically.`);
        else if (!res.succeeded(removed)) notes.push(`${res.name} ${id}: user A couldn't delete this throwaway record (${removed.status || 'no response'}). Remove it by hand.`);
      }
    }
    return finished;
  };

  const graphql = opts.config.graphql;
  const resources = [...opts.config.checks.map(restResource), ...(graphql?.checks ?? []).map((c) => graphqlResource(graphql!.path, c))];

  let checked = 0;
  for (const res of resources) {
    let ids = res.ids;
    if (!ids.length && res.list) {
      const list = await call(res.list, asA);
      if (!res.succeeded(list)) {
        notes.push(`${res.name}: ${res.listLabel} as user A returned ${list.status || 'no response'}, so it was skipped.`);
        continue;
      }
      ids = extractIds(list.body, res.idField);
      if (!ids.length) {
        notes.push(`${res.name}: user A has no ${res.name.toLowerCase()} records to test with. Create one for user A on staging.`);
        continue;
      }
    }
    for (const id of ids) {
      const req = res.read(id);
      const a = await call(req, asA);
      if (!res.succeeded(a)) {
        notes.push(`${res.name} ${id}: user A can't read it either (${a.status}), so it isn't A's record. Skipped.`);
        continue;
      }
      checked++;
      const b = await call(req, asB);
      const anon = await call(req, {});
      const evidence = { status: { a: a.status, b: b.status, anonymous: anon.status }, id };
      if (res.succeeded(anon) && sameRecord(a.body, anon.body, id)) {
        findings.push({
          ruleId: 'FX-AUTH-001', severity: 'critical', title: `${res.name} records readable without logging in`, file: res.where,
          snippet: `anonymous ${res.readSnippet} → ${anon.status}`,
          detail: `A request with no credentials got user A's ${res.name.toLowerCase()} (HTTP ${anon.status}). User A: ${a.status}, user B: ${b.status}, anonymous: ${anon.status}.\n\nFix: put this route behind authentication and scope the lookup to the signed-in customer.`,
          fingerprint: `access:auth:${res.key}`, evidence,
        });
        break;
      }
      if (res.succeeded(b) && sameRecord(a.body, b.body, id)) {
        findings.push({
          ruleId: 'FX-BOLA-001', severity: 'critical', title: `User B can read user A's ${res.name.toLowerCase()}`, file: res.where,
          snippet: `user B ${res.readSnippet} → ${b.status}`,
          detail: `Test user B requested a ${res.name.toLowerCase()} that belongs to test user A and got it back (HTTP ${b.status}). User A: ${a.status}, user B: ${b.status}, anonymous: ${anon.status}.\n\nFix: load the record with the signed-in customer's ID in the query (WHERE id = $1 AND customer_id = $2) and return 404 when it isn't theirs.`,
          fingerprint: `access:bola:${res.key}`, evidence,
        });
        break;
      }
    }
  }

  // Everything above is read-only. Nothing below runs without --writes.
  if (opts.writes) {
    for (const res of resources) {
      if (res.writes && !(await checkWrites(res, res.writes))) writesIncomplete = true;
    }
  }
  return { findings, checked, requests, notes, writesChecked, writesIncomplete };
}
