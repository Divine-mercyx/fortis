import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { CliFinding } from '@fortis/shared';

/*
 * Access checks with two test users (BOLA / IDOR). For each resource, Fortis finds records that
 * belong to test user A, then asks for each one as test user B and with no login at all. If B or
 * an anonymous request gets A's record back, the API is leaking customer data.
 *
 * Only GET requests are sent. Nothing is created, changed or deleted.
 */

export const ACCESS_CONFIG = '.fortis-access.json';

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
};

export type AccessConfig = {
  target?: string;
  /** Header that carries each user's credential (default Authorization; "Bearer " added if missing). */
  header?: string;
  /** Environment variables holding the two test users' tokens. Never put tokens in this file. */
  users?: { a?: { tokenEnv?: string }; b?: { tokenEnv?: string } };
  checks: AccessCheck[];
};

export type AccessFinding = CliFinding & { evidence: { status: { a: number; b: number; anonymous: number }; id: string } };
export type AccessResult = { findings: AccessFinding[]; checked: number; requests: number; notes: string[] };

type Http = (url: string, headers: Record<string, string>) => Promise<{ status: number; body: string }>;

const defaultHttp: Http = async (url, headers) => {
  const res = await fetch(url, { method: 'GET', headers: { accept: 'application/json', 'user-agent': 'fortis-access', ...headers }, redirect: 'manual', signal: AbortSignal.timeout(15_000) });
  return { status: res.status, body: (await res.text()).slice(0, 200_000) };
};

export function readAccessConfig(root: string, file = ACCESS_CONFIG): AccessConfig | null {
  const p = join(root, file);
  if (!existsSync(p)) return null;
  const cfg = JSON.parse(readFileSync(p, 'utf8')) as AccessConfig;
  if (!Array.isArray(cfg.checks) || !cfg.checks.length) throw new Error(`${file} needs at least one entry in "checks".`);
  for (const c of cfg.checks) {
    if (!c.name || !c.get?.includes('{id}')) throw new Error(`${file}: every check needs a "name" and a "get" path containing {id}.`);
    if (!c.list && !c.ids?.length) throw new Error(`${file}: check "${c.name}" needs a "list" path or "ids" owned by user A.`);
  }
  return cfg;
}

/** Builds checks from an OpenAPI document: GET /things/{param} paired with GET /things. */
export function checksFromOpenApi(spec: { paths?: Record<string, Record<string, unknown>> }): AccessCheck[] {
  const paths = Object.entries(spec.paths ?? {}).filter(([, ops]) => ops && typeof ops === 'object' && 'get' in ops).map(([p]) => p);
  const out: AccessCheck[] = [];
  for (const p of paths) {
    // Django REST ends its paths in a slash: /api/wallets/{id}/ and /api/wallets/.
    const m = /^(.*)\/\{([^}/]+)\}(\/?)$/.exec(p);
    if (!m || m[1]!.includes('{')) continue;
    const slash = m[3]!;
    const list = [`${m[1]!}${slash}`, m[1]!, `${m[1]!}/`].find((candidate) => paths.includes(candidate));
    if (!list) continue;
    const word = m[1]!.split('/').filter(Boolean).pop() ?? 'record';
    const name = word.replace(/[-_]/g, ' ').replace(/s$/, '').replace(/^\w/, (ch) => ch.toUpperCase());
    out.push({ name, list, get: `${m[1]!}/{id}${slash}` });
  }
  return out;
}

export function writeAccessTemplate(root: string, target: string | undefined, checks: AccessCheck[]) {
  const cfg: AccessConfig = {
    target,
    header: 'Authorization',
    users: { a: { tokenEnv: 'FORTIS_USER_A_TOKEN' }, b: { tokenEnv: 'FORTIS_USER_B_TOKEN' } },
    checks: checks.length
      ? checks
      : [
          { name: 'Loan', list: '/api/loans', get: '/api/loans/{id}' },
          { name: 'Wallet', list: '/api/wallets', get: '/api/wallets/{id}' },
          { name: 'Transfer', list: '/api/transfers', get: '/api/transfers/{id}' },
        ],
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

export async function runAccessChecks(
  opts: { origin: string; config: AccessConfig; tokenA: string; tokenB: string; maxRequests?: number; delayMs?: number },
  http: Http = defaultHttp,
): Promise<AccessResult> {
  const header = opts.config.header ?? 'Authorization';
  const cred = (t: string) => (header.toLowerCase() === 'authorization' && !/^(bearer|basic|token)\s/i.test(t) ? `Bearer ${t}` : t);
  const asA = { [header]: cred(opts.tokenA) };
  const asB = { [header]: cred(opts.tokenB) };
  const max = opts.maxRequests ?? 200;
  const delay = opts.delayMs ?? 150;
  let requests = 0;
  const notes: string[] = [];
  const findings: AccessFinding[] = [];

  const call = async (path: string, headers: Record<string, string>) => {
    if (requests >= max) throw new Error(`Stopped after ${max} requests (the safety limit).`);
    requests++;
    if (delay) await new Promise((r) => setTimeout(r, delay));
    try {
      return await http(join2(opts.origin, path), headers);
    } catch (e) {
      return { status: 0, body: String((e as Error).message) };
    }
  };

  let checked = 0;
  for (const check of opts.config.checks) {
    let ids = check.ids?.map(String) ?? [];
    if (!ids.length && check.list) {
      const list = await call(check.list, asA);
      if (!ok(list.status)) {
        notes.push(`${check.name}: GET ${check.list} as user A returned ${list.status || 'no response'}, so it was skipped.`);
        continue;
      }
      ids = extractIds(list.body, check.idField ?? 'id');
      if (!ids.length) {
        notes.push(`${check.name}: user A has no ${check.name.toLowerCase()} records to test with. Create one for user A on staging.`);
        continue;
      }
    }
    for (const id of ids) {
      const path = check.get.replace('{id}', encodeURIComponent(id));
      const a = await call(path, asA);
      if (!ok(a.status)) {
        notes.push(`${check.name} ${id}: user A can't read it either (${a.status}), so it isn't A's record. Skipped.`);
        continue;
      }
      checked++;
      const b = await call(path, asB);
      const anon = await call(path, {});
      const evidence = { status: { a: a.status, b: b.status, anonymous: anon.status }, id };
      const where = `GET ${check.get}`;
      if (ok(anon.status) && sameRecord(a.body, anon.body, id)) {
        findings.push({
          ruleId: 'FX-AUTH-001', severity: 'critical', title: `${check.name} records readable without logging in`, file: where,
          snippet: `anonymous GET ${check.get.replace('{id}', '<A’s id>')} → ${anon.status}`,
          detail: `A request with no credentials got user A's ${check.name.toLowerCase()} (HTTP ${anon.status}). User A: ${a.status}, user B: ${b.status}, anonymous: ${anon.status}.\n\nFix: put this route behind authentication and scope the lookup to the signed-in customer.`,
          fingerprint: `access:auth:${check.get}`, evidence,
        });
        break;
      }
      if (ok(b.status) && sameRecord(a.body, b.body, id)) {
        findings.push({
          ruleId: 'FX-BOLA-001', severity: 'critical', title: `User B can read user A's ${check.name.toLowerCase()}`, file: where,
          snippet: `user B GET ${check.get.replace('{id}', '<A’s id>')} → ${b.status}`,
          detail: `Test user B requested a ${check.name.toLowerCase()} that belongs to test user A and got it back (HTTP ${b.status}). User A: ${a.status}, user B: ${b.status}, anonymous: ${anon.status}.\n\nFix: load the record with the signed-in customer's ID in the query (WHERE id = $1 AND customer_id = $2) and return 404 when it isn't theirs.`,
          fingerprint: `access:bola:${check.get}`, evidence,
        });
        break;
      }
    }
  }
  return { findings, checked, requests, notes };
}
