import type { AccessCheck, AccessWrites } from './access';

/*
 * Builds access checks from a list of routes, read from an OpenAPI spec, a Postman collection or a
 * HAR file. Only the method and path are kept. Postman and HAR files can hold real tokens, customer
 * data and record IDs, so headers, bodies and query strings are never copied into the config.
 */

export type Route = { method: string; path: string };

const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

/** Pairs GET /things/{param} with GET /things, and adds a "writes" block when those routes exist too. */
export function checksFromRoutes(routes: Route[]): AccessCheck[] {
  const has = (method: string, path: string) => routes.some((r) => r.method === method && r.path === path);
  const gets = [...new Set(routes.filter((r) => r.method === 'GET').map((r) => r.path))];
  const out: AccessCheck[] = [];
  for (const p of gets) {
    // Django REST ends its paths in a slash: /api/wallets/{id}/ and /api/wallets/.
    const m = /^(.*)\/\{([^}/]+)\}(\/?)$/.exec(p);
    if (!m || m[1]!.includes('{')) continue;
    const slash = m[3]!;
    const candidates = [`${m[1]!}${slash}`, m[1]!, `${m[1]!}/`];
    const list = candidates.find((candidate) => gets.includes(candidate));
    if (!list) continue;
    const word = m[1]!.split('/').filter(Boolean).pop() ?? 'record';
    const name = word.replace(/[-_]/g, ' ').replace(/s$/, '').replace(/^\w/, (ch) => ch.toUpperCase());
    const check: AccessCheck = { name, list, get: `${m[1]!}/{id}${slash}` };
    const createPath = candidates.find((candidate) => has('POST', candidate));
    const writes: Partial<AccessWrites> = {};
    if (has('PUT', p)) writes.put = { body: {} };
    if (has('PATCH', p)) writes.patch = { body: {} };
    if (has('DELETE', p)) writes.delete = {};
    if (createPath && Object.keys(writes).length) check.writes = { create: { path: createPath, body: {} }, ...writes };
    if (!out.some((c) => c.get === check.get)) out.push(check);
  }
  return out;
}

export function routesFromOpenApi(spec: { paths?: Record<string, Record<string, unknown>> }): Route[] {
  const out: Route[] = [];
  for (const [path, ops] of Object.entries(spec.paths ?? {})) {
    if (!ops || typeof ops !== 'object') continue;
    for (const method of ['GET', ...WRITE_METHODS]) if (method.toLowerCase() in ops) out.push({ method, path });
  }
  return out;
}

export function checksFromOpenApi(spec: { paths?: Record<string, Record<string, unknown>> }): AccessCheck[] {
  return checksFromRoutes(routesFromOpenApi(spec));
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
/** A path segment that looks like a record's ID: 123, a UUID, a long hex or ULID, or trf_01J9ZQ3. */
export const looksLikeId = (segment: string) =>
  /^\d+$/.test(segment) || UUID.test(segment) || ULID.test(segment) || /^[0-9a-f]{16,}$/i.test(segment) || (/^[a-z]+[_-][A-Za-z0-9]{6,}$/.test(segment) && /\d/.test(segment));

/** Replaces real IDs and Postman variables with {id}, so nothing specific reaches the config. */
function normalisePath(segments: string[], trailingSlash: boolean): string {
  const parts = segments.map((s) => (/^:\w+$/.test(s) || /^\{\{.+\}\}$/.test(s) || /^\{[^}]+\}$/.test(s) || looksLikeId(s) ? '{id}' : s));
  return `/${parts.join('/')}${trailingSlash && parts.length ? '/' : ''}`;
}

const STATIC_FILE = /\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|html?)$/i;

function fromPathname(pathname: string): string {
  const segments = pathname.split('/').filter(Boolean);
  return normalisePath(segments, pathname.length > 1 && pathname.endsWith('/'));
}

type PostmanUrl = string | { raw?: string; path?: string | string[] };
type PostmanItem = { item?: PostmanItem[]; request?: string | { method?: string; url?: PostmanUrl } };

function postmanPath(url: PostmanUrl | undefined): string | null {
  if (!url) return null;
  if (typeof url === 'object' && Array.isArray(url.path)) {
    const raw = url.raw ?? '';
    return normalisePath(url.path.filter(Boolean), /\/(\?.*)?$/.test(raw));
  }
  const raw = (typeof url === 'string' ? url : (url.raw ?? '')).split(/[?#]/)[0]!;
  // {{baseUrl}}/api/loans or https://host/api/loans.
  const withoutHost = raw.replace(/^\{\{[^}]+\}\}/, '').replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '');
  return withoutHost.startsWith('/') ? fromPathname(withoutHost) : null;
}

export function routesFromPostman(collection: { item?: PostmanItem[] }): Route[] {
  if (!Array.isArray(collection?.item)) throw new Error('This is not a Postman collection: it has no "item" list.');
  const out: Route[] = [];
  const walk = (items: PostmanItem[]) => {
    for (const item of items) {
      if (Array.isArray(item.item)) walk(item.item);
      if (!item.request) continue;
      const request = typeof item.request === 'string' ? { method: 'GET', url: item.request } : item.request;
      const path = postmanPath(request.url);
      if (path) out.push({ method: (request.method ?? 'GET').toUpperCase(), path });
    }
  };
  walk(collection.item);
  return out;
}

type HarFile = { log?: { entries?: { request?: { method?: string; url?: string } }[] } };

/** A HAR file records every host a page talked to, so keep only the target (or the busiest host). */
export function routesFromHar(har: HarFile, origin?: string): Route[] {
  const entries = har?.log?.entries;
  if (!Array.isArray(entries)) throw new Error('This is not a HAR file: it has no "log.entries" list.');
  const urls: { method: string; url: URL }[] = [];
  for (const entry of entries) {
    try {
      const url = new URL(entry.request?.url ?? '');
      if (/^https?:$/.test(url.protocol)) urls.push({ method: (entry.request?.method ?? 'GET').toUpperCase(), url });
    } catch {
      /* not a usable URL */
    }
  }
  let keep = origin;
  if (!keep) {
    const counts = new Map<string, number>();
    for (const { url } of urls) counts.set(url.origin, (counts.get(url.origin) ?? 0) + 1);
    keep = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  }
  return urls
    .filter(({ url }) => url.origin === keep && !STATIC_FILE.test(url.pathname))
    .map(({ method, url }) => ({ method, path: fromPathname(url.pathname) }));
}
