import type { NextRequest } from 'next/server';

/*
 * Same-origin proxy to the Fortis API. The browser calls /api/... on the dashboard, so the
 * session cookie stays first-party. API_URL is read at request time (not baked in at build).
 */
export const dynamic = 'force-dynamic';

const FORWARD_REQUEST = ['content-type', 'cookie', 'origin', 'user-agent', 'accept', 'authorization'];
const FORWARD_RESPONSE = ['content-type', 'cache-control', 'retry-after', 'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset'];

function apiBase(): string | null {
  const raw = process.env.API_URL?.trim();
  return raw ? raw.replace(/\/+$/, '') : null;
}

const json = (status: number, code: string, message: string) =>
  Response.json({ error: { code, message } }, { status });

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const base = apiBase();
  if (!base) return json(500, 'API_URL_MISSING', 'The dashboard is not connected to the Fortis API. Set API_URL on the dashboard service.');

  const { path } = await ctx.params;
  const target = `${base}/${path.map(encodeURIComponent).join('/')}${req.nextUrl.search}`;

  const headers = new Headers();
  for (const h of FORWARD_REQUEST) {
    const v = req.headers.get(h);
    if (v) headers.set(h, v);
  }
  const fwd = req.headers.get('x-forwarded-for');
  if (fwd) headers.set('x-forwarded-for', fwd);

  let res: Response;
  try {
    res = await fetch(target, {
      method: req.method,
      headers,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : await req.arrayBuffer(),
      redirect: 'manual',
      cache: 'no-store',
      signal: AbortSignal.timeout(75_000),
    });
  } catch {
    return json(502, 'API_UNREACHABLE', 'Fortis could not reach its API. If it was asleep it may be waking up; try again in a minute.');
  }

  const type = res.headers.get('content-type') ?? '';
  if (!type.includes('application/json') && res.status >= 400) {
    return json(502, 'API_UNAVAILABLE', `The Fortis API is not responding properly (status ${res.status}). It may be starting up; try again in a minute.`);
  }

  const out = new Headers();
  for (const h of FORWARD_RESPONSE) {
    const v = res.headers.get(h);
    if (v) out.set(h, v);
  }
  for (const c of res.headers.getSetCookie()) out.append('set-cookie', c);
  return new Response(res.body, { status: res.status, headers: out });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
