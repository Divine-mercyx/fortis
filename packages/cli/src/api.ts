import { createPublicKey, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { maskSnippet, type CliFinding, type RulePack } from '@fortis/shared';

import { credentialsPath } from './config';
import { VERSION } from './env';
import type { Detection } from './rules/types';

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

export type WhoAmI = {
  project: { id: string; name: string };
  org: { id: string; name: string };
  plan: { id: string; name: string };
  entitlements: { rulePacks: RulePack[]; uploadFindings: boolean; releaseGates: boolean; blockOn: string; dast?: 'none' | 'baseline' | 'full' };
  rulesVersion: string;
};

export type CliTarget = { id: string; url: string; environment: string; label: string | null; status: string; blocker: string | null };

export function client(api: string, key: string, fetchImpl: typeof fetch = fetch) {
  async function call<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
    let res: Response;
    try {
      res = await fetchImpl(`${api}${path}`, {
        method: init.method ?? 'GET',
        headers: {
          authorization: `Bearer ${key}`,
          'user-agent': `fortis-cli/${VERSION}`,
          ...(init.body ? { 'content-type': 'application/json' } : {}),
        },
        body: init.body ? JSON.stringify(init.body) : undefined,
        signal: AbortSignal.timeout(20_000),
      });
    } catch (e) {
      throw new ApiError(0, 'NETWORK', `Could not reach Fortis at ${api} (${(e as Error).message}).`);
    }
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    if (!res.ok) throw new ApiError(res.status, data?.error?.code ?? 'ERROR', data?.error?.message ?? `Fortis responded ${res.status}`);
    return data as T;
  }

  return {
    whoami: () => call<WhoAmI>('/v1/cli/whoami'),
    targets: (url?: string, mode: 'baseline' | 'full' | 'access' = 'baseline') =>
      call<{ plan: { id: string; dast: string }; targets: CliTarget[] }>(
        `/v1/cli/targets?mode=${mode}${url ? `&url=${encodeURIComponent(url)}` : ''}`,
      ),
    upload: (body: unknown) => call<{ scanId: string; newCount: number; fixedCount: number; reopenedCount: number; duplicate: boolean; dashboardUrl: string }>('/v1/cli/scans', { method: 'POST', body }),
    async rulePacks(): Promise<RulePack[]> {
      const pack = await call<{ keyId: string; payload: string; signature: string }>('/v1/cli/rules');
      const pem = await trustedKey(api, pack.keyId, () => call<{ publicKey: string }>('/v1/cli/rules/public-key').then((r) => r.publicKey));
      const ok = verify(null, Buffer.from(pack.payload), createPublicKey(pem), Buffer.from(pack.signature, 'base64'));
      if (!ok) throw new ApiError(0, 'BAD_SIGNATURE', 'The rule pack signature did not verify. Refusing to use it.');
      const payload = JSON.parse(pack.payload) as { packs: RulePack[]; expiresAt: string };
      if (new Date(payload.expiresAt).getTime() < Date.now()) throw new ApiError(0, 'EXPIRED', 'The rule pack has expired.');
      return payload.packs;
    },
  };
}

/**
 * The rule-pack signing key, pinned on first use per API and key ID (like SSH known_hosts).
 * FORTIS_RULES_PUBLIC_KEY pins it explicitly, which CI should do.
 */
async function trustedKey(api: string, keyId: string, fetchKey: () => Promise<string>): Promise<string> {
  if (process.env.FORTIS_RULES_PUBLIC_KEY) return process.env.FORTIS_RULES_PUBLIC_KEY.replace(/\\n/g, '\n');
  const store = join(dirname(credentialsPath()), 'known-keys.json');
  const known: Record<string, string> = existsSync(store) ? JSON.parse(readFileSync(store, 'utf8')) : {};
  const id = `${api}#${keyId}`;
  if (known[id]) return known[id]!;
  const pem = await fetchKey();
  mkdirSync(dirname(store), { recursive: true, mode: 0o700 });
  writeFileSync(store, `${JSON.stringify({ ...known, [id]: pem }, null, 2)}\n`, { mode: 0o600 });
  return pem;
}

/** What gets uploaded: rule, location and a masked line. Never the file. */
export function toUpload(d: Detection): CliFinding {
  return {
    ruleId: d.ruleId,
    severity: d.severity,
    title: d.title.slice(0, 200),
    file: d.file,
    line: d.line,
    snippet: maskSnippet(d.snippet).slice(0, 300),
  };
}
