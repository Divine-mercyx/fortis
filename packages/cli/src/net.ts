import { readFileSync } from 'node:fs';
import { rootCertificates } from 'node:tls';

import type { Dispatcher } from 'undici';

/*
 * Company and bank networks: Node's built-in fetch ignores HTTPS_PROXY / NO_PROXY, so behind a
 * proxy every OSV and Fortis API call failed. When a proxy or a custom CA is configured, every
 * request in the CLI goes through undici's proxy-aware agent instead (bundled; nothing to install).
 *
 * - HTTPS_PROXY / HTTP_PROXY / NO_PROXY, upper or lower case, as curl reads them.
 * - localhost is never proxied, so access checks and ZAP against a local app keep working.
 * - Extra CA certificates (a proxy that inspects TLS): NODE_EXTRA_CA_CERTS, which Node reads
 *   itself, or --ca <file> / FORTIS_CA_FILE, added to the built-in roots.
 */

type Env = Record<string, string | undefined>;

const LOCAL = ['localhost', '127.0.0.1', '::1'];

const pick = (env: Env, name: string) => env[name] ?? env[name.toLowerCase()];

export type NetworkSetup = { proxy?: string; noProxy?: string; ca?: string; dispatcher: Dispatcher; fetch: typeof fetch };

/**
 * What the environment and flags ask for, ready to use; null when nothing is configured. undici is
 * loaded only here, so a scan without a proxy doesn't pay for it.
 */
export async function networkSetup(env: Env = process.env, caFile?: string): Promise<NetworkSetup | null> {
  const https = pick(env, 'HTTPS_PROXY')?.trim();
  const http = pick(env, 'HTTP_PROXY')?.trim();
  const ca = (caFile ?? env.FORTIS_CA_FILE)?.trim() || undefined;
  if (!https && !http && !ca) return null;
  const noProxy = [...new Set([...(pick(env, 'NO_PROXY') ?? '').split(',').map((s) => s.trim()).filter(Boolean), ...LOCAL])].join(',');
  const tls = ca ? { ca: [...rootCertificates, readFileSync(ca, 'utf8')] } : undefined;
  const { Agent, EnvHttpProxyAgent, fetch: undiciFetch } = await import('undici');
  const dispatcher =
    https || http
      ? quietly(() => new EnvHttpProxyAgent({ httpProxy: http, httpsProxy: https ?? http, noProxy, ...(tls ? { connect: tls, requestTls: tls, proxyTls: tls } : {}) }))
      : new Agent({ connect: tls });
  const proxied = ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) =>
    undiciFetch(input as never, { ...(init as object), dispatcher } as never)) as unknown as typeof fetch;
  return { proxy: https ?? http, noProxy, ca, dispatcher, fetch: proxied };
}

/**
 * Called once at start-up. With a proxy or CA configured, swaps the global fetch for a proxy-aware
 * one, so every caller (OSV, the Fortis API, access checks) picks it up without passing it around.
 * Returns a line for --verbose output, or null when nothing changed.
 */
export async function configureNetwork(env: Env = process.env, caFile?: string): Promise<string | null> {
  const setup = await networkSetup(env, caFile);
  if (!setup) return null;
  globalThis.fetch = setup.fetch;
  const skip = setup.noProxy?.split(',') ?? [];
  const parts = [setup.proxy ? `proxy ${redact(setup.proxy)} (not for ${skip.length > 6 ? `${skip.slice(0, 6).join(',')} and ${skip.length - 6} more` : skip.join(',')})` : '', setup.ca ? `extra CA ${setup.ca}` : ''].filter(Boolean);
  return `Network: ${parts.join(', ')}`;
}

/** undici flags its proxy agent as experimental on stderr; users can't act on that, so it is dropped. */
function quietly<T>(make: () => T): T {
  const emit = process.emitWarning;
  process.emitWarning = ((warning: string | Error, ...rest: unknown[]) => {
    const code = typeof rest[0] === 'object' ? (rest[0] as { code?: string } | null)?.code : rest[1];
    if (code === 'UNDICI-EHPA' || String(warning).includes('EnvHttpProxyAgent is experimental')) return;
    return (emit as (...a: unknown[]) => void).call(process, warning, ...rest);
  }) as typeof process.emitWarning;
  try {
    return make();
  } finally {
    process.emitWarning = emit;
  }
}

/** Proxy URLs can carry a password: http://user:pass@proxy:8080. */
export function redact(url: string): string {
  return url.replace(/\/\/([^:@/]+):[^@/]*@/, '//$1:***@');
}
