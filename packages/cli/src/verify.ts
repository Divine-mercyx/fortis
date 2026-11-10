import { skProvider } from './rules/secrets';
import type { Detection } from './rules/types';

/*
 * `fortis scan --verify`: is a leaked key still live? One read-only API call per key, to the
 * provider that issued it, labels each secret finding live, revoked or unknown, so you know what
 * to rotate first. Off by default: it is the one check that sends a secret anywhere.
 *
 * - A key only ever goes to its own provider's API host, over HTTPS. Each provider below names its
 *   hosts, and a request to any other host is refused before it is made. A key whose provider
 *   can't be told apart from its shape (a bare sk_live_ that could be Stripe or Paystack) isn't sent.
 * - Every call reads: account, balance, or "who am I". None creates, changes, sends or charges anything.
 * - Each distinct key is checked once per scan, at most MAX_CHECKS keys, CONCURRENCY at a time,
 *   with MIN_GAP_MS between calls to the same provider and TIMEOUT_MS per call.
 * - Anything other than a clear yes or no (timeout, rate limit, provider error) is "unknown".
 */

export type SecretStatus = 'live' | 'revoked' | 'unknown';

type Answer = { status: number; json: () => Promise<unknown> };
type Request = { url: string; method?: 'GET' | 'POST'; headers?: Record<string, string> };

export type Provider = {
  id: string;
  name: string;
  /** The key, out of the finding's line. */
  match: RegExp;
  /** Only these hosts ever receive the key. */
  hosts: string[];
  /** For keys whose prefix is shared with another provider: whether this one is clearly the issuer. */
  owns?: (key: string) => boolean;
  /** The calls to make, in order; the first that gives a clear answer wins. */
  requests: (key: string) => Request[];
  /** What the provider's answer means. */
  read: (res: Answer, req: Request) => Promise<SecretStatus> | SecretStatus;
  /** For the docs: the endpoint and why calling it is safe. */
  why: string;
};

const bearer = (key: string) => ({ authorization: `Bearer ${key}` });
/** 2xx: the key works. 401: the provider doesn't recognise it. Anything else: can't tell. */
const byStatus = (res: Answer): SecretStatus => (res.status >= 200 && res.status < 300 ? 'live' : res.status === 401 ? 'revoked' : 'unknown');
/** Some keys work but aren't allowed this endpoint (restricted or scoped keys): 403 still means live. */
const forbiddenIsLive = (res: Answer): SecretStatus => (res.status === 403 ? 'live' : byStatus(res));

export const PROVIDERS: Provider[] = [
  {
    id: 'paystack',
    name: 'Paystack',
    match: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/,
    hosts: ['api.paystack.co'],
    owns: (k) => skProvider(k) === 'Paystack',
    requests: (k) => [{ url: 'https://api.paystack.co/balance', headers: bearer(k) }],
    read: byStatus,
    why: 'GET /balance reads the balance. 401 means Paystack does not know the key.',
  },
  {
    id: 'stripe',
    name: 'Stripe',
    match: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/,
    hosts: ['api.stripe.com'],
    owns: (k) => k.startsWith('rk_') || skProvider(k) === 'Stripe',
    requests: (k) => [{ url: 'https://api.stripe.com/v1/balance', headers: bearer(k) }],
    // A restricted key without balance access gets 403: the key still works.
    read: forbiddenIsLive,
    why: 'GET /v1/balance reads the balance. 401 means the key is invalid or rolled; a restricted key without balance access gets 403, which still means live.',
  },
  {
    id: 'flutterwave',
    name: 'Flutterwave',
    match: /\bFLWSECK(?:_TEST)?-[A-Za-z0-9]{20,}-X\b/,
    hosts: ['api.flutterwave.com'],
    requests: (k) => [{ url: 'https://api.flutterwave.com/v3/balances', headers: bearer(k) }],
    read: byStatus,
    why: 'GET /v3/balances reads wallet balances. 401 means the key is invalid.',
  },
  {
    id: 'github',
    name: 'GitHub',
    match: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
    hosts: ['api.github.com'],
    requests: (k) => [{ url: 'https://api.github.com/user', headers: { ...bearer(k), accept: 'application/vnd.github+json' } }],
    // App installation tokens can't read /user (403) but still work. A 403 from the rate limit is unknown.
    read: async (res) => (res.status === 403 && JSON.stringify(await res.json().catch(() => ({}))).includes('rate limit') ? 'unknown' : forbiddenIsLive(res)),
    why: 'GET /user reads who the token belongs to. 401 means it was revoked or expired; an app installation token gets 403, which still means live.',
  },
  {
    id: 'slack',
    name: 'Slack',
    match: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
    hosts: ['slack.com'],
    requests: (k) => [{ url: 'https://slack.com/api/auth.test', method: 'POST', headers: bearer(k) }],
    // Slack answers 200 either way, with ok and an error code.
    read: async (res) => {
      if (res.status !== 200) return 'unknown';
      const body = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (body.ok) return 'live';
      return ['invalid_auth', 'token_revoked', 'token_expired', 'account_inactive', 'not_authed'].includes(body.error ?? '') ? 'revoked' : 'unknown';
    },
    why: 'auth.test only says which workspace and user the token is for. invalid_auth, token_revoked, token_expired or account_inactive means it no longer works.',
  },
  {
    id: 'sendgrid',
    name: 'SendGrid',
    match: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
    hosts: ['api.sendgrid.com'],
    requests: (k) => [{ url: 'https://api.sendgrid.com/v3/scopes', headers: bearer(k) }],
    read: forbiddenIsLive,
    why: "GET /v3/scopes lists the key's own permissions. 401 means it was deleted.",
  },
  {
    id: 'mailgun',
    name: 'Mailgun',
    match: /\bkey-[0-9a-f]{32}\b/,
    // US and EU accounts live on different hosts, both Mailgun's.
    hosts: ['api.mailgun.net', 'api.eu.mailgun.net'],
    requests: (k) => {
      const headers = { authorization: `Basic ${Buffer.from(`api:${k}`).toString('base64')}` };
      return [{ url: 'https://api.mailgun.net/v3/domains?limit=1', headers }, { url: 'https://api.eu.mailgun.net/v3/domains?limit=1', headers }];
    },
    read: byStatus,
    why: 'GET /v3/domains lists sending domains, on the US host and then the EU one. Revoked only when both answer 401.',
  },
  {
    id: 'resend',
    name: 'Resend',
    match: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24,}\b/,
    hosts: ['api.resend.com'],
    requests: (k) => [{ url: 'https://api.resend.com/domains', headers: bearer(k) }],
    // A sending-only key can't list domains: Resend says restricted_api_key, which means it works.
    read: async (res) => {
      if (res.status === 401 && JSON.stringify(await res.json().catch(() => ({}))).includes('restricted_api_key')) return 'live';
      return forbiddenIsLive(res);
    },
    why: 'GET /domains lists domains. A sending-only key is refused as restricted_api_key, which still means live; any other 401 means invalid.',
  },
  {
    id: 'telegram',
    name: 'Telegram',
    match: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/,
    hosts: ['api.telegram.org'],
    requests: (k) => [{ url: `https://api.telegram.org/bot${k}/getMe` }],
    read: (res) => (res.status === 404 ? 'revoked' : byStatus(res)),
    why: "getMe returns the bot's own name. 401 or 404 means the token was revoked.",
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    match: /\bsk-ant-api\d{2}-[A-Za-z0-9_-]{80,}/,
    hosts: ['api.anthropic.com'],
    requests: (k) => [{ url: 'https://api.anthropic.com/v1/models?limit=1', headers: { 'x-api-key': k, 'anthropic-version': '2023-06-01' } }],
    read: byStatus,
    why: 'GET /v1/models lists models; it runs no model and costs nothing. 401 means the key was disabled or deleted.',
  },
  {
    id: 'openai',
    name: 'OpenAI',
    match: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/,
    hosts: ['api.openai.com'],
    requests: (k) => [{ url: 'https://api.openai.com/v1/models', headers: bearer(k) }],
    read: forbiddenIsLive,
    why: 'GET /v1/models lists models; it runs no model and costs nothing. 401 means the key was revoked.',
  },
  {
    id: 'npm',
    name: 'npm',
    match: /\bnpm_[A-Za-z0-9]{36}\b/,
    hosts: ['registry.npmjs.org'],
    requests: (k) => [{ url: 'https://registry.npmjs.org/-/whoami', headers: bearer(k) }],
    read: byStatus,
    why: 'GET /-/whoami returns the username. 401 means the token was revoked.',
  },
  {
    id: 'digitalocean',
    name: 'DigitalOcean',
    match: /\bdo[opr]_v1_[a-f0-9]{64}\b/,
    hosts: ['api.digitalocean.com'],
    requests: (k) => [{ url: 'https://api.digitalocean.com/v2/account', headers: bearer(k) }],
    read: forbiddenIsLive,
    why: 'GET /v2/account reads account details. 401 means the token was deleted.',
  },
  {
    id: 'render',
    name: 'Render',
    match: /\brnd_[A-Za-z0-9]{24,}\b/,
    hosts: ['api.render.com'],
    requests: (k) => [{ url: 'https://api.render.com/v1/owners?limit=1', headers: bearer(k) }],
    read: byStatus,
    why: 'GET /v1/owners lists the workspaces the key belongs to. 401 means it was revoked.',
  },
  {
    id: 'discord-webhook',
    name: 'Discord',
    match: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{40,}/,
    hosts: ['discord.com', 'canary.discord.com', 'ptb.discord.com', 'discordapp.com'],
    // GET on a webhook returns its name and channel; only POST would send a message.
    requests: (k) => [{ url: k }],
    read: (res) => (res.status === 404 ? 'revoked' : byStatus(res)),
    why: 'GET on the webhook URL returns its name and channel and posts nothing. 401 or 404 means it was deleted.',
  },
];

export const MAX_CHECKS = 50;
export const CONCURRENCY = 4;
export const MIN_GAP_MS = 250;
export const TIMEOUT_MS = 5_000;

/** The provider and key a finding's line holds, when we know how to check it. */
export function secretIn(d: Detection): { provider: Provider; key: string } | null {
  if (d.ruleId !== 'FX-SEC-001' && d.ruleId !== 'SEC-GEN-001') return null;
  for (const provider of PROVIDERS) {
    const key = provider.match.exec(d.snippet)?.[0];
    if (key && (!provider.owns || provider.owns(key))) return { provider, key };
  }
  return null;
}

export type VerifyOptions = { fetchImpl?: typeof fetch; maxChecks?: number; minGapMs?: number; timeoutMs?: number; concurrency?: number };
export type VerifyResult = { checked: number; live: number; revoked: number; unknown: number; notes: string[] };

/** Sets `secretStatus` on each secret finding it can check. Never throws: a failed check is unknown. */
export async function verifySecrets(detections: Detection[], opts: VerifyOptions = {}): Promise<VerifyResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const maxChecks = opts.maxChecks ?? MAX_CHECKS;
  const minGap = opts.minGapMs ?? MIN_GAP_MS;
  const timeout = opts.timeoutMs ?? TIMEOUT_MS;
  const notes: string[] = [];

  // One call per distinct key, however many places it appears.
  const byKey = new Map<string, { provider: Provider; key: string; findings: Detection[] }>();
  for (const d of detections) {
    const found = secretIn(d);
    if (!found) continue;
    const id = `${found.provider.id}|${found.key}`;
    const entry = byKey.get(id) ?? { ...found, findings: [] };
    entry.findings.push(d);
    byKey.set(id, entry);
  }
  const queue = [...byKey.values()];
  const skipped = queue.splice(maxChecks);
  for (const s of skipped) for (const d of s.findings) d.secretStatus = 'unknown';
  if (skipped.length) notes.push(`--verify checked the first ${maxChecks} keys; ${skipped.length} more are marked unknown.`);

  // Calls to one provider are spaced out, so a repository full of keys doesn't trip its rate limit.
  const nextSlot = new Map<string, number>();
  const wait = async (provider: string) => {
    const now = Date.now();
    const at = Math.max(now, nextSlot.get(provider) ?? 0);
    nextSlot.set(provider, at + minGap);
    if (at > now) await new Promise((r) => setTimeout(r, at - now));
  };

  // Live if any call says so; revoked only if every call says so (Mailgun's US and EU hosts).
  const check = async ({ provider, key }: { provider: Provider; key: string }): Promise<SecretStatus> => {
    const answers: SecretStatus[] = [];
    for (const req of provider.requests(key)) {
      const url = new URL(req.url);
      // The one rule that matters most: a key never goes anywhere but its own provider.
      if (url.protocol !== 'https:' || !provider.hosts.includes(url.hostname)) return 'unknown';
      await wait(provider.id);
      let res: Response;
      try {
        res = await fetchImpl(url, {
          method: req.method ?? 'GET',
          headers: { 'user-agent': 'fortis-cli (secret check)', ...req.headers },
          redirect: 'error',
          signal: AbortSignal.timeout(timeout),
        });
      } catch {
        answers.push('unknown'); // timeout or network
        continue;
      }
      const status = await provider.read({ status: res.status, json: () => res.json() }, req);
      if (status === 'live') return status;
      answers.push(status);
    }
    return answers.length && answers.every((a) => a === 'revoked') ? 'revoked' : 'unknown';
  };

  const counts = { live: 0, revoked: 0, unknown: 0 };
  let next = 0;
  const workers = Array.from({ length: Math.min(opts.concurrency ?? CONCURRENCY, queue.length) }, async () => {
    while (next < queue.length) {
      const entry = queue[next++]!;
      const status = await check(entry).catch((): SecretStatus => 'unknown');
      counts[status]++;
      for (const d of entry.findings) d.secretStatus = status;
    }
  });
  await Promise.all(workers);
  counts.unknown += skipped.length;

  // Secret findings with no check for their kind of key.
  const unchecked = detections.filter((d) => (d.ruleId === 'FX-SEC-001' || d.ruleId === 'SEC-GEN-001') && !d.secretStatus).length;
  if (queue.length) {
    const parts = [counts.live && `${counts.live} live`, counts.revoked && `${counts.revoked} revoked`, counts.unknown && `${counts.unknown} unknown`].filter(Boolean).join(', ');
    notes.push(`Checked ${queue.length + skipped.length} leaked key${queue.length + skipped.length === 1 ? '' : 's'} with their providers: ${parts}.${counts.live ? ' Rotate the live ones first.' : ''}`);
  }
  if (unchecked) notes.push(`${unchecked} secret finding${unchecked === 1 ? '' : 's'} can't be checked (no safe read-only call for that kind of key, or the provider isn't clear from the key): treat ${unchecked === 1 ? 'it' : 'them'} as live.`);
  return { checked: queue.length, ...counts, notes };
}
