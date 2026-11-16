import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { Detection } from '../src/rules/types';
import { verifySecrets, type SecretStatus } from '../src/verify';

/*
 * `fortis scan --verify` against the real Paystack, Stripe and Flutterwave APIs (#95). verify.test.ts covers every
 * provider with mocked answers; this checks that the real ones answer the way those mocks say. Normal test runs
 * stay offline; turn it on with
 *   FORTIS_LIVE_VERIFY=1 pnpm --filter fortis-watchdog exec vitest run tests/verify-live.test.ts
 *
 * Without any keys it still checks, with each provider:
 *   - a key it never issued (random, made here) reads as revoked;
 *   - a request cut off by the timeout reads as unknown, not revoked.
 * With test-mode keys in the environment it also checks that a working key reads as live, and a revoked one as
 * revoked. Only test-mode keys are accepted; a live key fails the test before anything is sent.
 *   FORTIS_LIVE_PAYSTACK_TEST_KEY      FORTIS_LIVE_PAYSTACK_REVOKED_KEY
 *   FORTIS_LIVE_STRIPE_TEST_KEY        FORTIS_LIVE_STRIPE_REVOKED_KEY
 *   FORTIS_LIVE_FLUTTERWAVE_TEST_KEY   FORTIS_LIVE_FLUTTERWAVE_REVOKED_KEY
 *
 * A rate-limited answer can't be caused without flooding a provider, so that case stays with the mocks.
 */
const LIVE = process.env.FORTIS_LIVE_VERIFY === '1';

const hex = (n: number) => randomBytes(n).toString('hex').slice(0, n);
/** Letters and digits with at least one capital, as Stripe's keys have. */
const mixed = (n: number) => `A${randomBytes(n * 2).toString('base64').replace(/[^A-Za-z0-9]/g, '')}`.slice(0, n);

type Provider = { name: string; env: string; made: () => string; testMode: RegExp };
const PROVIDERS: Provider[] = [
  // Paystack's shape (40 lower-case hex characters) is what tells Fortis the key is Paystack's.
  { name: 'Paystack', env: 'PAYSTACK', made: () => ['sk', 'test', hex(40)].join('_'), testMode: /^sk_test_/ },
  // A long mixed-case body starting 51 is what tells Fortis the key is Stripe's.
  { name: 'Stripe', env: 'STRIPE', made: () => ['sk', 'test', `51${mixed(97)}`].join('_'), testMode: /^(?:sk|rk)_test_/ },
  { name: 'Flutterwave', env: 'FLUTTERWAVE', made: () => `${['FLWSECK', 'TEST'].join('_')}-${hex(32)}-X`, testMode: /^FLWSECK_TEST-/ },
];

const finding = (key: string): Detection => ({ ruleId: 'FX-SEC-001', severity: 'high', title: 'Test secret key in code', file: 'src/pay.ts', line: 1, snippet: `const key = '${key}';` });

async function statusOf(key: string, opts: { timeoutMs?: number } = {}): Promise<SecretStatus | undefined> {
  const d = finding(key);
  const result = await verifySecrets([d], { minGapMs: 0, ...opts });
  expect(result.checked, 'Fortis should recognise whose key this is and check it').toBe(1);
  return d.secretStatus;
}

describe.skipIf(!LIVE)('fortis scan --verify against the real providers', () => {
  for (const p of PROVIDERS) {
    describe(p.name, () => {
      it('a key it never issued reads as revoked', async () => {
        expect(await statusOf(p.made())).toBe('revoked');
      }, 20_000);

      it('a request cut off by the timeout reads as unknown, not revoked', async () => {
        expect(await statusOf(p.made(), { timeoutMs: 1 })).toBe('unknown');
      }, 20_000);

      const working = process.env[`FORTIS_LIVE_${p.env}_TEST_KEY`];
      it.skipIf(!working)(`a working test key reads as live (FORTIS_LIVE_${p.env}_TEST_KEY)`, async () => {
        expect(working, 'only test-mode keys belong here, never a live key').toMatch(p.testMode);
        expect(await statusOf(working!)).toBe('live');
      }, 20_000);

      const revoked = process.env[`FORTIS_LIVE_${p.env}_REVOKED_KEY`];
      it.skipIf(!revoked)(`a revoked test key reads as revoked (FORTIS_LIVE_${p.env}_REVOKED_KEY)`, async () => {
        expect(revoked, 'only test-mode keys belong here, never a live key').toMatch(p.testMode);
        expect(await statusOf(revoked!)).toBe('revoked');
      }, 20_000);
    });
  }
});
