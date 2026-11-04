import { describe, expect, it } from 'vitest';

import { FINTECH_RULES } from '../src/rules/fintech';
import { genericSecretRule, paymentKeyRule } from '../src/rules/secrets';
import { emptyContext, type FileRule, type SourceFile } from '../src/rules/types';
import { buildContext } from '../src/scan';

const file = (path: string, text: string): SourceFile => ({ path, text, lines: text.split('\n') });
const run = (rule: FileRule, path: string, text: string, ctx = emptyContext()) => rule.run(file(path, text), ctx);
const rule = (id: string) => FINTECH_RULES.find((r) => r.id === id)!;

// Fake keys are assembled at runtime so secret scanners don't flag this test file.
const PAYSTACK_LIVE = ['sk', 'live', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4'].join('_');
const FLW_LIVE = `${['FLWSECK', 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'].join('-')}-X`;

describe('FX-SEC-001 payment-provider keys', () => {
  it('flags a live Paystack key as critical and a Flutterwave key', () => {
    const d = run(paymentKeyRule, 'src/config.ts', `export const PAYSTACK = '${PAYSTACK_LIVE}';\nconst flw = "${FLW_LIVE}";`);
    expect(d.map((x) => [x.ruleId, x.severity, x.line])).toEqual([['FX-SEC-001', 'critical', 1], ['FX-SEC-001', 'critical', 2]]);
  });
  it('ignores keys read from the environment and honours fortis-ignore', () => {
    expect(run(paymentKeyRule, 'a.ts', 'const k = process.env.PAYSTACK_SECRET_KEY;')).toHaveLength(0);
    expect(run(paymentKeyRule, 'a.ts', `const k = '${PAYSTACK_LIVE}'; // fortis-ignore`)).toHaveLength(0);
    expect(run(paymentKeyRule, 'a.ts', `// fortis-ignore-next-line\nconst k = '${PAYSTACK_LIVE}';`)).toHaveLength(0);
  });
});

describe('SEC-GEN-001 generic secrets', () => {
  it('flags private keys and random-looking hard-coded secrets', () => {
    const d = run(genericSecretRule, 'src/a.ts', `-----BEGIN RSA PRIVATE KEY-----\nconst apiKey = "Zx9Qm2Lp7Vt4Rk8Wn3Yb6Hc1";`); // fortis-ignore: test input
    expect(d.map((x) => x.line)).toEqual([1, 2]);
  });
  it('skips placeholders, low-entropy values and env lookups', () => {
    const text = ['const password = "changeme-changeme-123";', 'const token = "aaaaaaaaaaaaaaaaaaaa";', 'const secret = process.env.SECRET ?? "Zx9Qm2Lp7Vt4Rk8Wn3Yb6Hc1";'].join('\n');
    expect(run(genericSecretRule, 'src/a.ts', text)).toHaveLength(0);
  });
});

describe('FX-OWN-001 ownership checks', () => {
  it('flags a transfer loaded by request ID with no user scope', () => {
    const code = `router.get('/transfers/:id', auth, async (req, res) => {\n  const t = await Transfer.findById(req.params.id);\n  res.json(t);\n});`;
    const d = run(rule('FX-OWN-001'), 'src/routes/transfers.ts', code);
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ line: 2, severity: 'critical' });
  });
  it('passes when the query is scoped to the signed-in user', () => {
    const code = `router.get('/transfers/:id', auth, async (req, res) => {\n  const t = await Transfer.findOne({ _id: req.params.id, ownerId: req.user.id });\n  res.json(t);\n});`;
    expect(run(rule('FX-OWN-001'), 'src/routes/transfers.ts', code)).toHaveLength(0);
  });
  it('ignores non-money records', () => {
    const code = `const post = await BlogPost.findById(req.params.id);`;
    expect(run(rule('FX-OWN-001'), 'src/routes/blog.ts', code)).toHaveLength(0);
  });
});

describe('FX-HOOK-001 webhook signatures', () => {
  it('flags a Paystack webhook that never checks the signature', () => {
    const code = `// paystack events\napp.post('/webhooks/paystack', async (req, res) => {\n  await credit(req.body.data);\n  res.sendStatus(200);\n});`;
    expect(run(rule('FX-HOOK-001'), 'src/webhooks.ts', code)).toHaveLength(1);
  });
  it('passes when the HMAC is verified', () => {
    const code = `// paystack\napp.post('/webhooks/paystack', (req, res) => {\n  const sig = req.headers['x-paystack-signature'];\n  const h = crypto.createHmac('sha512', secret).update(raw).digest('hex');\n});`;
    expect(run(rule('FX-HOOK-001'), 'src/webhooks.ts', code)).toHaveLength(0);
  });
});

describe('FX-TXN-001 balance races', () => {
  it('flags read-modify-write of a balance outside a transaction', () => {
    expect(run(rule('FX-TXN-001'), 'src/wallet.ts', 'wallet.balance = wallet.balance - amount;\nawait wallet.save();')).toHaveLength(1);
  });
  it('passes inside a transaction or with an atomic increment', () => {
    expect(run(rule('FX-TXN-001'), 'src/wallet.ts', 'await prisma.$transaction(async (tx) => {\n wallet.balance = wallet.balance - amount;\n});')).toHaveLength(0);
    expect(run(rule('FX-TXN-001'), 'src/wallet.ts', "await Wallet.updateOne({ _id }, { $inc: { balance: -amount } });")).toHaveLength(0);
  });
});

describe('FX-PII-002, FX-OTP-001 and FX-IDEM-001', () => {
  it('flags BVN in logs but not masked values', () => {
    expect(run(rule('FX-PII-002'), 'src/kyc.ts', 'logger.info({ bvn: user.bvn });')).toHaveLength(1);
    expect(run(rule('FX-PII-002'), 'src/kyc.ts', 'logger.info({ bvn: mask(user.bvn) });')).toHaveLength(0);
  });
  it('flags Math.random OTPs and OTPs in responses', () => {
    expect(run(rule('FX-OTP-001'), 'src/otp.ts', 'const otp = Math.floor(Math.random() * 1e6);')).toHaveLength(1);
    expect(run(rule('FX-OTP-001'), 'src/otp.ts', 'res.json({ sent: true, otp });')).toHaveLength(1);
    expect(run(rule('FX-OTP-001'), 'src/otp.ts', 'const otp = crypto.randomInt(100000, 999999);')).toHaveLength(0);
  });
  it('flags money-out routes without idempotency handling', () => {
    expect(run(rule('FX-IDEM-001'), 'src/routes.ts', "router.post('/v1/transfers', createTransfer);")).toHaveLength(1);
    expect(run(rule('FX-IDEM-001'), 'src/routes.ts', "router.post('/v1/transfers', requireIdempotencyKey, createTransfer);")).toHaveLength(0);
  });
});

describe('false positives seen on a real fintech backend', () => {
  it('does not treat the word BVN in a message as a logged BVN', () => {
    expect(run(rule('FX-PII-002'), 'scripts/a.ts', "console.error('BVN must be 11 digits');")).toHaveLength(0);
    expect(run(rule('FX-PII-002'), 'src/kyc.ts', 'console.log(`[KYC] Prembly BVN+face ${tag}:`);')).toHaveLength(0);
    const multi = "console.warn('[KYC] Prembly BVN+face rejected', {\n  faceStatus: faceData.status,\n  confidence,\n});";
    expect(run(rule('FX-PII-002'), 'src/kyc.ts', multi)).toHaveLength(0);
  });
  it('still flags a BVN value, including inside a multi-line log call', () => {
    expect(run(rule('FX-PII-002'), 'scripts/a.ts', 'console.log(`BVN: ${BVN}`);')).toHaveLength(1);
    expect(run(rule('FX-PII-002'), 'src/kyc.ts', "logger.warn('rejected', {\n  status,\n  bvn: customer.bvn,\n});")).toHaveLength(1);
  });
  it('does not treat the word OTP in a message as a logged OTP', () => {
    expect(run(rule('FX-OTP-001'), 'src/auth.ts', 'console.log(`[auth:login] reviewer_bypass customer #${customer.id} — no OTP sent`);')).toHaveLength(0);
    expect(run(rule('FX-OTP-001'), 'src/otp.ts', 'console.error(`[otp] delivery failed purpose=${purpose} channel=${delivery.channel}: ${detail}`);')).toHaveLength(0);
  });
  it('still flags a logged OTP value and a hard-coded OTP', () => {
    expect(run(rule('FX-OTP-001'), 'src/otp.ts', 'console.log(`sent ${otp} to ${phone}`);')[0]?.title).toBe('OTP written to logs');
    expect(run(rule('FX-OTP-001'), 'scripts/seed.ts', "console.log('  2. OTP: 482901 (no SMS when bypass is on)');")[0]).toMatchObject({ severity: 'medium', title: 'Hard-coded OTP in source' });
  });
  it('recognises idempotency middleware defined in another file', () => {
    const guard = file('src/services/payment-guard.service.ts', "function idempotencyKey(req) { return req.headers['idempotency-key']; }\nexport function withPaymentGuard(route) { return async () => {}; }");
    const ctx = buildContext([guard]);
    const route = "router.post('/transfer', validateBody(schema), requireTxnAuth, withPaymentGuard('wallet.transfer'), async (req, res) => {});";
    expect(run(rule('FX-IDEM-001'), 'src/modules/wallet/wallet.routes.ts', route, ctx)).toHaveLength(0);
    expect(run(rule('FX-IDEM-001'), 'src/modules/wallet/wallet.routes.ts', "router.post('/transfer', async (req, res) => {});", ctx)).toHaveLength(1);
  });
});
