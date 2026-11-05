import { describe, expect, it } from 'vitest';

import { FINTECH_RULES } from '../src/rules/fintech';
import { maskSnippet } from '@fortis/shared';
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
    const d = run(genericSecretRule, 'src/a.ts', `${['-----BEGIN RSA PRIVATE', 'KEY-----'].join(' ')}\nconst apiKey = "${['Zx9Qm2Lp7Vt4', 'Rk8Wn3Yb6Hc1'].join('')}";`);
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

describe('SEC-GEN-001 in tests', () => {
  it('skips values that spell themselves out as fake, in test files only', () => {
    const fake = 'out = ApiKeyCreated(**record, api_key="nova_abc12345_secret")';
    expect(run(genericSecretRule, 'backend/tests/test_integration_api.py', fake)).toEqual([]);
    expect(run(genericSecretRule, 'backend/test_api.py', fake)).toEqual([]);
    expect(run(genericSecretRule, 'pkg/client_test.go', 'token := "fake-token-9fK2mQ8vX1pL"')).toEqual([]);
    // The same value in application code is still reported.
    expect(run(genericSecretRule, 'backend/app/config.py', fake)).toHaveLength(1);
  });

  it('still catches a real-looking secret in a test file', () => {
    expect(run(genericSecretRule, 'backend/tests/test_payments.py', 'api_key = "Zx9Qm2Lp7Vt4Rk8Wn3Yb6Hc1"')).toHaveLength(1); // fortis-ignore: test input
  });
});


describe('SEC-GEN-001 connection strings', () => {
  const PW = ['Zx9Qm2Lp', '7Vt4Rk8W'].join('');
  it('reports passwords in database and broker URLs, JDBC URLs and .NET connection strings', () => {
    const cases: [string, string][] = [
      ['.env', `DATABASE_URL=postgres://app:${PW}@db.prod.internal:5432/app`],
      ['.env', `MONGO_URI=mongodb+srv://ledger:${PW}@cluster0.ab12c.mongodb.net/ledger`],
      ['app.properties', `spring.datasource.url=jdbc:sqlserver://sql01.bank.net:1433;databaseName=core;user=svc;password=${PW}`],
      ['appsettings.json', `"Core": "Server=tcp:core.database.windows.net,1433;User ID=svc;Password=${PW};"`],
      ['src/db.ts', `const url = process.env.DATABASE_URL ?? 'postgres://app:${PW}@10.0.3.12:5432/app';`],
    ];
    for (const [path, text] of cases) {
      const d = run(genericSecretRule, path, text);
      expect(d, text).toHaveLength(1);
      expect(d[0]!.severity).toBe('critical');
      expect(d[0]!.title).toMatch(/Database password/);
    }
  });

  it('leaves local databases, placeholders and URLs without a password alone', () => {
    for (const text of [
      'DATABASE_URL=postgres://postgres:postgres@localhost:5432/app',
      'DATABASE_URL=postgresql://app:app_dev_pw@db:5432/app',
      'DATABASE_URL=postgres://app:${DB_PASSWORD}@db.prod.internal:5432/app',
      'DATABASE_URL=postgres://app@db.prod.internal:5432/app',
      '// postgres://USER:PASSWORD@HOST:5432/DB',
      'const u = `mysql://${user}:${pass}@${host}/core`;',
      'dev.url=jdbc:mysql://localhost:3306/dev?user=root&password=root',
    ]) {
      expect(run(genericSecretRule, '.env', text), text).toEqual([]);
    }
  });

  it('masks the password in every snippet it reports', () => {
    const d = run(genericSecretRule, '.env', `DATABASE_URL=postgres://app:${PW}@db.prod.internal:5432/app`);
    const masked = maskSnippet(d[0]!.snippet);
    expect(masked).not.toContain(PW);
    expect(masked).toContain('postgres://app:••••••••');
    expect(maskSnippet(`Server=x;Password=${PW};`)).not.toContain(PW);
    expect(maskSnippet(`jdbc:mysql://h/db?user=u&password=${PW}&ssl=1`)).not.toContain(PW);
  });
});

describe('FX-SEC-001 names the right provider', () => {
  const hex = 'a3f9c2e1b7d04f6a8c5e2b9d1f7a3c6e0b4d8f2a';
  const stripeBody = `51HxQ2mKz9vP8rT4wL0bN6yH3cJ7fA1${'Qw3Er5Ty7Ui9Op1As3Df5Gh7Jk9Lz2Xc4Vb6Nm8'.repeat(2)}`;
  const title = (key: string) => run(paymentKeyRule, 'src/pay.ts', `const k = '${key}';`)[0]?.title;
  it('tells Paystack and Stripe secret keys apart, and says so when it cannot', () => {
    expect(title(['sk', 'live', hex].join('_'))).toBe('Live Paystack secret key in code');
    expect(title(['sk', 'test', hex].join('_'))).toBe('Paystack test secret key in code');
    expect(title(['sk', 'live', stripeBody].join('_'))).toBe('Live Stripe secret key in code');
    expect(title(['sk', 'live', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4'].join('_'))).toBe('Live Stripe or Paystack secret key in code');
  });
  it('reports Stripe restricted keys and webhook secrets, and masks them', () => {
    expect(title(['rk', 'live', stripeBody].join('_'))).toBe('Live Stripe restricted key in code');
    const wh = `whsec_${'Zx9Qm2Lp7Vt4Rk8Wn3Yb6Hc1Df5Gj0Ks'}`;
    expect(title(wh)).toBe('Stripe webhook signing secret in code');
    expect(maskSnippet(`const s = '${wh}';`)).not.toContain(wh);
    expect(maskSnippet(`k = '${['rk', 'live', stripeBody].join('_')}'`)).toContain('rk_live_••••••••');
  });
});

describe('SEC-GEN-001 SaaS, cloud and registry tokens', () => {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = (role: string) => [b64({ alg: 'HS256', typ: 'JWT' }), b64({ iss: 'supabase', role }), 'Zm9vYmFyYmF6cXV4cXV1eGNvcmdl'].join('.');
  const SENDGRID = ['SG', 'aB3dE6gH9jK2mN5pQ8sT1v', 'wX4zA7cD0fG3iJ6lM9oP2rS5uV8xY1aB4dE7gH0jK3m'].join('.');
  const SLACK = ['https://hooks.slack.com/services', 'T01ABCDEF', 'B02GHIJKL', 'aB3dE6gH9jK2mN5pQ8sT1vW4'].join('/');
  const ANTHROPIC = ['sk', 'ant', 'api03', 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hI6kL9nO2qR5tU8wX1zA4cD7fG0iJ3lM6oP9rS2uV5xY8aB1dE4gH7jK0mN3'].join('-');

  it('names the provider of each token', () => {
    const titles = run(genericSecretRule, 'src/notify.ts', [`const a = '${SENDGRID}';`, `const b = '${SLACK}';`, `const c = '${ANTHROPIC}';`].join('\n')).map((d) => d.title);
    expect(titles).toEqual(['SendGrid API key in code', 'Slack webhook URL in code', 'Anthropic API key in code']);
  });

  it('flags a Supabase service_role key as critical but not the public anon key', () => {
    const d = run(genericSecretRule, 'src/db.ts', `const admin = '${jwt('service_role')}';\nconst anon = '${jwt('anon')}';`);
    expect(d.map((x) => [x.line, x.severity, x.title])).toEqual([[1, 'critical', 'Supabase service_role key in code']]);
  });

  it('flags a Twilio auth token but not the account SID or an env read', () => {
    const src = [`TWILIO_AUTH_TOKEN=${'0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d'}`, `TWILIO_ACCOUNT_SID=AC${'0'.repeat(32)}`, 'const t = process.env.TWILIO_AUTH_TOKEN;'].join('\n');
    expect(run(genericSecretRule, '.env', src).map((d) => [d.line, d.title])).toEqual([[1, 'Twilio auth token in code']]);
  });

  it('calls a PEM inside a service-account JSON a Google Cloud key', () => {
    const src = `{\n  "type": "service_account",\n  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE\\n"\n}`; // fortis-ignore: test input
    expect(run(genericSecretRule, 'deploy/sa.json', src).map((d) => [d.line, d.severity, d.title])).toEqual([[3, 'critical', 'Google Cloud service account key in code']]);
  });

  it('masks the secret part of each token', () => {
    expect(maskSnippet(`const a = '${SENDGRID}';`)).not.toContain(SENDGRID.slice(3, 20));
    expect(maskSnippet(`const b = '${SLACK}';`)).not.toContain('aB3dE6gH9jK2mN5pQ8sT1vW4');
    expect(maskSnippet(`const c = '${ANTHROPIC}';`)).not.toContain(ANTHROPIC.slice(20, 40));
    expect(maskSnippet(`const k = '${jwt('service_role')}';`)).not.toContain(b64({ iss: 'supabase', role: 'service_role' }));
  });
});

describe('FX-SEC-001 African payment providers', () => {
  const SEERBIT = ['SBSECK', 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF'].join('_');
  const SEERBIT_PUB = ['SBPUBK', 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF'].join('_');
  const OPAY = ['OPAY', 'PRV', '1612345678901234567890'].join('');
  const OPAY_PUB = ['OPAY', 'PUB', '1612345678901234567890'].join('');
  const SQUAD = ['sandbox', 'sk', '94f2b798466408ef4d19e848ee1a4d1a3e93f1'].join('_');

  it('names live and sandbox secret keys and masks them', () => {
    const src = [`const a = '${SEERBIT}';`, `const b = '${OPAY}';`, `const c = '${SQUAD}';`].join('\n');
    const d = run(paymentKeyRule, 'src/pay.ts', src);
    expect(d.map((x) => [x.severity, x.title])).toEqual([
      ['critical', 'Live SeerBit secret key in code'],
      ['critical', 'OPay private key in code'],
      ['high', 'Squad sandbox secret key in code'],
    ]);
    for (const [line, key] of [[0, SEERBIT], [1, OPAY], [2, SQUAD]] as const) {
      expect(maskSnippet(src.split('\n')[line]!)).not.toContain(key.slice(-16));
    }
  });

  it('leaves public keys alone under every rule', () => {
    const src = `export const SEERBIT_PUBLIC_KEY = '${SEERBIT_PUB}';\nexport const OPAY_PUBLIC_KEY = '${OPAY_PUB}';`;
    expect([...run(paymentKeyRule, 'src/pay.ts', src), ...run(genericSecretRule, 'src/pay.ts', src)]).toEqual([]);
  });
});
