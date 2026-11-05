import type { RulePack } from './plans';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export type RuleMeta = {
  id: string;
  pack: RulePack;
  title: string;
  severity: Severity;
  summary: string;
  fix: string;
  /** The fix in Python's terms, where `fix` is written for JavaScript. */
  fixPython?: string;
};

/**
 * Catalogue of rule metadata shown in the dashboard and sent to the CLI with
 * each rule pack. Detection logic lives in the CLI's rules package.
 */
export const RULE_CATALOG: readonly RuleMeta[] = [
  {
    id: 'FX-SEC-001',
    // Free: a leaked payment key is a secret, and the free plan promises secret scanning.
    pack: 'secrets',
    title: 'Payment-provider secret key in code',
    severity: 'critical',
    summary: 'A Paystack, Stripe, Flutterwave, Monnify, SeerBit, OPay or Squad secret key (or a Stripe restricted key or webhook secret) is committed to the repository or config.',
    fix: 'Move the key to an environment variable or secret manager, then rotate it with the provider: Paystack (Settings → API Keys & Webhooks → generate a new secret key), Stripe (Developers → API keys → roll the key), Flutterwave (Settings → API Keys → generate new keys), Monnify (Developers → API Keys → regenerate), SeerBit (Account settings → API keys → regenerate), OPay (merchant dashboard → API keys → reset the private key), Squad (Merchant Settings → API & Webhook → regenerate).',
  },
  {
    id: 'FX-OWN-001',
    pack: 'fintech',
    title: 'Money record read without an ownership check',
    severity: 'critical',
    summary: 'A transfer, wallet or account is loaded by ID without scoping it to the signed-in user.',
    fix: 'Filter the query by the signed-in user, for example { _id: id, ownerId: req.user.id }, and return 404 otherwise.',
    fixPython: 'Filter by the signed-in user, for example get_object_or_404(Wallet, pk=pk, user=request.user), or override get_queryset in Django REST.',
  },
  {
    id: 'FX-HOOK-001',
    pack: 'fintech',
    title: 'Payment webhook without a signature check',
    severity: 'critical',
    summary: 'A webhook credits value without verifying the provider signature header.',
    fix: "Verify the provider's HMAC signature (for example x-paystack-signature) against the raw body before acting.",
    fixPython: "Compute the HMAC of the raw body and compare it to the provider's signature header with hmac.compare_digest before acting.",
  },
  {
    id: 'FX-TXN-001',
    pack: 'fintech',
    title: 'Balance update outside a transaction',
    severity: 'high',
    summary: 'A debit or credit reads and writes a balance in separate steps, open to race conditions.',
    fix: 'Use a single atomic update or a database transaction with a row lock.',
    fixPython: 'Use update(balance=F("balance") - amount), or lock the row first with select_for_update() (with_for_update() in SQLAlchemy). transaction.atomic alone is not enough.',
  },
  {
    id: 'FX-PII-002',
    pack: 'fintech',
    title: 'BVN or NIN exposed',
    severity: 'high',
    summary: 'A BVN or NIN is written to logs, errors or API responses.',
    fix: 'Remove it from the output or mask all but the last four digits.',
  },
  {
    id: 'FX-IDEM-001',
    pack: 'fintech',
    title: 'Transfer without an idempotency key',
    severity: 'high',
    summary: 'A money-out endpoint can be replayed and pay out twice on a retry.',
    fix: 'Require an idempotency key and store it with the transfer, rejecting repeats.',
  },
  {
    id: 'FX-OTP-001',
    pack: 'fintech',
    title: 'Weak or leaked one-time passcode',
    severity: 'high',
    summary: 'An OTP is logged, returned in a response, generated with a predictable random function or has no attempt limit.',
    fix: 'Generate with crypto.randomInt, never log or return it, and limit attempts.',
    fixPython: 'Generate with secrets.randbelow, never log or return it, and limit attempts.',
  },
  {
    id: 'SEC-GEN-001',
    pack: 'secrets',
    title: 'Generic secret in code',
    severity: 'high',
    summary: 'An API key, token, private key or database password (in a connection URL or connection string) is committed to the repository.',
    fix: 'Move it to an environment variable or secret manager and rotate it.',
  },
  {
    id: 'DEP-OSV',
    pack: 'dependencies',
    title: 'Vulnerable dependency',
    severity: 'medium',
    summary: 'A package has a known vulnerability in public advisory data.',
    fix: 'Upgrade to the fixed version. Each finding names the version that clears every advisory on the package and the command for your package manager; for an indirect dependency, it names the direct dependency that pulls it in.',
  },
  {
    id: 'FX-BOLA-001',
    pack: 'fintech',
    title: "One customer can read another customer's records",
    severity: 'critical',
    summary: "Found by `fortis access` on staging: test user B asked for test user A's loan, wallet or transfer by ID and got it. This is broken object-level authorisation (BOLA/IDOR), the most common way fintech data leaks.",
    fix: "Scope every lookup to the signed-in customer (WHERE id = $1 AND customer_id = $2) and return 404 when the record isn't theirs.",
  },
  {
    id: 'FX-AUTH-001',
    pack: 'fintech',
    title: 'Customer records readable without logging in',
    severity: 'critical',
    summary: 'Found by `fortis access` on staging: a request with no login at all returned a customer record.',
    fix: 'Put the route behind your authentication middleware and add a test that an anonymous request gets 401.',
  },
];

/** The fix for a finding, in the language of the file it's in. */
export function fixFor(rule: Pick<RuleMeta, 'fix' | 'fixPython'>, file: string): string {
  return /\.py$/i.test(file) && rule.fixPython ? rule.fixPython : rule.fix;
}

export function findRule(id: string): RuleMeta | undefined {
  return RULE_CATALOG.find((r) => r.id === id);
}
