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
};

/**
 * Catalogue of rule metadata shown in the dashboard and sent to the CLI with
 * each rule pack. Detection logic lives in the CLI's rules package.
 */
export const RULE_CATALOG: readonly RuleMeta[] = [
  {
    id: 'FX-SEC-001',
    pack: 'fintech',
    title: 'Payment-provider secret key in code',
    severity: 'critical',
    summary: 'A Paystack, Flutterwave or Monnify secret key is committed to the repository or config.',
    fix: 'Move the key to an environment variable or secret manager, then rotate it with the provider.',
  },
  {
    id: 'FX-OWN-001',
    pack: 'fintech',
    title: 'Money record read without an ownership check',
    severity: 'critical',
    summary: 'A transfer, wallet or account is loaded by ID without scoping it to the signed-in user.',
    fix: 'Filter the query by the signed-in user, for example { _id: id, ownerId: req.user.id }, and return 404 otherwise.',
  },
  {
    id: 'FX-HOOK-001',
    pack: 'fintech',
    title: 'Payment webhook without a signature check',
    severity: 'critical',
    summary: 'A webhook credits value without verifying the provider signature header.',
    fix: "Verify the provider's HMAC signature (for example x-paystack-signature) against the raw body before acting.",
  },
  {
    id: 'FX-TXN-001',
    pack: 'fintech',
    title: 'Balance update outside a transaction',
    severity: 'high',
    summary: 'A debit or credit reads and writes a balance in separate steps, open to race conditions.',
    fix: 'Use a single atomic update or a database transaction with a row lock.',
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
    summary: 'An OTP is logged, returned in a response, generated with Math.random or has no attempt limit.',
    fix: 'Generate with crypto.randomInt, never log or return it, and limit attempts.',
  },
  {
    id: 'SEC-GEN-001',
    pack: 'secrets',
    title: 'Generic secret in code',
    severity: 'high',
    summary: 'An API key, token or private key is committed to the repository.',
    fix: 'Move it to an environment variable or secret manager and rotate it.',
  },
  {
    id: 'DEP-OSV',
    pack: 'dependencies',
    title: 'Vulnerable dependency',
    severity: 'medium',
    summary: 'A package has a known vulnerability in public advisory data.',
    fix: 'Upgrade to the fixed version shown in the advisory.',
  },
];

export function findRule(id: string): RuleMeta | undefined {
  return RULE_CATALOG.find((r) => r.id === id);
}
