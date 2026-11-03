import { z } from 'zod';

import { SEVERITIES } from './rules';

/** Max snippet length the API accepts. Findings carry a masked line, never source files. */
export const MAX_SNIPPET_LENGTH = 300;
export const MAX_FINDINGS_PER_SCAN = 2000;

export const ROLES = ['owner', 'admin', 'developer', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

export const FINDING_STATUSES = ['open', 'fixed', 'accepted_risk', 'false_positive'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

/* ---------- Accounts ---------- */

export const signupSchema = z.object({
  name: z.string().trim().min(2).max(120),
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(10, 'Use at least 10 characters').max(200),
  company: z.string().trim().min(2).max(120),
});
export type SignupInput = z.infer<typeof signupSchema>;

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(1).max(200),
});

/* ---------- Projects and tokens ---------- */

export const createProjectSchema = z.object({
  name: z.string().trim().min(2).max(80),
  repoUrl: z.string().trim().url().max(500).optional(),
});

export const createTokenSchema = z.object({
  name: z.string().trim().min(2).max(80),
});

export const addMemberSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  role: z.enum(['admin', 'developer', 'viewer']),
});

/* ---------- CLI upload ---------- */

export const cliFindingSchema = z.object({
  ruleId: z.string().trim().min(3).max(40).regex(/^[A-Z0-9-]+$/),
  severity: z.enum(SEVERITIES),
  title: z.string().trim().min(3).max(200),
  file: z.string().trim().min(1).max(500),
  line: z.number().int().min(0).max(10_000_000).optional(),
  snippet: z.string().max(MAX_SNIPPET_LENGTH).optional(),
  /** Longer explanation and fix from the tool (used for DAST findings, which have no catalogue entry). */
  detail: z.string().max(4000).optional(),
  /** Stable hash from the CLI; the API computes one if missing. */
  fingerprint: z.string().trim().min(8).max(128).optional(),
});
export type CliFinding = z.infer<typeof cliFindingSchema>;

export const cliScanSchema = z.object({
  /** Client-generated UUID so retries don't create duplicate scans. */
  scanId: z.string().uuid(),
  trigger: z.enum(['pre-push', 'ci', 'manual']),
  /** code: static checks of the repository. dast: OWASP ZAP against a verified staging target. */
  kind: z.enum(['code', 'dast']).default('code'),
  targetId: z.string().uuid().optional(),
  dastMode: z.enum(['baseline', 'full']).optional(),
  /** "changed" scans only cover changed files, so they never auto-close findings. */
  scope: z.enum(['changed', 'full']),
  commit: z.string().trim().max(64).optional(),
  branch: z.string().trim().max(200).optional(),
  cliVersion: z.string().trim().max(40),
  rulesVersion: z.string().trim().max(40).optional(),
  durationMs: z.number().int().min(0).max(86_400_000).optional(),
  filesScanned: z.number().int().min(0).max(10_000_000).optional(),
  findings: z.array(cliFindingSchema).max(MAX_FINDINGS_PER_SCAN),
});
export type CliScanInput = z.infer<typeof cliScanSchema>;

/* ---------- Staging targets (DAST) ---------- */

export const createTargetSchema = z.object({
  url: z
    .string()
    .trim()
    .url()
    .max(500)
    .refine((u) => /^https?:\/\//i.test(u), 'Use an http(s) URL'),
  environment: z.enum(['staging', 'development', 'production']),
  label: z.string().trim().max(80).optional(),
});

export const authorizeTargetSchema = z.object({
  signerName: z.string().trim().min(3).max(120),
  accept: z.literal(true),
});

/** Version of the testing-authorisation wording the signer agreed to. */
export const TARGET_AUTHORIZATION_VERSION = '2026-11';
export const TARGET_AUTHORIZATION_TEXT =
  'I confirm that my organisation owns or has written permission to test this target, that it is a non-production environment using test data only, and I authorise Fortis to run automated security tests against it, including active attack simulations when my plan and settings allow. Tests can be paused at any time.';

/* ---------- Findings ---------- */

export const updateFindingSchema = z
  .object({
    status: z.enum(FINDING_STATUSES),
    reason: z.string().trim().max(500).optional(),
  })
  .refine((v) => (v.status === 'accepted_risk' || v.status === 'false_positive' ? Boolean(v.reason) : true), {
    message: 'Give a reason when accepting a risk or marking a false positive',
    path: ['reason'],
  });
