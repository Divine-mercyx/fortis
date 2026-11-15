import { sql } from 'drizzle-orm';
import {
  bigint,
  bigserial,
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

const id = () => uuid('id').primaryKey().default(sql`gen_random_uuid()`);
const createdAt = () => timestamp('created_at', { withTimezone: true }).notNull().defaultNow();

/* ---------- People and teams ---------- */

export const users = pgTable(
  'users',
  {
    id: id(),
    email: text('email').notNull(),
    name: text('name').notNull(),
    passwordHash: text('password_hash').notNull(),
    emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),
    /** Authenticator secret, sealed (lib/secret-box). Set once 2FA is turned on. */
    twoFactorSecret: text('two_factor_secret'),
    /** A secret being set up: replaced by twoFactorSecret once the first code is confirmed. */
    twoFactorPendingSecret: text('two_factor_pending_secret'),
    twoFactorEnabledAt: timestamp('two_factor_enabled_at', { withTimezone: true }),
    /** The time step of the last code accepted, so a code can't be used twice. */
    twoFactorLastStep: bigint('two_factor_last_step', { mode: 'number' }),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('users_email_key').on(sql`lower(${t.email})`)],
);

/** One-time recovery codes for when the phone with the authenticator is lost. Only hashes are kept. */
export const recoveryCodes = pgTable(
  'recovery_codes',
  {
    id: id(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    codeHash: text('code_hash').notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [index('recovery_codes_user_idx').on(t.userId)],
);

/** A password that was right, waiting for its authenticator code. Five minutes and five tries. */
export const loginChallenges = pgTable(
  'login_challenges',
  {
    id: id(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    tokenHash: text('token_hash').notNull(),
    attempts: integer('attempts').notNull().default(0),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('login_challenges_token_hash_key').on(t.tokenHash)],
);

export const sessions = pgTable(
  'sessions',
  {
    id: id(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    tokenHash: text('token_hash').notNull(),
    ip: text('ip'),
    userAgent: text('user_agent'),
    createdAt: createdAt(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (t) => [uniqueIndex('sessions_token_hash_key').on(t.tokenHash), index('sessions_user_idx').on(t.userId)],
);

export const organizations = pgTable(
  'organizations',
  {
    id: id(),
    name: text('name').notNull(),
    slug: text('slug').notNull(),
    plan: text('plan').notNull().default('free'),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('organizations_slug_key').on(t.slug)],
);

export const memberships = pgTable(
  'memberships',
  {
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: text('role').notNull(),
    createdAt: createdAt(),
  },
  (t) => [primaryKey({ columns: [t.orgId, t.userId] }), index('memberships_user_idx').on(t.userId)],
);

/* ---------- Projects and CLI keys ---------- */

export const projects = pgTable(
  'projects',
  {
    id: id(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    slug: text('slug').notNull(),
    repoUrl: text('repo_url'),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('projects_org_slug_key').on(t.orgId, t.slug)],
);

export const projectTokens = pgTable(
  'project_tokens',
  {
    id: id(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    /** First characters of the key, safe to display. */
    tokenPrefix: text('token_prefix').notNull(),
    /** SHA-256 of the full key. The key itself is shown once and never stored. */
    tokenHash: text('token_hash').notNull(),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [uniqueIndex('project_tokens_hash_key').on(t.tokenHash), index('project_tokens_project_idx').on(t.projectId)],
);

/* ---------- Staging targets for running-app (DAST) tests ---------- */

export const targets = pgTable(
  'targets',
  {
    id: id(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    /** Origin only, e.g. https://staging.paywave.ng */
    url: text('url').notNull(),
    hostname: text('hostname').notNull(),
    environment: text('environment').notNull(),
    label: text('label'),
    /** Value expected in the TXT record at _fortis-verify.<hostname>. */
    verificationToken: text('verification_token').notNull(),
    verifiedAt: timestamp('verified_at', { withTimezone: true }),
    lastVerificationError: text('last_verification_error'),
    authorizedBy: uuid('authorized_by').references(() => users.id, { onDelete: 'set null' }),
    authorizedSigner: text('authorized_signer'),
    authorizationVersion: text('authorization_version'),
    authorizedAt: timestamp('authorized_at', { withTimezone: true }),
    /** Kill switch: while set, no tests may run or upload. */
    pausedAt: timestamp('paused_at', { withTimezone: true }),
    lastRunAt: timestamp('last_run_at', { withTimezone: true }),
    /** Exposure checks on a schedule: off, daily or weekly. Runs only while the target is ready. */
    exposureSchedule: text('exposure_schedule').notNull().default('off'),
    /** When the last exposure check ran, scheduled or by hand. */
    exposureCheckedAt: timestamp('exposure_checked_at', { withTimezone: true }),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('targets_project_url_key').on(t.projectId, t.url), index('targets_org_idx').on(t.orgId)],
);

/* ---------- Scans and findings ---------- */

export const scans = pgTable(
  'scans',
  {
    id: id(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    tokenId: uuid('token_id').references(() => projectTokens.id, { onDelete: 'set null' }),
    clientScanId: uuid('client_scan_id').notNull(),
    trigger: text('trigger').notNull(),
    kind: text('kind').notNull().default('code'),
    targetId: uuid('target_id').references(() => targets.id, { onDelete: 'set null' }),
    dastMode: text('dast_mode'),
    scope: text('scope').notNull(),
    commit: text('commit'),
    branch: text('branch'),
    cliVersion: text('cli_version').notNull(),
    rulesVersion: text('rules_version'),
    durationMs: integer('duration_ms'),
    filesScanned: integer('files_scanned'),
    /** Release gate verdict for this scan: passed, failed or excepted. Null when no gate applied. */
    gateStatus: text('gate_status'),
    /** What the gate decided on: the blocking findings and any approved exception. */
    gateDetail: jsonb('gate_detail'),
    findingsCount: integer('findings_count').notNull().default(0),
    newCount: integer('new_count').notNull().default(0),
    reopenedCount: integer('reopened_count').notNull().default(0),
    fixedCount: integer('fixed_count').notNull().default(0),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex('scans_project_client_key').on(t.projectId, t.clientScanId),
    index('scans_org_created_idx').on(t.orgId, t.createdAt),
  ],
);

export const findings = pgTable(
  'findings',
  {
    id: id(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    fingerprint: text('fingerprint').notNull(),
    kind: text('kind').notNull().default('code'),
    targetId: uuid('target_id').references(() => targets.id, { onDelete: 'cascade' }),
    ruleId: text('rule_id').notNull(),
    severity: text('severity').notNull(),
    title: text('title').notNull(),
    file: text('file').notNull(),
    line: integer('line'),
    snippet: text('snippet'),
    detail: text('detail'),
    /** Secret findings: live, revoked or unknown, from the last `fortis scan --verify`. Null when never checked. */
    secretStatus: text('secret_status'),
    secretCheckedAt: timestamp('secret_checked_at', { withTimezone: true }),
    status: text('status').notNull().default('open'),
    statusReason: text('status_reason'),
    firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
    fixedAt: timestamp('fixed_at', { withTimezone: true }),
    /** When an alert went out for this finding. Cleared when it reopens, so a reopened finding alerts again. */
    alertedAt: timestamp('alerted_at', { withTimezone: true }),
    firstScanId: uuid('first_scan_id').references(() => scans.id, { onDelete: 'set null' }),
    lastScanId: uuid('last_scan_id').references(() => scans.id, { onDelete: 'set null' }),
  },
  (t) => [
    uniqueIndex('findings_project_fingerprint_key').on(t.projectId, t.fingerprint),
    index('findings_org_status_idx').on(t.orgId, t.status),
  ],
);

/** The trail that becomes the evidence pack: detected, fixed, reopened, status changes. */
export const findingEvents = pgTable(
  'finding_events',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    findingId: uuid('finding_id')
      .notNull()
      .references(() => findings.id, { onDelete: 'cascade' }),
    type: text('type').notNull(),
    fromStatus: text('from_status'),
    toStatus: text('to_status'),
    scanId: uuid('scan_id').references(() => scans.id, { onDelete: 'set null' }),
    actorUserId: uuid('actor_user_id').references(() => users.id, { onDelete: 'set null' }),
    reason: text('reason'),
    createdAt: createdAt(),
  },
  (t) => [index('finding_events_finding_idx').on(t.findingId, t.createdAt)],
);

export const auditLog = pgTable(
  'audit_log',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    orgId: uuid('org_id').references(() => organizations.id, { onDelete: 'cascade' }),
    actorUserId: uuid('actor_user_id').references(() => users.id, { onDelete: 'set null' }),
    action: text('action').notNull(),
    targetType: text('target_type'),
    targetId: text('target_id'),
    meta: jsonb('meta'),
    ip: text('ip'),
    createdAt: createdAt(),
  },
  (t) => [index('audit_log_org_created_idx').on(t.orgId, t.createdAt)],
);

/** Where a workspace's alerts go when a scan finds something serious. No row means the defaults. */
export const alertSettings = pgTable('alert_settings', {
  orgId: uuid('org_id')
    .primaryKey()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  emailEnabled: boolean('email_enabled').notNull().default(true),
  /** 'admins' (owners and admins) or 'everyone' in the workspace. */
  emailTo: text('email_to').notNull().default('admins'),
  /** 'critical', or 'high' for critical and high. */
  minSeverity: text('min_severity').notNull().default('high'),
  /** Slack incoming-webhook URL, sealed (lib/secret-box): it lets anyone post to the channel. */
  slackWebhook: text('slack_webhook'),
  lastSentAt: timestamp('last_sent_at', { withTimezone: true }),
  /** The last delivery problem, shown in Settings until a delivery succeeds. */
  lastError: text('last_error'),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

/** A project's release gate: what stops a CI run on Plus and Enterprise. No row means no gate. */
export const releaseGates = pgTable('release_gates', {
  projectId: uuid('project_id')
    .primaryKey()
    .references(() => projects.id, { onDelete: 'cascade' }),
  orgId: uuid('org_id')
    .notNull()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  enabled: boolean('enabled').notNull().default(false),
  /** 'critical', 'high' (and above) or 'medium' (and above). */
  minSeverity: text('min_severity').notNull().default('critical'),
  /** A leaked key that `fortis scan --verify` found still working blocks whatever its severity. */
  blockLiveSecrets: boolean('block_live_secrets').notNull().default(true),
  /** Comma-separated branch patterns (`main, release/*`). Empty: every branch. */
  branches: text('branches').notNull().default(''),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

/** An admin's approval to release through a failing gate: a reason, an expiry and optionally one commit. */
export const gateExceptions = pgTable(
  'gate_exceptions',
  {
    id: id(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    commit: text('commit'),
    reason: text('reason').notNull(),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  },
  (t) => [index('gate_exceptions_project_idx').on(t.projectId, t.expiresAt)],
);

/* ---------- Billing (Paystack, naira) ---------- */

/**
 * A workspace's paid plan. One row per workspace, created by its first payment. `organizations.plan`
 * stays the source of truth for what's unlocked; this row says how long it's paid for and how it renews.
 */
export const billingSubscriptions = pgTable(
  'billing_subscriptions',
  {
    orgId: uuid('org_id')
      .primaryKey()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    plan: text('plan').notNull(),
    /** 'active', 'past_due' (in the grace period) or 'ended' (stepped down to Free). */
    status: text('status').notNull(),
    currentPeriodStart: timestamp('current_period_start', { withTimezone: true }).notNull(),
    currentPeriodEnd: timestamp('current_period_end', { withTimezone: true }).notNull(),
    cancelAtPeriodEnd: boolean('cancel_at_period_end').notNull().default(false),
    /** A cheaper plan that starts at the next renewal. */
    nextPlan: text('next_plan'),
    /** Paystack's reusable card authorization, sealed (lib/secret-box). Null: renew by paying again. */
    authorization: text('authorization'),
    cardBrand: text('card_brand'),
    cardLast4: text('card_last4'),
    cardExp: text('card_exp'),
    billingEmail: text('billing_email').notNull(),
    graceEndsAt: timestamp('grace_ends_at', { withTimezone: true }),
    failedAttempts: integer('failed_attempts').notNull().default(0),
    lastAttemptAt: timestamp('last_attempt_at', { withTimezone: true }),
    reminderSentAt: timestamp('reminder_sent_at', { withTimezone: true }),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('billing_subscriptions_due_idx').on(t.status, t.currentPeriodEnd)],
);

/** Every payment Fortis asked for: a checkout, an upgrade or a renewal. The reference is ours and unique. */
export const billingPayments = pgTable(
  'billing_payments',
  {
    id: id(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    reference: text('reference').notNull(),
    /** 'checkout' (new plan, a new month starts), 'upgrade' (credit for unused days) or 'renewal'. */
    kind: text('kind').notNull(),
    plan: text('plan').notNull(),
    amountKobo: bigint('amount_kobo', { mode: 'number' }).notNull(),
    vatKobo: bigint('vat_kobo', { mode: 'number' }).notNull().default(0),
    /** 'pending', 'success', 'failed' or 'abandoned'. */
    status: text('status').notNull().default('pending'),
    channel: text('channel'),
    failureReason: text('failure_reason'),
    periodStart: timestamp('period_start', { withTimezone: true }),
    periodEnd: timestamp('period_end', { withTimezone: true }),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    paidAt: timestamp('paid_at', { withTimezone: true }),
    receiptSentAt: timestamp('receipt_sent_at', { withTimezone: true }),
  },
  (t) => [uniqueIndex('billing_payments_reference_key').on(t.reference), index('billing_payments_org_idx').on(t.orgId, t.createdAt)],
);

/** Paystack webhook events already handled, so a redelivered event changes nothing. */
export const billingEvents = pgTable(
  'billing_events',
  {
    id: id(),
    eventKey: text('event_key').notNull(),
    type: text('type').notNull(),
    reference: text('reference'),
    receivedAt: timestamp('received_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('billing_events_key').on(t.eventKey)],
);
