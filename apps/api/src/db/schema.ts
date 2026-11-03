import { sql } from 'drizzle-orm';
import {
  bigserial,
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
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('users_email_key').on(sql`lower(${t.email})`)],
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
    status: text('status').notNull().default('open'),
    statusReason: text('status_reason'),
    firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
    fixedAt: timestamp('fixed_at', { withTimezone: true }),
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
