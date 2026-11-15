import { and, desc, eq, gt, inArray, isNull, or, sql } from 'drizzle-orm';

import { db } from '../db/client';
import { findings, gateExceptions, releaseGates, scans, users } from '../db/schema';
import { env } from '../config/env';

/*
 * Release gates (Plus and Enterprise). A project's policy lives in the dashboard; when a CI scan is uploaded,
 * the API judges it against the policy and the CLI exits with that verdict. So changing the policy changes
 * what passes CI, without touching the repository.
 */

export type GateSeverity = 'critical' | 'high' | 'medium';
export type GatePolicy = { enabled: boolean; minSeverity: GateSeverity; blockLiveSecrets: boolean; branches: string };
export const DEFAULT_GATE: GatePolicy = { enabled: false, minSeverity: 'critical', blockLiveSecrets: true, branches: '' };

const AT_OR_ABOVE: Record<GateSeverity, string[]> = {
  critical: ['critical'],
  high: ['critical', 'high'],
  medium: ['critical', 'high', 'medium'],
};

export type GateStatus = 'passed' | 'failed' | 'excepted';
export type GateFinding = { findingId: string; ruleId: string; severity: string; title: string; file: string; line: number | null; liveSecret: boolean };
export type GateDetail = {
  status: GateStatus;
  policy: Pick<GatePolicy, 'minSeverity' | 'blockLiveSecrets'>;
  blockingCount: number;
  blocking: GateFinding[];
  exception?: { id: string; reason: string; by: string | null; expiresAt: string; commit: string | null };
};
/** What the upload response carries. `enforced: false` means the CLI keeps its own --fail-on. */
export type GateResponse = ({ enforced: true } & GateDetail & { manageUrl: string }) | { enforced: false; reason: string };

/** `main, release/*`: `*` matches within one path segment, `**` across segments. A blank list matches every branch. */
export function branchMatches(patterns: string, branch: string | null | undefined): boolean {
  const list = patterns.split(',').map((p) => p.trim()).filter(Boolean);
  if (!list.length) return true;
  if (!branch) return false;
  return list.some((p) => {
    const re = p
      .split('**')
      .map((part) => part.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*'))
      .join('.*');
    return new RegExp(`^${re}$`).test(branch);
  });
}

export async function loadGate(projectId: string): Promise<GatePolicy> {
  const [row] = await db.select().from(releaseGates).where(eq(releaseGates.projectId, projectId)).limit(1);
  if (!row) return { ...DEFAULT_GATE };
  const sev = (['critical', 'high', 'medium'] as const).includes(row.minSeverity as GateSeverity) ? (row.minSeverity as GateSeverity) : 'critical';
  return { enabled: row.enabled, minSeverity: sev, blockLiveSecrets: row.blockLiveSecrets, branches: row.branches };
}

const manageUrl = (projectId: string) => `${env.WEB_URL.replace(/\/+$/, '')}/projects/${projectId}#release-gate`;

/**
 * Judges one uploaded scan. Only CI scans, on a plan with release gates, on a branch the policy covers, are gated;
 * everything else reports `enforced: false` and the CLI keeps its local --fail-on.
 */
export async function evaluateGate(input: {
  orgId: string;
  projectId: string;
  plan: { releaseGates: boolean; name: string };
  scanId: string;
  trigger: string;
  kind: string;
  branch: string | null | undefined;
  commit: string | null | undefined;
  findingIds: string[];
}): Promise<GateResponse> {
  if (!input.plan.releaseGates) return { enforced: false, reason: `${input.plan.name} doesn't include release gates.` };
  if (input.kind !== 'code' || input.trigger !== 'ci') return { enforced: false, reason: 'Release gates apply to CI scans.' };
  const policy = await loadGate(input.projectId);
  if (!policy.enabled) return { enforced: false, reason: 'No release gate is turned on for this project.' };
  if (!branchMatches(policy.branches, input.branch)) return { enforced: false, reason: `The release gate doesn't cover ${input.branch ? `branch ${input.branch}` : 'a detached checkout'}.` };

  const blockingRows = input.findingIds.length
    ? await db
        .select({ findingId: findings.id, ruleId: findings.ruleId, severity: findings.severity, title: findings.title, file: findings.file, line: findings.line, secretStatus: findings.secretStatus })
        .from(findings)
        .where(
          and(
            inArray(findings.id, input.findingIds),
            eq(findings.status, 'open'),
            policy.blockLiveSecrets
              ? or(inArray(findings.severity, AT_OR_ABOVE[policy.minSeverity]), eq(findings.secretStatus, 'live'))
              : inArray(findings.severity, AT_OR_ABOVE[policy.minSeverity]),
          ),
        )
    : [];
  const rank = (s: string) => ({ critical: 0, high: 1, medium: 2, low: 3 })[s] ?? 4;
  const blocking: GateFinding[] = blockingRows
    .map((r) => ({ findingId: r.findingId, ruleId: r.ruleId, severity: r.severity, title: r.title, file: r.file, line: r.line, liveSecret: r.secretStatus === 'live' }))
    .sort((a, b) => Number(b.liveSecret) - Number(a.liveSecret) || rank(a.severity) - rank(b.severity));

  let detail: GateDetail = { status: blocking.length ? 'failed' : 'passed', policy: { minSeverity: policy.minSeverity, blockLiveSecrets: policy.blockLiveSecrets }, blockingCount: blocking.length, blocking: blocking.slice(0, 20) };

  if (blocking.length) {
    const commit = (input.commit ?? '').toLowerCase();
    const candidates = await db
      .select({ id: gateExceptions.id, reason: gateExceptions.reason, commit: gateExceptions.commit, expiresAt: gateExceptions.expiresAt, by: users.name })
      .from(gateExceptions)
      .leftJoin(users, eq(users.id, gateExceptions.createdBy))
      .where(and(eq(gateExceptions.projectId, input.projectId), isNull(gateExceptions.revokedAt), gt(gateExceptions.expiresAt, new Date())))
      .orderBy(desc(gateExceptions.createdAt));
    // An exception for one commit covers it however the SHA is abbreviated.
    const match = candidates.find((e) => !e.commit || (commit && (commit.startsWith(e.commit.toLowerCase()) || e.commit.toLowerCase().startsWith(commit))));
    if (match) {
      await db.update(gateExceptions).set({ lastUsedAt: new Date() }).where(eq(gateExceptions.id, match.id));
      detail = { ...detail, status: 'excepted', exception: { id: match.id, reason: match.reason, by: match.by, expiresAt: match.expiresAt.toISOString(), commit: match.commit } };
    }
  }

  await db.update(scans).set({ gateStatus: detail.status, gateDetail: detail }).where(eq(scans.id, input.scanId));
  return { enforced: true, ...detail, manageUrl: manageUrl(input.projectId) };
}

/** The verdict already stored for a scan, for a retried upload. */
export async function storedGate(scanId: string, projectId: string): Promise<GateResponse | null> {
  const [row] = await db.select({ status: scans.gateStatus, detail: scans.gateDetail }).from(scans).where(eq(scans.id, scanId)).limit(1);
  if (!row?.status || !row.detail) return null;
  return { enforced: true, ...(row.detail as GateDetail), manageUrl: manageUrl(projectId) };
}

/** Recent gate verdicts for a project, newest first. */
export async function recentGateRuns(projectId: string, limit = 15) {
  return db
    .select({ scanId: scans.id, at: scans.createdAt, branch: scans.branch, commit: scans.commit, status: scans.gateStatus, detail: scans.gateDetail })
    .from(scans)
    .where(and(eq(scans.projectId, projectId), sql`${scans.gateStatus} is not null`))
    .orderBy(desc(scans.createdAt))
    .limit(limit);
}
