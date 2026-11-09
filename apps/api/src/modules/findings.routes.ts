import { and, asc, desc, eq, sql, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { FINDING_STATUSES, findRule, RULE_CATALOG, SEVERITIES, updateFindingSchema } from '@fortis/shared';

import { db } from '../db/client';
import { auditLog, findingEvents, findings, projects, scans, users } from '../db/schema';
import { audit } from '../lib/audit';
import { sha256 } from '../lib/crypto';
import { notFound, paymentRequired } from '../lib/errors';
import { planLimits } from './orgs.routes';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';

const orgParams = z.object({ orgId: z.string().uuid() });
const findingParams = orgParams.extend({ findingId: z.string().uuid() });

const listQuery = z.object({
  projectId: z.string().uuid().optional(),
  status: z.enum(FINDING_STATUSES).optional(),
  severity: z.enum(SEVERITIES).optional(),
  q: z.string().trim().max(100).optional(),
  kind: z.enum(['code', 'dast', 'access']).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(100_000).default(0),
});

/** Code findings marked as false positives, for the benchmark. See scripts/false-positive-shapes.ts. */
export const falsePositiveSql = sql`
  select rule_id as "ruleId", file, snippet, org_id as "orgId"
  from findings
  where status = 'false_positive' and kind = 'code' and snippet is not null
`;

export const ruleHealthSql = sql`
  select rule_id as "ruleId",
    count(*)::int as total,
    count(*) filter (where status = 'open')::int as open,
    count(*) filter (where status = 'fixed')::int as fixed,
    count(*) filter (where status = 'accepted_risk')::int as "acceptedRisk",
    count(*) filter (where status = 'false_positive')::int as "falsePositive"
  from findings`;

export type RuleHealthRow = { ruleId: string; total: number; open: number; fixed: number; acceptedRisk: number; falsePositive: number };

/** Share of triaged findings (anything no longer open) that people marked false positive. */
export function presentHealth(r: RuleHealthRow) {
  const triaged = r.total - r.open;
  return { ...r, triaged, falsePositiveRate: triaged ? Math.round((r.falsePositive / triaged) * 1000) / 1000 : null };
}

const severityOrder = sql`case ${findings.severity} when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end`;

export async function findingsRoutes(app: FastifyInstance) {
  app.get('/v1/rules', async () => ({ rules: RULE_CATALOG }));

  /**
   * Rule health: how this team triaged each rule's findings. A high false-positive share means
   * the rule is noisy for this codebase, which is what we tune next.
   */
  app.get('/v1/orgs/:orgId/rules/health', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const rows = await db.execute(sql`${ruleHealthSql} where org_id = ${orgId} group by rule_id order by rule_id`);
    return { rules: (rows.rows as RuleHealthRow[]).map(presentHealth) };
  });

  app.get('/v1/orgs/:orgId/findings', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const q = parse(listQuery, req.query);
    const where: SQL[] = [eq(findings.orgId, orgId)];
    if (q.projectId) where.push(eq(findings.projectId, q.projectId));
    if (q.status) where.push(eq(findings.status, q.status));
    if (q.severity) where.push(eq(findings.severity, q.severity));
    if (q.kind) where.push(eq(findings.kind, q.kind));
    if (q.q) {
      const like = `%${q.q.replace(/[%_\\]/g, (c) => `\\${c}`)}%`;
      where.push(sql`(${findings.title} ilike ${like} or ${findings.file} ilike ${like} or ${findings.ruleId} ilike ${like})`);
    }
    const [rows, [total]] = await Promise.all([
      db
        .select({
          id: findings.id,
          projectId: findings.projectId,
          projectName: projects.name,
          ruleId: findings.ruleId,
          kind: findings.kind,
          targetId: findings.targetId,
          severity: findings.severity,
          title: findings.title,
          file: findings.file,
          line: findings.line,
          status: findings.status,
          secretStatus: findings.secretStatus,
          firstSeenAt: findings.firstSeenAt,
          lastSeenAt: findings.lastSeenAt,
          fixedAt: findings.fixedAt,
        })
        .from(findings)
        .innerJoin(projects, eq(projects.id, findings.projectId))
        .where(and(...where))
        .orderBy(desc(severityOrder), desc(findings.lastSeenAt))
        .limit(q.limit)
        .offset(q.offset),
      db.select({ n: sql<number>`count(*)::int` }).from(findings).where(and(...where)),
    ]);
    return { findings: rows, total: total?.n ?? 0, limit: q.limit, offset: q.offset };
  });

  app.get('/v1/orgs/:orgId/findings/:findingId', async (req) => {
    const { orgId, findingId } = parse(findingParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const [finding] = await db
      .select({ finding: findings, projectName: projects.name })
      .from(findings)
      .innerJoin(projects, eq(projects.id, findings.projectId))
      .where(and(eq(findings.id, findingId), eq(findings.orgId, orgId)))
      .limit(1);
    if (!finding) throw notFound('Finding not found.');
    const events = await db
      .select({
        id: findingEvents.id,
        type: findingEvents.type,
        fromStatus: findingEvents.fromStatus,
        toStatus: findingEvents.toStatus,
        reason: findingEvents.reason,
        scanId: findingEvents.scanId,
        actor: users.name,
        createdAt: findingEvents.createdAt,
      })
      .from(findingEvents)
      .leftJoin(users, eq(users.id, findingEvents.actorUserId))
      .where(eq(findingEvents.findingId, findingId))
      .orderBy(asc(findingEvents.createdAt), asc(findingEvents.id));
    return {
      finding: { ...finding.finding, projectName: finding.projectName },
      rule: findRule(finding.finding.ruleId) ?? null,
      events,
    };
  });

  app.patch('/v1/orgs/:orgId/findings/:findingId', async (req) => {
    const { orgId, findingId } = parse(findingParams, req.params);
    const { user } = await requireOrgRole(req, orgId, 'developer');
    const input = parse(updateFindingSchema, req.body);
    return db.transaction(async (tx) => {
      const [current] = await tx
        .select({ status: findings.status })
        .from(findings)
        .where(and(eq(findings.id, findingId), eq(findings.orgId, orgId)))
        .for('update')
        .limit(1);
      if (!current) throw notFound('Finding not found.');
      const [updated] = await tx
        .update(findings)
        .set({
          status: input.status,
          statusReason: input.reason ?? null,
          fixedAt: input.status === 'fixed' ? new Date() : null,
        })
        .where(eq(findings.id, findingId))
        .returning();
      await tx.insert(findingEvents).values({
        orgId,
        findingId,
        type: 'status_changed',
        fromStatus: current.status,
        toStatus: input.status,
        actorUserId: user.id,
        reason: input.reason ?? null,
      });
      await audit(tx, req, {
        orgId, action: 'finding.status_changed', targetType: 'finding', targetId: findingId,
        meta: { from: current.status, to: input.status },
      });
      return { finding: updated };
    });
  });

  app.get('/v1/orgs/:orgId/scans', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const q = parse(z.object({ projectId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(100).default(20) }), req.query);
    const where: SQL[] = [eq(scans.orgId, orgId)];
    if (q.projectId) where.push(eq(scans.projectId, q.projectId));
    const rows = await db
      .select({
        id: scans.id,
        projectId: scans.projectId,
        projectName: projects.name,
        trigger: scans.trigger,
        kind: scans.kind,
        dastMode: scans.dastMode,
        scope: scans.scope,
        branch: scans.branch,
        commit: scans.commit,
        findingsCount: scans.findingsCount,
        newCount: scans.newCount,
        fixedCount: scans.fixedCount,
        reopenedCount: scans.reopenedCount,
        durationMs: scans.durationMs,
        createdAt: scans.createdAt,
      })
      .from(scans)
      .innerJoin(projects, eq(projects.id, scans.projectId))
      .where(and(...where))
      .orderBy(desc(scans.createdAt))
      .limit(q.limit);
    return { scans: rows };
  });

  /**
   * Evidence pack for auditors: what was checked, found, fixed and decided in a period, with who
   * decided and why. "basic" (Core) is the summary and findings; "full" (Plus) adds the complete
   * event trail, staging-test authorisations and the admin audit log. A SHA-256 digest of the
   * content lets an auditor confirm the pack was not edited after it was generated.
   */
  app.get('/v1/orgs/:orgId/evidence', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const { org, user } = await requireOrgRole(req, orgId, 'viewer');
    const limits = planLimits(org.plan);
    if (limits.evidencePack === 'none') throw paymentRequired(`${limits.name} does not include evidence packs. Upgrade to Fortis Core.`);
    const q = parse(
      z.object({
        from: z.coerce.date().optional(),
        to: z.coerce.date().optional(),
        projectId: z.string().uuid().optional(),
      }),
      req.query,
    );
    const to = q.to ?? new Date();
    const from = q.from ?? new Date(to.getTime() - 90 * 86_400_000);
    const p = q.projectId ? sql`and f.project_id = ${q.projectId}` : sql``;
    const ps = q.projectId ? sql`and s.project_id = ${q.projectId}` : sql``;
    const full = limits.evidencePack === 'full';

    const [scansBy, open, detected, fixed, fixTimes, list, decisions] = await Promise.all([
      db.execute(sql`select s.kind, s.trigger, count(*)::int as n from scans s where s.org_id = ${orgId} ${ps} and s.created_at between ${from} and ${to} group by 1, 2 order by 1, 2`),
      db.execute(sql`select f.severity, count(*)::int as n from findings f where f.org_id = ${orgId} ${p} and f.status = 'open' group by 1`),
      db.execute(sql`select count(*)::int as n from findings f where f.org_id = ${orgId} ${p} and f.first_seen_at between ${from} and ${to}`),
      db.execute(sql`select count(*)::int as n from findings f where f.org_id = ${orgId} ${p} and f.status = 'fixed' and f.fixed_at between ${from} and ${to}`),
      db.execute(sql`select f.severity, percentile_cont(0.5) within group (order by extract(epoch from f.fixed_at - f.first_seen_at))::float as seconds, count(*)::int as n
        from findings f where f.org_id = ${orgId} ${p} and f.status = 'fixed' and f.fixed_at between ${from} and ${to} group by 1`),
      db.execute(sql`select f.id, f.rule_id as "ruleId", f.kind, f.severity, f.title, f.file, f.line, f.status, f.status_reason as "statusReason",
          f.first_seen_at as "firstSeenAt", f.fixed_at as "fixedAt", pr.name as "projectName"
        from findings f join projects pr on pr.id = f.project_id
        where f.org_id = ${orgId} ${p} and f.first_seen_at <= ${to} and (f.fixed_at is null or f.fixed_at >= ${from})
        order by case f.severity when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end desc, f.first_seen_at
        limit 2000`),
      db.execute(sql`select e.created_at as "at", e.to_status as "decision", e.reason, u.name as "by", f.title, f.rule_id as "ruleId", f.severity
        from finding_events e join findings f on f.id = e.finding_id left join users u on u.id = e.actor_user_id
        where e.org_id = ${orgId} ${p} and e.to_status in ('accepted_risk', 'false_positive') and e.created_at between ${from} and ${to}
        order by e.created_at`),
    ]);

    let trail: unknown[] = [];
    let authorisations: unknown[] = [];
    let adminLog: unknown[] = [];
    if (full) {
      const [ev, tg, al] = await Promise.all([
        db.execute(sql`select e.created_at as "at", e.type, e.from_status as "from", e.to_status as "to", e.reason, u.name as "by", f.rule_id as "ruleId", f.title
          from finding_events e join findings f on f.id = e.finding_id left join users u on u.id = e.actor_user_id
          where e.org_id = ${orgId} ${p} and e.created_at between ${from} and ${to} order by e.created_at, e.id limit 5000`),
        db.execute(sql`select t.url, t.environment, t.verified_at as "verifiedAt", t.authorized_signer as "signer", t.authorization_version as "version",
            t.authorized_at as "authorizedAt", t.paused_at as "pausedAt", t.last_run_at as "lastRunAt", pr.name as "projectName"
          from targets t join projects pr on pr.id = t.project_id where t.org_id = ${orgId} ${q.projectId ? sql`and t.project_id = ${q.projectId}` : sql``} order by t.created_at`),
        db.execute(sql`select a.created_at as "at", a.action, u.name as "by", a.meta from audit_log a left join users u on u.id = a.actor_user_id
          where a.org_id = ${orgId} and a.created_at between ${from} and ${to}
            and (a.action like 'target.%' or a.action like 'token.%' or a.action like 'member.%' or a.action like 'project.%' or a.action = 'plan.changed')
          order by a.created_at limit 2000`),
      ]);
      trail = ev.rows;
      authorisations = tg.rows;
      adminLog = (al.rows as { meta: Record<string, unknown> | null }[]).map((r) => ({ ...r, meta: r.meta ? { ...r.meta, text: undefined } : null }));
    }

    const openBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const r of open.rows as { severity: string; n: number }[]) openBySeverity[r.severity] = r.n;
    const content = {
      organisation: { name: org.name, plan: limits.name },
      period: { from: from.toISOString(), to: to.toISOString() },
      projectId: q.projectId ?? null,
      level: limits.evidencePack,
      generatedAt: new Date().toISOString(),
      generatedBy: user.name,
      summary: {
        scans: scansBy.rows,
        openBySeverity,
        detected: (detected.rows[0] as { n: number }).n,
        fixed: (fixed.rows[0] as { n: number }).n,
        medianFixSeconds: fixTimes.rows,
      },
      findings: list.rows,
      decisions: decisions.rows,
      trail,
      authorisations,
      adminLog,
    };
    return { ...content, digest: sha256(JSON.stringify(content)) };
  });

  /** Numbers for the dashboard home: open by severity, 30-day trend, fix speed, recent scans. */
  app.get('/v1/orgs/:orgId/overview', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const [bySeverity, trend, totals, fixSpeed] = await Promise.all([
      db.execute(sql`select severity, count(*)::int as n from findings where org_id = ${orgId} and status = 'open' group by severity`),
      db.execute(sql`
        with days as (select generate_series(current_date - 29, current_date, interval '1 day')::date as day)
        select to_char(d.day, 'YYYY-MM-DD') as day,
          (select count(*)::int from finding_events e where e.org_id = ${orgId} and e.type in ('detected','reopened') and e.created_at::date = d.day) as detected,
          (select count(*)::int from finding_events e where e.org_id = ${orgId} and e.to_status = 'fixed' and e.created_at::date = d.day) as fixed
        from days d order by d.day`),
      db.execute(sql`
        select
          (select count(*)::int from scans where org_id = ${orgId} and created_at > now() - interval '30 days') as "scans30d",
          (select count(*)::int from scans where org_id = ${orgId} and trigger = 'pre-push' and created_at > now() - interval '30 days') as "prePush30d",
          (select count(*)::int from findings where org_id = ${orgId} and status = 'fixed' and fixed_at > now() - interval '30 days') as "fixed30d",
          (select count(*)::int from projects where org_id = ${orgId}) as projects,
          (select count(*)::int from scans where org_id = ${orgId}) as "scansAllTime",
          (select count(*)::int from project_tokens where org_id = ${orgId} and revoked_at is null) as "activeKeys",
          (select count(*)::int from memberships where org_id = ${orgId}) as members,
          (select count(*)::int from finding_events where org_id = ${orgId} and to_status in ('fixed','accepted_risk','false_positive')) as "resolvedAllTime",
          (select count(*)::int from finding_events where org_id = ${orgId}) as "evidenceEvents",
          (select count(*)::int from scans where org_id = ${orgId} and trigger = 'ci' and created_at > now() - interval '30 days') as "ci30d",
          (select coalesce(sum(new_count), 0)::int from scans where org_id = ${orgId} and trigger = 'pre-push' and created_at > now() - interval '30 days') as "blockedPrePush30d",
          (select count(*)::int from targets where org_id = ${orgId}) as targets,
          (select count(*)::int from targets where org_id = ${orgId} and verified_at is not null and authorized_at is not null and paused_at is null) as "targetsReady",
          (select count(*)::int from scans where org_id = ${orgId} and kind = 'dast' and created_at > now() - interval '30 days') as "dast30d",
          (select count(*)::int from findings where org_id = ${orgId} and kind = 'dast' and status = 'open') as "dastOpen",
          (select extract(day from now() - min(first_seen_at))::int from findings where org_id = ${orgId} and status = 'open' and severity = 'critical') as "oldestOpenCriticalDays"`),
      db.execute(sql`
        select percentile_cont(0.5) within group (order by extract(epoch from (fixed_at - first_seen_at)))::float as seconds
        from findings where org_id = ${orgId} and severity = 'critical' and status = 'fixed' and fixed_at is not null`),
    ]);
    const open: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const r of bySeverity.rows as { severity: string; n: number }[]) open[r.severity] = r.n;
    const seconds = (fixSpeed.rows[0] as { seconds: number | null } | undefined)?.seconds ?? null;
    const recentActivity = await db
      .select({ action: auditLog.action, targetType: auditLog.targetType, createdAt: auditLog.createdAt, actor: users.name })
      .from(auditLog)
      .leftJoin(users, eq(users.id, auditLog.actorUserId))
      .where(eq(auditLog.orgId, orgId))
      .orderBy(desc(auditLog.createdAt))
      .limit(8);
    const byProject = await db.execute(sql`
      select p.id, p.name,
        count(*) filter (where f.severity = 'critical')::int as critical,
        count(*) filter (where f.severity = 'high')::int as high,
        count(*)::int as total,
        min(f.first_seen_at) as "oldestOpenAt"
      from findings f join projects p on p.id = f.project_id
      where f.org_id = ${orgId} and f.status = 'open'
      group by p.id, p.name
      order by critical desc, high desc, total desc
      limit 6`);
    return {
      openByProject: byProject.rows,
      open,
      openTotal: Object.values(open).reduce((a, b) => a + b, 0),
      trend: trend.rows,
      totals: totals.rows[0],
      medianCriticalFixHours: seconds === null ? null : Math.round((seconds / 3600) * 10) / 10,
      recentActivity,
    };
  });

  app.get('/v1/orgs/:orgId/audit', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const rows = await db
      .select({
        id: auditLog.id, action: auditLog.action, targetType: auditLog.targetType, targetId: auditLog.targetId,
        meta: auditLog.meta, ip: auditLog.ip, createdAt: auditLog.createdAt, actor: users.name,
      })
      .from(auditLog)
      .leftJoin(users, eq(users.id, auditLog.actorUserId))
      .where(eq(auditLog.orgId, orgId))
      .orderBy(desc(auditLog.createdAt))
      .limit(100);
    return { entries: rows };
  });
}
