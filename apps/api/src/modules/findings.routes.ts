import { and, asc, desc, eq, sql, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { FINDING_STATUSES, findRule, RULE_CATALOG, SEVERITIES, updateFindingSchema } from '@fortis/shared';

import { db } from '../db/client';
import { auditLog, findingEvents, findings, projects, scans, users } from '../db/schema';
import { audit } from '../lib/audit';
import { notFound } from '../lib/errors';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';

const orgParams = z.object({ orgId: z.string().uuid() });
const findingParams = orgParams.extend({ findingId: z.string().uuid() });

const listQuery = z.object({
  projectId: z.string().uuid().optional(),
  status: z.enum(FINDING_STATUSES).optional(),
  severity: z.enum(SEVERITIES).optional(),
  q: z.string().trim().max(100).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(100_000).default(0),
});

const severityOrder = sql`case ${findings.severity} when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end`;

export async function findingsRoutes(app: FastifyInstance) {
  app.get('/v1/rules', async () => ({ rules: RULE_CATALOG }));

  app.get('/v1/orgs/:orgId/findings', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const q = parse(listQuery, req.query);
    const where: SQL[] = [eq(findings.orgId, orgId)];
    if (q.projectId) where.push(eq(findings.projectId, q.projectId));
    if (q.status) where.push(eq(findings.status, q.status));
    if (q.severity) where.push(eq(findings.severity, q.severity));
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
          severity: findings.severity,
          title: findings.title,
          file: findings.file,
          line: findings.line,
          status: findings.status,
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
          (select count(*)::int from projects where org_id = ${orgId}) as projects`),
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
    return {
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
