import { randomUUID, timingSafeEqual } from 'node:crypto';

import { and, asc, desc, eq, isNull, lt, ne, or } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { env } from '../config/env';
import { db } from '../db/client';
import { findings, organizations, scans, targets } from '../db/schema';
import { audit } from '../lib/audit';
import { AppError, badRequest, notFound, paymentRequired } from '../lib/errors';
import { parse } from '../lib/validate';
import { authenticateCli, requireOrgRole } from '../plugins/auth';
import { ExposureError, exposureFindings, probeHost, SERVICES, type ProbeOptions } from './exposure.service';
import { ingestScan } from './ingest.service';
import { planLimits } from './orgs.routes';
import { targetStatus } from './targets.routes';

const params = z.object({ orgId: z.string().uuid(), projectId: z.string().uuid(), targetId: z.string().uuid() });
export const SCHEDULES = ['off', 'daily', 'weekly'] as const;
const scheduleSchema = z.object({ schedule: z.enum(SCHEDULES) });

/** How long after a check the next scheduled one is due. A little under the period, so a daily cron never skips a day. */
const DUE_AFTER_MS: Record<Exclude<(typeof SCHEDULES)[number], 'off'>, number> = { daily: 20 * 3600_000, weekly: 6.5 * 86_400_000 };
/** Scheduled checks per cron call, so one call stays well inside a request timeout. */
const MAX_PER_RUN = 25;

/** Probe settings, swappable in tests so they can use local fake services. */
let probeOptions: ProbeOptions = {};
export function setExposureProbeOptions(opts: ProbeOptions | null) {
  probeOptions = opts ?? {};
}

type TargetRow = typeof targets.$inferSelect;

async function loadTarget(orgId: string, projectId: string, targetId: string) {
  const [row] = await db
    .select()
    .from(targets)
    .where(and(eq(targets.id, targetId), eq(targets.projectId, projectId), eq(targets.orgId, orgId)))
    .limit(1);
  if (!row) throw notFound('Target not found.');
  return row;
}

/** Every safeguard, checked the same way whoever asks: plan, verified domain, signed authorisation, not paused. */
function assertRunnable(target: TargetRow, plan: string) {
  if (planLimits(plan).dast === 'none') throw paymentRequired('Exposure checks come with running-app tests, on Fortis Core and above.', 'PLAN_EXPOSURE');
  const status = targetStatus(target);
  if (status !== 'ready') {
    const why = status === 'paused' ? 'This target is paused.' : status === 'unverified' ? 'Verify the domain first.' : 'Authorise testing for this target first.';
    throw badRequest(`${why} Exposure checks only run on verified, authorised targets.`, 'TARGET_NOT_READY');
  }
}

/** Run one exposure check and record it. Shared by the dashboard, the schedule and the CLI. */
export async function runExposure(req: FastifyRequest, target: TargetRow, how: { trigger: 'manual' | 'ci' | 'schedule'; by: string }) {
  const started = Date.now();
  let probe: Awaited<ReturnType<typeof probeHost>>;
  try {
    probe = await probeHost(target.hostname, probeOptions);
  } catch (e) {
    if (e instanceof ExposureError) throw badRequest(e.message, e.code);
    throw e;
  }
  const found = exposureFindings(target.hostname, probe.results, probe.pages);
  const result = await ingestScan(
    { orgId: target.orgId, projectId: target.projectId, tokenId: null },
    {
      scanId: randomUUID(),
      trigger: how.trigger,
      kind: 'exposure',
      targetId: target.id,
      scope: 'full',
      cliVersion: 'server',
      durationMs: Date.now() - started,
      filesScanned: probe.results.length,
      findings: found.map((f) => ({ ruleId: f.ruleId, severity: f.severity, title: f.title, file: f.file, snippet: f.snippet, detail: f.detail })),
    },
  );
  await db.update(targets).set({ exposureCheckedAt: new Date() }).where(eq(targets.id, target.id));
  await audit(db, req, {
    orgId: target.orgId,
    action: 'target.exposure_checked',
    targetType: 'target',
    targetId: target.id,
    meta: { by: how.by, trigger: how.trigger, addresses: probe.addresses, open: probe.results.filter((r) => r.open).length, pages: probe.pages.length },
  });
  return {
    scanId: result.scanId,
    hostname: target.hostname,
    url: target.url,
    addresses: probe.addresses,
    refused: probe.refused,
    checked: SERVICES.length,
    pages: probe.pages.map((p) => ({ url: p.url, what: p.check.what, severity: p.check.severity })),
    open: probe.results.filter((r) => r.open).map((r) => ({ ip: r.ip, port: r.port, service: r.service, noAuth: r.noAuth ?? null, banner: r.banner ?? null })),
    findings: found,
    newCount: result.newCount,
    fixedCount: result.fixedCount,
  };
}

/** Constant-time comparison of the cron secret. */
function cronAllowed(req: FastifyRequest): boolean {
  const secret = env.CRON_SECRET;
  const given = req.headers['x-fortis-cron'];
  if (!secret || typeof given !== 'string') return false;
  const a = Buffer.from(given);
  const b = Buffer.from(secret);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Exposure checks: from Fortis's servers, which admin and database ports, admin pages and secret
 * files a verified target's domain exposes. Same safeguards as running-app tests: the domain is
 * proven with a TXT record, testing is authorised in writing, and a paused target is never touched.
 */
export async function exposureRoutes(app: FastifyInstance) {
  const base = '/v1/orgs/:orgId/projects/:projectId/targets/:targetId/exposure';

  app.post(base, { config: { rateLimit: { max: 6, timeWindow: '1 hour' } } }, async (req) => {
    const { orgId, projectId, targetId } = parse(params, req.params);
    const { org, user } = await requireOrgRole(req, orgId, 'developer');
    const target = await loadTarget(orgId, projectId, targetId);
    assertRunnable(target, org.plan);
    return runExposure(req, target, { trigger: 'manual', by: `user:${user.id}` });
  });

  app.get(base, async (req) => {
    const { orgId, projectId, targetId } = parse(params, req.params);
    await requireOrgRole(req, orgId, 'viewer');
    const target = await loadTarget(orgId, projectId, targetId);
    const [last] = await db
      .select()
      .from(scans)
      .where(and(eq(scans.targetId, target.id), eq(scans.kind, 'exposure')))
      .orderBy(desc(scans.createdAt))
      .limit(1);
    const open = await db
      .select({ id: findings.id, ruleId: findings.ruleId, severity: findings.severity, title: findings.title, file: findings.file, detail: findings.detail, firstSeenAt: findings.firstSeenAt })
      .from(findings)
      .where(and(eq(findings.targetId, target.id), eq(findings.kind, 'exposure'), eq(findings.status, 'open')))
      .orderBy(desc(findings.firstSeenAt));
    return {
      hostname: target.hostname,
      schedule: target.exposureSchedule,
      services: SERVICES.map((s) => ({ port: s.port, name: s.name })),
      lastScan: last ? { id: last.id, at: last.createdAt, durationMs: last.durationMs, findings: last.findingsCount, fixed: last.fixedCount, trigger: last.trigger } : null,
      findings: open,
    };
  });

  /** Turn scheduled checks on or off for a target. */
  app.put(`${base}/schedule`, async (req) => {
    const { orgId, projectId, targetId } = parse(params, req.params);
    const { org } = await requireOrgRole(req, orgId, 'admin');
    const { schedule } = parse(scheduleSchema, req.body);
    const target = await loadTarget(orgId, projectId, targetId);
    if (schedule !== 'off' && planLimits(org.plan).dast === 'none') throw paymentRequired('Exposure checks come with running-app tests, on Fortis Core and above.', 'PLAN_EXPOSURE');
    await db.update(targets).set({ exposureSchedule: schedule }).where(eq(targets.id, target.id));
    await audit(db, req, { orgId, action: 'target.exposure_schedule', targetType: 'target', targetId, meta: { schedule } });
    return { schedule };
  });

  /**
   * Runs the scheduled checks that are due. Called by a cron (GitHub Actions, Render cron) with the
   * shared CRON_SECRET; never by browsers. Each target still has to pass every safeguard.
   */
  app.post('/v1/internal/exposure/run-due', { config: { rateLimit: { max: 30, timeWindow: '1 hour' } } }, async (req, reply) => {
    if (!cronAllowed(req)) return reply.code(env.CRON_SECRET ? 401 : 404).send({ error: { code: 'UNAUTHORIZED', message: 'Not allowed.' } });
    const now = Date.now();
    const rows = await db
      .select({ t: targets, plan: organizations.plan })
      .from(targets)
      .innerJoin(organizations, eq(organizations.id, targets.orgId))
      .where(
        and(
          ne(targets.exposureSchedule, 'off'),
          isNull(targets.pausedAt),
          or(isNull(targets.exposureCheckedAt), lt(targets.exposureCheckedAt, new Date(now - DUE_AFTER_MS.daily))),
        ),
      )
      .orderBy(asc(targets.exposureCheckedAt))
      .limit(MAX_PER_RUN * 4);
    const due = rows.filter(({ t }) => {
      const after = DUE_AFTER_MS[t.exposureSchedule as keyof typeof DUE_AFTER_MS];
      return after !== undefined && (!t.exposureCheckedAt || now - t.exposureCheckedAt.getTime() >= after);
    });
    const ran: { targetId: string; hostname: string; findings: number; newCount: number; fixedCount: number }[] = [];
    const skipped: { targetId: string; reason: string }[] = [];
    for (const { t, plan } of due.slice(0, MAX_PER_RUN)) {
      try {
        assertRunnable(t, plan);
        const r = await runExposure(req, t, { trigger: 'schedule', by: 'schedule' });
        ran.push({ targetId: t.id, hostname: t.hostname, findings: r.findings.length, newCount: r.newCount, fixedCount: r.fixedCount });
      } catch (e) {
        // Record the attempt so a broken target doesn't hold up the queue every run.
        await db.update(targets).set({ exposureCheckedAt: new Date() }).where(eq(targets.id, t.id));
        skipped.push({ targetId: t.id, reason: e instanceof AppError ? e.code : 'ERROR' });
      }
    }
    return { due: due.length, ran, skipped, remaining: Math.max(0, due.length - MAX_PER_RUN) };
  });

  /** `fortis exposure`: the same check, with a project key, for CI. */
  app.post('/v1/cli/exposure', { config: { rateLimit: { max: 10, timeWindow: '1 hour' } } }, async (req) => {
    const auth = await authenticateCli(req);
    const { url } = parse(z.object({ url: z.string().url().max(500).optional() }), req.body ?? {});
    const rows = await db.select().from(targets).where(and(eq(targets.projectId, auth.projectId), eq(targets.orgId, auth.orgId)));
    let target: TargetRow | undefined;
    if (url) {
      const origin = new URL(url).origin.toLowerCase();
      target = rows.find((t) => t.url.toLowerCase() === origin);
      if (!target) throw notFound(`${origin} isn't a target of ${auth.projectName}. Add and verify it in the dashboard first.`);
    } else {
      const ready = rows.filter((t) => targetStatus(t) === 'ready');
      if (ready.length !== 1) {
        throw badRequest(
          ready.length ? `${auth.projectName} has ${ready.length} ready targets; choose one with --target (${ready.map((t) => t.url).join(', ')}).` : `${auth.projectName} has no ready target. Add one, verify its domain and authorise testing in the dashboard.`,
          'TARGET_REQUIRED',
        );
      }
      target = ready[0]!;
    }
    assertRunnable(target, auth.plan);
    return runExposure(req, target, { trigger: 'ci', by: `key:${auth.tokenId}` });
  });
}
