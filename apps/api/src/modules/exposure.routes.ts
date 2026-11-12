import { randomUUID } from 'node:crypto';

import { and, desc, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { db } from '../db/client';
import { findings, scans, targets } from '../db/schema';
import { audit } from '../lib/audit';
import { badRequest, notFound, paymentRequired } from '../lib/errors';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';
import { ExposureError, exposureFindings, probeHost, SERVICES, type ProbeOptions } from './exposure.service';
import { ingestScan } from './ingest.service';
import { planLimits } from './orgs.routes';
import { targetStatus } from './targets.routes';

const params = z.object({ orgId: z.string().uuid(), projectId: z.string().uuid(), targetId: z.string().uuid() });

/** Probe settings, swappable in tests so they can use local fake services. */
let probeOptions: ProbeOptions = {};
export function setExposureProbeOptions(opts: ProbeOptions | null) {
  probeOptions = opts ?? {};
}

async function loadTarget(orgId: string, projectId: string, targetId: string) {
  const [row] = await db
    .select()
    .from(targets)
    .where(and(eq(targets.id, targetId), eq(targets.projectId, projectId), eq(targets.orgId, orgId)))
    .limit(1);
  if (!row) throw notFound('Target not found.');
  return row;
}

/**
 * Exposure checks: from Fortis's servers, which admin and database ports a verified target's domain
 * answers on, and whether any of them answer without a password. Same safeguards as running-app
 * tests: the domain is proven with a TXT record, testing is authorised in writing, and a paused
 * target is never touched.
 */
export async function exposureRoutes(app: FastifyInstance) {
  const base = '/v1/orgs/:orgId/projects/:projectId/targets/:targetId/exposure';

  app.post(base, { config: { rateLimit: { max: 6, timeWindow: '1 hour' } } }, async (req) => {
    const { orgId, projectId, targetId } = parse(params, req.params);
    const { org } = await requireOrgRole(req, orgId, 'developer');
    if (planLimits(org.plan).dast === 'none') throw paymentRequired('Exposure checks come with running-app tests, on Fortis Core and above.', 'PLAN_EXPOSURE');
    const target = await loadTarget(orgId, projectId, targetId);
    const status = targetStatus(target);
    if (status !== 'ready') {
      const why = status === 'paused' ? 'This target is paused.' : status === 'unverified' ? 'Verify the domain first.' : 'Authorise testing for this target first.';
      throw badRequest(`${why} Exposure checks only run on verified, authorised targets.`, 'TARGET_NOT_READY');
    }

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
      { orgId, projectId, tokenId: null },
      {
        scanId: randomUUID(),
        trigger: 'manual',
        kind: 'exposure',
        targetId,
        scope: 'full',
        cliVersion: 'server',
        durationMs: Date.now() - started,
        filesScanned: probe.results.length,
        findings: found.map((f) => ({ ruleId: f.ruleId, severity: f.severity, title: f.title, file: f.file, snippet: f.snippet, detail: f.detail })),
      },
    );
    await audit(db, req, { orgId, action: 'target.exposure_checked', targetType: 'target', targetId, meta: { addresses: probe.addresses, open: probe.results.filter((r) => r.open).length } });
    return {
      scanId: result.scanId,
      hostname: target.hostname,
      addresses: probe.addresses,
      refused: probe.refused,
      checked: SERVICES.length,
      pages: probe.pages.map((p) => ({ url: p.url, what: p.check.what, severity: p.check.severity })),
      open: probe.results.filter((r) => r.open).map((r) => ({ ip: r.ip, port: r.port, service: r.service, noAuth: r.noAuth ?? null, banner: r.banner ?? null })),
      findings: found,
      newCount: result.newCount,
      fixedCount: result.fixedCount,
    };
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
      services: SERVICES.map((s) => ({ port: s.port, name: s.name })),
      lastScan: last ? { id: last.id, at: last.createdAt, durationMs: last.durationMs, findings: last.findingsCount, fixed: last.fixedCount } : null,
      findings: open,
    };
  });
}
