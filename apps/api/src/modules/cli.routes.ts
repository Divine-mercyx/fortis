import type { FastifyInstance } from 'fastify';

import { and, eq } from 'drizzle-orm';
import { z } from 'zod';

import { cliScanSchema, planAllowsDast, RULE_CATALOG } from '@fortis/shared';

import { db } from '../db/client';
import { targets } from '../db/schema';

import { env } from '../config/env';
import { badRequest, forbidden, notFound, paymentRequired } from '../lib/errors';
import { rulesKeyId, rulesPublicKeyPem, signPayload } from '../lib/rules-signing';
import { parse } from '../lib/validate';
import { authenticateCli } from '../plugins/auth';
import { ingestScan } from './ingest.service';
import { planLimits } from './orgs.routes';
import { normaliseTargetUrl, presentTarget, targetStatus } from './targets.routes';

/** Why a target can't be tested right now, or null when it can. */
function dastBlocker(t: typeof targets.$inferSelect, plan: string, mode: 'baseline' | 'full' | 'access') {
  const limits = planLimits(plan);
  if (mode === 'access') {
    if (!limits.stagingChecks) return `${limits.name} does not include access checks with test users. Upgrade to Fortis Plus.`;
  } else if (!planAllowsDast(limits, mode)) {
    return mode === 'full' && limits.dast === 'baseline'
      ? `${limits.name} includes passive baseline tests. Upgrade to Fortis Plus for full active scans.`
      : `${limits.name} does not include running-app tests. Upgrade to Fortis Core.`;
  }
  const status = targetStatus(t);
  if (status === 'paused') return 'Tests on this target are paused from the dashboard.';
  if (status === 'unverified') return 'Verify the domain with its DNS TXT record in the dashboard first.';
  if (status === 'unauthorized') return 'An admin must authorise testing for this target in the dashboard first.';
  if (mode === 'access' && t.environment === 'production') return 'Access checks use test users, so they run on staging and development targets only.';
  if (mode === 'full' && t.environment === 'production') return 'Active scans are never run against production. Use baseline mode.';
  return null;
}

export const RULES_VERSION = '2026.11.0';
const RULE_PACK_TTL_DAYS = 7;
const cliRateLimit = { rateLimit: { max: 120, timeWindow: '1 minute' } };

export async function cliRoutes(app: FastifyInstance) {
  /** What this key is for and what its plan unlocks. */
  app.get('/v1/cli/whoami', { config: cliRateLimit }, async (req) => {
    const auth = await authenticateCli(req);
    const limits = planLimits(auth.plan);
    return {
      project: { id: auth.projectId, name: auth.projectName },
      org: { id: auth.orgId, name: auth.orgName },
      plan: { id: auth.plan, name: limits.name },
      entitlements: {
        rulePacks: limits.rulePacks,
        uploadFindings: limits.dashboard,
        releaseGates: limits.releaseGates,
        dast: limits.dast,
        accessChecks: limits.stagingChecks,
        blockOn: 'critical',
      },
      rulesVersion: RULES_VERSION,
    };
  });

  /**
   * Signed rule pack for this key's plan. The CLI verifies the signature with the pinned public
   * key and may cache it offline until `expiresAt`.
   */
  app.get('/v1/cli/rules', { config: cliRateLimit }, async (req) => {
    const auth = await authenticateCli(req);
    const limits = planLimits(auth.plan);
    const issuedAt = new Date();
    const payload = {
      version: RULES_VERSION,
      orgId: auth.orgId,
      projectId: auth.projectId,
      plan: auth.plan,
      packs: limits.rulePacks,
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + RULE_PACK_TTL_DAYS * 86_400_000).toISOString(),
      rules: RULE_CATALOG.filter((r) => limits.rulePacks.includes(r.pack)),
    };
    const payloadJson = JSON.stringify(payload);
    return { keyId: rulesKeyId, algorithm: 'ed25519', payload: payloadJson, signature: signPayload(payloadJson) };
  });

  app.get('/v1/cli/rules/public-key', async () => ({ keyId: rulesKeyId, algorithm: 'ed25519', publicKey: rulesPublicKeyPem }));

  /** The project's test targets and whether each can be tested now. `?url=` narrows to one. */
  app.get('/v1/cli/targets', { config: cliRateLimit }, async (req) => {
    const auth = await authenticateCli(req);
    const { url, mode } = parse(
      z.object({ url: z.string().url().max(500).optional(), mode: z.enum(['baseline', 'full', 'access']).default('baseline') }),
      req.query,
    );
    const conditions = [eq(targets.projectId, auth.projectId), eq(targets.orgId, auth.orgId)];
    if (url) conditions.push(eq(targets.url, normaliseTargetUrl(url).url));
    const rows = await db.select().from(targets).where(and(...conditions));
    return {
      plan: { id: auth.plan, dast: planLimits(auth.plan).dast },
      targets: rows.map((t) => {
        const p = presentTarget(t);
        return { id: p.id, url: p.url, environment: p.environment, label: p.label, status: p.status, blocker: dastBlocker(t, auth.plan, mode) };
      }),
    };
  });

  /** Upload one scan's findings. Safe to retry with the same scanId. */
  app.post('/v1/cli/scans', { config: cliRateLimit, bodyLimit: 2 * 1024 * 1024 }, async (req, reply) => {
    const auth = await authenticateCli(req);
    if (!planLimits(auth.plan).dashboard) {
      throw paymentRequired('Fortis Free keeps results on your machine. Upgrade to Fortis Core to upload findings to the dashboard.');
    }
    const input = parse(cliScanSchema, req.body);
    if (input.kind !== 'code') {
      if (!input.targetId) throw badRequest('Running-app results need a targetId.', 'TARGET_REQUIRED');
      const mode = input.kind === 'access' ? 'access' : (input.dastMode ?? 'baseline');
      const [target] = await db
        .select()
        .from(targets)
        .where(and(eq(targets.id, input.targetId), eq(targets.projectId, auth.projectId)))
        .limit(1);
      if (!target) throw notFound('Target not found for this project.');
      const blocker = dastBlocker(target, auth.plan, mode);
      if (blocker) {
        const limits = planLimits(auth.plan);
        const planIssue = mode === 'access' ? !limits.stagingChecks : !planAllowsDast(limits, mode);
        throw planIssue ? paymentRequired(blocker) : forbidden(blocker, 'TARGET_NOT_READY');
      }
    } else if (input.targetId) {
      throw badRequest('targetId is only used for running-app results.');
    }
    const result = await ingestScan(auth, input);
    return reply.code(result.duplicate ? 200 : 201).send({
      ...result,
      dashboardUrl: `${env.WEB_URL}/projects/${auth.projectId}?scan=${result.scanId}`,
    });
  });
}
