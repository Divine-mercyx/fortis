import type { FastifyInstance } from 'fastify';

import { cliScanSchema, RULE_CATALOG } from '@fortis/shared';

import { env } from '../config/env';
import { paymentRequired } from '../lib/errors';
import { rulesKeyId, rulesPublicKeyPem, signPayload } from '../lib/rules-signing';
import { parse } from '../lib/validate';
import { authenticateCli } from '../plugins/auth';
import { ingestScan } from './ingest.service';
import { planLimits } from './orgs.routes';

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

  /** Upload one scan's findings. Safe to retry with the same scanId. */
  app.post('/v1/cli/scans', { config: cliRateLimit, bodyLimit: 2 * 1024 * 1024 }, async (req, reply) => {
    const auth = await authenticateCli(req);
    if (!planLimits(auth.plan).dashboard) {
      throw paymentRequired('Fortis Free keeps results on your machine. Upgrade to Fortis Core to upload findings to the dashboard.');
    }
    const input = parse(cliScanSchema, req.body);
    const result = await ingestScan(auth, input);
    return reply.code(result.duplicate ? 200 : 201).send({
      ...result,
      dashboardUrl: `${env.WEB_URL}/projects/${auth.projectId}?scan=${result.scanId}`,
    });
  });
}
