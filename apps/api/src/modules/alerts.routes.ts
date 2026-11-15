import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { alertSettingsSchema } from '@fortis/shared';

import { db } from '../db/client';
import { alertSettings } from '../db/schema';
import { deliver, emailAvailable, isSlackWebhook, loadAlertSettings, maskWebhook, saveAlertSettings } from '../lib/alerts';
import { audit } from '../lib/audit';
import { badRequest } from '../lib/errors';
import { parse } from '../lib/validate';
import { requireOrgRole } from '../plugins/auth';

const orgParams = z.object({ orgId: z.string().uuid() });

async function present(orgId: string) {
  const s = await loadAlertSettings(orgId);
  return {
    emailEnabled: s.emailEnabled,
    emailTo: s.emailTo,
    minSeverity: s.minSeverity,
    // The URL itself lets anyone post to the channel, so only a masked form leaves the server.
    slack: s.slackWebhook ? { connected: true, display: maskWebhook(s.slackWebhook) } : { connected: false, display: null },
    emailAvailable: emailAvailable(),
    lastSentAt: s.lastSentAt,
    lastError: s.lastError,
  };
}

export async function alertRoutes(app: FastifyInstance) {
  app.get('/v1/orgs/:orgId/alerts', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    return present(orgId);
  });

  app.put('/v1/orgs/:orgId/alerts', async (req) => {
    const { orgId } = parse(orgParams, req.params);
    await requireOrgRole(req, orgId, 'admin');
    const input = parse(alertSettingsSchema, req.body);
    if (input.slackWebhookUrl && !isSlackWebhook(input.slackWebhookUrl)) {
      throw badRequest('Paste a Slack incoming-webhook URL. It starts with https://hooks.slack.com/', 'SLACK_URL_INVALID');
    }
    await saveAlertSettings(orgId, {
      ...(input.emailEnabled !== undefined ? { emailEnabled: input.emailEnabled } : {}),
      ...(input.emailTo ? { emailTo: input.emailTo } : {}),
      ...(input.minSeverity ? { minSeverity: input.minSeverity } : {}),
      ...(input.slackWebhookUrl !== undefined ? { slackWebhook: input.slackWebhookUrl || null } : {}),
    });
    await audit(db, req, {
      orgId,
      action: 'org.alerts_updated',
      targetType: 'organization',
      targetId: orgId,
      meta: {
        ...(input.emailEnabled !== undefined ? { emailEnabled: input.emailEnabled } : {}),
        ...(input.emailTo ? { emailTo: input.emailTo } : {}),
        ...(input.minSeverity ? { minSeverity: input.minSeverity } : {}),
        ...(input.slackWebhookUrl !== undefined ? { slack: input.slackWebhookUrl ? 'connected' : 'removed' } : {}),
      },
    });
    return present(orgId);
  });

  /** Sends a sample alert through the channels that are on, so an admin can see it arrive. */
  app.post('/v1/orgs/:orgId/alerts/test', { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const { orgId, org } = await (async () => {
      const { orgId } = parse(orgParams, req.params);
      const { org } = await requireOrgRole(req, orgId, 'admin');
      return { orgId, org };
    })();
    const cfg = await loadAlertSettings(orgId);
    if (!cfg.slackWebhook && !(cfg.emailEnabled && emailAvailable())) {
      throw badRequest('Turn on email or connect Slack first.', 'NO_ALERT_CHANNEL');
    }
    // deliver() records the outcome on the settings row, which needs to exist.
    await db.insert(alertSettings).values({ orgId }).onConflictDoNothing();
    const result = await deliver(orgId, cfg, {
      orgName: org.name,
      projectName: 'your project',
      scanLabel: 'Test alert from Fortis Settings',
      findings: [
        { id: '00000000-0000-0000-0000-000000000000', severity: 'critical', title: 'Paystack live secret key in source (test alert)', file: 'src/config/payments.ts', line: 12, ruleId: 'SEC-PSK-001', kind: 'code' },
      ],
    });
    await audit(db, req, { orgId, action: 'org.alerts_tested', targetType: 'organization', targetId: orgId, meta: { sent: result.sent, failed: result.errors.length } });
    return result;
  });
}
