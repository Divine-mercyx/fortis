import type { FastifyRequest } from 'fastify';

import type { DbOrTx } from '../db/client';
import { auditLog } from '../db/schema';

export async function audit(
  tx: DbOrTx,
  req: FastifyRequest,
  entry: { orgId: string | null; action: string; targetType?: string; targetId?: string; meta?: Record<string, unknown> },
) {
  await tx.insert(auditLog).values({
    orgId: entry.orgId,
    actorUserId: req.user?.id ?? null,
    action: entry.action,
    targetType: entry.targetType ?? null,
    targetId: entry.targetId ?? null,
    meta: entry.meta ?? null,
    ip: req.ip,
  });
}
