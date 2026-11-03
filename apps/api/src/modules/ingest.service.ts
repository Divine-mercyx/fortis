import { and, eq, inArray, notInArray, sql } from 'drizzle-orm';

import { findRule, type CliScanInput } from '@fortis/shared';

import { db } from '../db/client';
import { findingEvents, findings, scans, targets } from '../db/schema';
import { sha256 } from '../lib/crypto';
import { maskSnippet, maskText } from '../lib/mask';
import type { CliAuth } from '../plugins/auth';

export type IngestResult = {
  scanId: string;
  duplicate: boolean;
  findingsCount: number;
  newCount: number;
  reopenedCount: number;
  fixedCount: number;
  findings: { fingerprint: string; findingId: string; status: string; isNew: boolean }[];
};

const normaliseFile = (file: string) => file.replace(/\\/g, '/').replace(/^\.\//, '');

/** Stable identity for "the same issue": rule + file + the masked line (not the line number, which shifts). */
function fingerprintOf(ruleId: string, file: string, snippet: string | null, line: number | undefined) {
  const anchor = snippet ? snippet.replace(/\s+/g, ' ').trim() : `line:${line ?? 0}`;
  return sha256(`${ruleId}|${file}|${anchor}`).slice(0, 40);
}

/**
 * Records one CLI run. Idempotent on (project, scanId): a retried upload returns the first result.
 * New fingerprints become open findings; fixed ones that reappear are reopened. A "full" scan also
 * closes open findings it no longer sees. Everything is written as finding events for the evidence trail.
 */
export async function ingestScan(auth: CliAuth, input: CliScanInput): Promise<IngestResult> {
  const isDast = input.kind === 'dast';
  const targetId = isDast ? (input.targetId ?? null) : null;
  return db.transaction(async (tx) => {
    const inserted = await tx
      .insert(scans)
      .values({
        orgId: auth.orgId,
        projectId: auth.projectId,
        tokenId: auth.tokenId,
        clientScanId: input.scanId,
        trigger: input.trigger,
        kind: input.kind,
        targetId,
        dastMode: isDast ? (input.dastMode ?? 'baseline') : null,
        scope: input.scope,
        commit: input.commit ?? null,
        branch: input.branch ?? null,
        cliVersion: input.cliVersion,
        rulesVersion: input.rulesVersion ?? null,
        durationMs: input.durationMs ?? null,
        filesScanned: input.filesScanned ?? null,
      })
      .onConflictDoNothing()
      .returning();

    if (!inserted.length) {
      const [prev] = await tx
        .select()
        .from(scans)
        .where(and(eq(scans.projectId, auth.projectId), eq(scans.clientScanId, input.scanId)))
        .limit(1);
      return {
        scanId: prev!.id,
        duplicate: true,
        findingsCount: prev!.findingsCount,
        newCount: prev!.newCount,
        reopenedCount: prev!.reopenedCount,
        fixedCount: prev!.fixedCount,
        findings: [],
      };
    }
    const scan = inserted[0]!;
    const now = new Date();

    // Normalise, mask and de-duplicate within this upload.
    const incoming = new Map<string, {
      ruleId: string; severity: string; title: string; file: string; line: number | null; snippet: string | null;
      detail: string | null; kind: string; targetId: string | null;
    }>();
    for (const f of input.findings) {
      const file = normaliseFile(f.file);
      const snippet = f.snippet ? maskSnippet(f.snippet) : null;
      const base = f.fingerprint ?? fingerprintOf(f.ruleId, file, snippet, f.line);
      // DAST findings are per target, so the same alert on two environments stays two findings.
      const fingerprint = isDast ? sha256(`dast|${targetId}|${base}`).slice(0, 40) : base;
      if (incoming.has(fingerprint)) continue;
      incoming.set(fingerprint, {
        ruleId: f.ruleId,
        severity: f.severity,
        // Dependency and ZAP findings keep the tool's specific title; catalogue rules use ours.
        title: f.ruleId === 'DEP-OSV' || isDast ? f.title : (findRule(f.ruleId)?.title ?? f.title),
        file,
        line: f.line ?? null,
        snippet,
        detail: f.detail ? maskText(f.detail).slice(0, 4000) : null,
        kind: input.kind,
        targetId,
      });
    }
    const fingerprints = [...incoming.keys()];

    const existing = fingerprints.length
      ? await tx
          .select({ id: findings.id, fingerprint: findings.fingerprint, status: findings.status })
          .from(findings)
          .where(and(eq(findings.projectId, auth.projectId), inArray(findings.fingerprint, fingerprints)))
      : [];
    const byFingerprint = new Map(existing.map((e) => [e.fingerprint, e]));

    const out: IngestResult['findings'] = [];
    let newCount = 0;
    let reopenedCount = 0;

    for (const [fingerprint, f] of incoming) {
      const prev = byFingerprint.get(fingerprint);
      if (!prev) {
        const [row] = await tx
          .insert(findings)
          .values({
            orgId: auth.orgId,
            projectId: auth.projectId,
            fingerprint,
            ...f,
            status: 'open',
            firstSeenAt: now,
            lastSeenAt: now,
            firstScanId: scan.id,
            lastScanId: scan.id,
          })
          // A concurrent upload may have just created it; treat that as already seen.
          .onConflictDoNothing()
          .returning({ id: findings.id });
        if (!row) {
          const [raced] = await tx
            .select({ id: findings.id, status: findings.status })
            .from(findings)
            .where(and(eq(findings.projectId, auth.projectId), eq(findings.fingerprint, fingerprint)))
            .limit(1);
          out.push({ fingerprint, findingId: raced!.id, status: raced!.status, isNew: false });
          continue;
        }
        await tx.insert(findingEvents).values({
          orgId: auth.orgId, findingId: row!.id, type: 'detected', toStatus: 'open', scanId: scan.id,
        });
        newCount++;
        out.push({ fingerprint, findingId: row!.id, status: 'open', isNew: true });
        continue;
      }

      const reopen = prev.status === 'fixed';
      await tx
        .update(findings)
        .set({
          severity: f.severity,
          title: f.title,
          line: f.line,
          snippet: f.snippet,
          detail: f.detail,
          lastSeenAt: now,
          lastScanId: scan.id,
          ...(reopen ? { status: 'open', fixedAt: null, statusReason: null } : {}),
        })
        .where(eq(findings.id, prev.id));
      if (reopen) {
        await tx.insert(findingEvents).values({
          orgId: auth.orgId, findingId: prev.id, type: 'reopened', fromStatus: 'fixed', toStatus: 'open', scanId: scan.id,
        });
        reopenedCount++;
      }
      out.push({ fingerprint, findingId: prev.id, status: reopen ? 'open' : prev.status, isNew: false });
    }

    // A full scan that no longer sees an open finding means it was fixed.
    let fixedCount = 0;
    if (input.scope === 'full') {
      const conditions = [eq(findings.projectId, auth.projectId), eq(findings.status, 'open'), eq(findings.kind, input.kind)];
      if (isDast) {
        conditions.push(eq(findings.targetId, targetId!));
        // A passive baseline can't see what an active scan found, so it only closes baseline findings.
        if ((input.dastMode ?? 'baseline') === 'baseline') {
          conditions.push(sql`${findings.lastScanId} in (select id from scans where dast_mode = 'baseline')`);
        }
      }
      if (fingerprints.length) conditions.push(notInArray(findings.fingerprint, fingerprints));
      const closed = await tx
        .update(findings)
        .set({ status: 'fixed', fixedAt: now })
        .where(and(...conditions))
        .returning({ id: findings.id });
      if (closed.length) {
        await tx.insert(findingEvents).values(
          closed.map((c) => ({
            orgId: auth.orgId, findingId: c.id, type: 'fixed', fromStatus: 'open', toStatus: 'fixed', scanId: scan.id,
            reason: 'No longer detected by a full scan',
          })),
        );
      }
      fixedCount = closed.length;
    }

    await tx
      .update(scans)
      .set({ findingsCount: incoming.size, newCount, reopenedCount, fixedCount })
      .where(eq(scans.id, scan.id));
    if (targetId) await tx.update(targets).set({ lastRunAt: now }).where(eq(targets.id, targetId));

    return { scanId: scan.id, duplicate: false, findingsCount: incoming.size, newCount, reopenedCount, fixedCount, findings: out };
  });
}
