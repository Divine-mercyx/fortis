import type { Severity } from '@fortis/shared';

import { readLockfile } from './lockfiles';
import type { Detection } from './types';

/*
 * DEP-OSV: known vulnerabilities in npm packages, from the OSV database (osv.dev).
 * Reads the lockfile (npm, pnpm or yarn; see lockfiles.ts), asks OSV which versions are affected, then fetches severity
 * for the advisories found. Needs network access; skipped with --offline.
 */

const SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

  if (opts.allPaths) {
    const missing = missingLockfiles(opts.allPaths, opts.ignore ?? [], seen);
    if (missing.length) incomplete = true;
    notes.push(...missing);
  }
  return { packages, notes, incomplete };
}

async function inPool<T>(items: T[], size: number, run: (item: T) => Promise<void>) {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (next < items.length) await run(items[next++]!);
    }),
  );
}

export async function scanDependencies(
  root: string,
  files: string[],
  opts: { sbom?: string; allPaths?: string[]; ignore?: string[]; includeDev?: boolean; fetchImpl?: typeof fetch; osvUrl?: string } = {},
): Promise<{ detections: Detection[]; checked: number; error?: string; notes: string[]; incomplete: boolean }> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = opts.osvUrl ?? 'https://api.osv.dev';
  const lock = readLockfile(root);
  const pkgs = (lock?.packages ?? []).filter((p) => opts.includeDev || !p.dev);
  if (!pkgs.length) return { detections: [], checked: 0 };

  try {
    const hits: { pkg: Locked; ids: string[] }[] = [];
    for (let i = 0; i < pkgs.length; i += 500) {
      const chunk = pkgs.slice(i, i + 500);
      const res = await fetchImpl(`${base}/v1/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`OSV responded ${res.status}`);
      const data = (await res.json()) as { results: { vulns?: { id: string }[] }[] };
      data.results.forEach((r, k) => {
        if (r.vulns?.length) hits.push({ pkg: chunk[k]!, ids: r.vulns.map((v) => v.id) });
      });
    }

    const details = new Map<string, OsvVuln>();
    const allIds = [...new Set(hits.flatMap((h) => h.ids))];
    await inPool(allIds.slice(0, MAX_ADVISORIES), ADVISORY_CONCURRENCY, async (id) => {
      try {
        const r = await fetchImpl(`${base}/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(10_000) });
        if (r.ok) details.set(id, (await r.json()) as OsvVuln);
      } catch {
        /* keep going without severity */
      }
    });
    if (allIds.length > MAX_ADVISORIES) notes.push(`Severity was looked up for the first ${MAX_ADVISORIES} of ${allIds.length} advisories; the rest show as medium.`);

    const byKey = new Map(hits.map((h) => [keyOf(h.pkg), h]));
    const detections: Detection[] = [];
    for (const where of new Map(located.map((p) => [`${p.file}|${keyOf(p)}`, p])).values()) {
      const hit = byKey.get(keyOf(where));
      if (!hit) continue;
      const { pkg, ids: vulnIds } = hit;
      const vulns = vulnIds.map((id) => details.get(id)).filter(Boolean) as OsvVuln[];
      const ranked = vulns
        .map((v) => SEVERITY[(v.database_specific?.severity ?? '').toUpperCase()] ?? 'medium')
        .sort((a, b) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(a) - ['critical', 'high', 'medium', 'low', 'info'].indexOf(b));
      const severity = ranked[0] ?? 'medium';
      const top = vulns[0];
      const ref = top?.aliases?.find((a) => a.startsWith('CVE-')) ?? top?.id ?? vulnIds[0];
      detections.push({
        ruleId: 'DEP-OSV',
        severity,
        title: `${pkg.name}@${pkg.version}: ${top?.summary ?? 'known vulnerability'}${vulnIds.length > 1 ? ` (+${vulnIds.length - 1} more)` : ''}`.slice(0, 200),
        file: lock!.file,
        line: pkg.line,
        snippet: `${pkg.name}@${pkg.version} · ${ref}`,
      });
    }
    return { detections, checked: pkgs.length, notes, incomplete: read.incomplete };
  } catch (e) {
    const msg = (e as Error).message;
    // Node's fetch says only "fetch failed" when the host can't be reached (offline, proxy, firewall).
    const error = /fetch failed|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|aborted|timeout/i.test(msg) ? `could not reach ${new URL(base).host} (${msg})` : msg;
    return { detections: [], checked: 0, error };
  }
}
