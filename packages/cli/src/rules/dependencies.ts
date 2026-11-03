import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { Severity } from '@fortis/shared';

import type { Detection } from './types';

/*
 * DEP-OSV: known vulnerabilities in npm packages, from the OSV database (osv.dev).
 * Reads package-lock.json, asks OSV which versions are affected, then fetches severity
 * for the advisories found. Needs network access; skipped with --offline.
 */

type LockPackages = Record<string, { version?: string; dev?: boolean }>;

export function readLockfile(root: string): { name: string; version: string; dev: boolean }[] {
  const p = join(root, 'package-lock.json');
  if (!existsSync(p)) return [];
  const lock = JSON.parse(readFileSync(p, 'utf8')) as { packages?: LockPackages; dependencies?: Record<string, { version: string; dev?: boolean }> };
  const out = new Map<string, { name: string; version: string; dev: boolean }>();
  if (lock.packages) {
    for (const [path, meta] of Object.entries(lock.packages)) {
      if (!path || !meta.version) continue;
      const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.set(`${name}@${meta.version}`, { name, version: meta.version, dev: Boolean(meta.dev) });
    }
  } else if (lock.dependencies) {
    for (const [name, meta] of Object.entries(lock.dependencies)) {
      out.set(`${name}@${meta.version}`, { name, version: meta.version, dev: Boolean(meta.dev) });
    }
  }
  return [...out.values()];
}

const SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

type OsvVuln = { id: string; summary?: string; aliases?: string[]; database_specific?: { severity?: string } };

export async function scanDependencies(
  root: string,
  opts: { includeDev?: boolean; fetchImpl?: typeof fetch; osvUrl?: string } = {},
): Promise<{ detections: Detection[]; checked: number; error?: string }> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = opts.osvUrl ?? 'https://api.osv.dev';
  const pkgs = readLockfile(root).filter((p) => opts.includeDev || !p.dev);
  if (!pkgs.length) return { detections: [], checked: 0 };

  try {
    const hits: { pkg: (typeof pkgs)[number]; ids: string[] }[] = [];
    for (let i = 0; i < pkgs.length; i += 500) {
      const chunk = pkgs.slice(i, i + 500);
      const res = await fetchImpl(`${base}/v1/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) }),
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`OSV responded ${res.status}`);
      const data = (await res.json()) as { results: { vulns?: { id: string }[] }[] };
      data.results.forEach((r, k) => {
        if (r.vulns?.length) hits.push({ pkg: chunk[k]!, ids: r.vulns.map((v) => v.id) });
      });
    }

    const details = new Map<string, OsvVuln>();
    const ids = [...new Set(hits.flatMap((h) => h.ids))].slice(0, 60);
    await Promise.all(
      ids.map(async (id) => {
        try {
          const r = await fetchImpl(`${base}/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(10_000) });
          if (r.ok) details.set(id, (await r.json()) as OsvVuln);
        } catch {
          /* keep going without severity */
        }
      }),
    );

    const detections: Detection[] = hits.map(({ pkg, ids: vulnIds }) => {
      const vulns = vulnIds.map((id) => details.get(id)).filter(Boolean) as OsvVuln[];
      const ranked = vulns
        .map((v) => SEVERITY[(v.database_specific?.severity ?? '').toUpperCase()] ?? 'medium')
        .sort((a, b) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(a) - ['critical', 'high', 'medium', 'low', 'info'].indexOf(b));
      const severity = ranked[0] ?? 'medium';
      const top = vulns[0];
      const ref = top?.aliases?.find((a) => a.startsWith('CVE-')) ?? top?.id ?? vulnIds[0];
      return {
        ruleId: 'DEP-OSV',
        severity,
        title: `${pkg.name}@${pkg.version}: ${top?.summary ?? 'known vulnerability'}${vulnIds.length > 1 ? ` (+${vulnIds.length - 1} more)` : ''}`.slice(0, 200),
        file: 'package-lock.json',
        line: 0,
        snippet: `${pkg.name}@${pkg.version} · ${ref}`,
      };
    });
    return { detections, checked: pkgs.length };
  } catch (e) {
    return { detections: [], checked: 0, error: (e as Error).message };
  }
}
