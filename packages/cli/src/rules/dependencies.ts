import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

import type { Severity } from '@fortis/shared';

import { cycloneDx, ecosystemOf, findLockfiles, isPomXml, missingLockfiles, parseLockfile, type Ecosystem, type Locked } from './lockfiles';
import { fixedVersion, fixMessage, type OsvAffected } from './fix-version';
import { OsvCache } from './osv-cache';
import { lookupLocal } from './osv-db';
import type { Detection } from './types';

/*
 * DEP-OSV: known vulnerabilities in packages of any supported language, from the OSV database
 * (osv.dev). Reads lockfiles (and an SBOM if given), asks OSV which versions are affected, then
 * fetches severity for the advisories found. Needs network access; skipped with --offline.
 */

/** Whatever the check could not see. `incomplete` stops a full scan closing findings it didn't look for. */
type LockRead = { packages: (Locked & { file: string })[]; notes: string[]; incomplete: boolean };

const SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

/** One scan's advisory lookups. Past this, findings still appear but without a looked-up severity. */
const MAX_ADVISORIES = 500;
const ADVISORY_CONCURRENCY = 8;

type OsvVuln = { id: string; summary?: string; aliases?: string[]; database_specific?: { severity?: string }; affected?: OsvAffected[] };

export function readPackages(root: string, files: string[], opts: { sbom?: string; allPaths?: string[]; ignore?: string[] } = {}): LockRead {
  const notes: string[] = [];
  const packages: LockRead['packages'] = [];
  let incomplete = false;
  let sbomRead = false;
  const seen = new Set<Ecosystem>();

  if (opts.sbom) {
    const abs = resolve(root, opts.sbom);
    const file = relative(root, abs).replace(/\\/g, '/');
    try {
      const sbom = cycloneDx(readFileSync(abs, 'utf8'));
      packages.push(...sbom.packages.map((p) => ({ ...p, file })));
      for (const p of sbom.packages) seen.add(p.ecosystem);
      sbomRead = true;
    } catch (e) {
      notes.push(`Could not read the SBOM ${file}: ${(e as Error).message}.`);
      incomplete = true;
    }
  }

  let pomFiles = 0;
  let pomChecked = 0;
  let pomSkipped = 0;
  let skippedElsewhere = 0;
  for (const file of findLockfiles(files, opts.ignore)) {
    if (sbomRead && isPomXml(file)) continue; // the SBOM already has this, and more
    const abs = join(root, file);
    if (!existsSync(abs)) continue;
    try {
      const manifestPath = join(root, dirname(file), 'package.json');
      const manifest = /(^|\/)yarn\.lock$/.test(file) && existsSync(manifestPath) ? readFileSync(manifestPath, 'utf8') : undefined;
      const parsed = parseLockfile(file, readFileSync(abs, 'utf8'), manifest);
      packages.push(...parsed.packages.map((p) => ({ ...p, file })));
      seen.add(ecosystemOf(file));
      if (isPomXml(file)) {
        pomFiles++;
        pomChecked += parsed.packages.length;
        pomSkipped += parsed.skipped;
      } else {
        skippedElsewhere += parsed.skipped;
      }
    } catch (e) {
      notes.push(`Could not read ${file}: ${(e as Error).message}.`);
      incomplete = true;
    }
  }

  if (pomFiles) {
    const declared = pomChecked + pomSkipped;
    const versions = pomSkipped ? `; the other ${pomSkipped} get their version from a parent POM or BOM` : '';
    notes.push(`pom.xml: checked ${pomChecked} of ${declared} declared dependencies${versions}. Transitive dependencies aren't covered: generate a CycloneDX SBOM and pass --sbom for those.`);
  }
  if (skippedElsewhere) notes.push(`${skippedElsewhere === 1 ? '1 dependency has' : `${skippedElsewhere} dependencies have`} no exact version (unpinned or installed from a branch), so ${skippedElsewhere === 1 ? "it wasn't" : "they weren't"} checked.`);

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
  opts: {
    sbom?: string;
    allPaths?: string[];
    ignore?: string[];
    includeDev?: boolean;
    fetchImpl?: typeof fetch;
    osvUrl?: string;
    /** Folder of OSV exports: no network at all. */
    osvDb?: string;
    /** Cache folder for OSV answers; omitted means no cache. */
    cacheDir?: string;
    now?: () => number;
  } = {},
): Promise<{ detections: Detection[]; checked: number; error?: string; notes: string[]; incomplete: boolean }> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = opts.osvUrl ?? 'https://api.osv.dev';
  const read = readPackages(root, files, opts);
  const { notes } = read;
  const located = read.packages.filter((p) => opts.includeDev || !p.dev);
  if (!located.length) return { detections: [], checked: 0, notes, incomplete: read.incomplete };

  // The same version in several lockfiles is one question for OSV, and one finding per lockfile.
  const keyOf = (p: Locked) => `${p.ecosystem}|${p.name}|${p.version}`;
  const pkgs = [...new Map(located.map((p) => [keyOf(p), p])).values()];

  try {
    const hits: { pkg: Locked; ids: string[] }[] = [];
    const details = new Map<string, OsvVuln>();

    if (opts.osvDb) {
      const local = lookupLocal(opts.osvDb, pkgs, keyOf);
      for (const p of pkgs) {
        const ids = local.hits.get(keyOf(p));
        if (ids?.length) hits.push({ pkg: p, ids });
      }
      for (const [id, v] of local.details) details.set(id, v);
      notes.push(`Dependencies checked against the local OSV database in ${opts.osvDb} (${local.read} advisories read).`);
    } else {
      const cache = opts.cacheDir ? new OsvCache(opts.cacheDir, opts.now) : undefined;
      const ask: Locked[] = [];
      for (const p of pkgs) {
        const known = cache?.query(keyOf(p));
        if (known === undefined) ask.push(p);
        else if (known.length) hits.push({ pkg: p, ids: known });
      }
      for (let i = 0; i < ask.length; i += 500) {
        const chunk = ask.slice(i, i + 500);
        const res = await fetchImpl(`${base}/v1/querybatch`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
          signal: AbortSignal.timeout(15_000),
        });
        if (!res.ok) throw new Error(`OSV responded ${res.status}`);
        const data = (await res.json()) as { results: { vulns?: { id: string }[] }[] };
        data.results.forEach((r, k) => {
          const ids = (r.vulns ?? []).map((v) => v.id);
          cache?.setQuery(keyOf(chunk[k]!), ids);
          if (ids.length) hits.push({ pkg: chunk[k]!, ids });
        });
      }

      const allIds = [...new Set(hits.flatMap((h) => h.ids))];
      const missing: string[] = [];
      for (const id of allIds) {
        const v = cache?.vuln<OsvVuln>(id);
        if (v) details.set(id, v);
        else missing.push(id);
      }
      await inPool(missing.slice(0, MAX_ADVISORIES), ADVISORY_CONCURRENCY, async (id) => {
        try {
          const r = await fetchImpl(`${base}/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(10_000) });
          if (!r.ok) return;
          const v = (await r.json()) as OsvVuln;
          // Keep only what the CLI reads, so the cache stays small.
          const slim: OsvVuln = { id: v.id, summary: v.summary, aliases: v.aliases, database_specific: { severity: v.database_specific?.severity }, affected: v.affected?.map((a) => ({ package: a.package, ranges: a.ranges })) };
          details.set(id, slim);
          cache?.setVuln(id, slim);
        } catch {
          /* keep going without severity */
        }
      });
      if (missing.length > MAX_ADVISORIES) notes.push(`Severity was looked up for the first ${MAX_ADVISORIES} of ${missing.length} advisories; the rest show as medium.`);
      cache?.save();
    }

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
      // Without every advisory's details the fix can't be trusted to clear them all.
      const fix = vulns.length === vulnIds.length ? fixedVersion(vulns, pkg.ecosystem, pkg.name, pkg.version) : undefined;
      detections.push({
        ruleId: 'DEP-OSV',
        severity,
        title: `${pkg.name}@${pkg.version}: ${top?.summary ?? 'known vulnerability'}${vulnIds.length > 1 ? ` (+${vulnIds.length - 1} more)` : ''}`.slice(0, 200),
        file: where.file,
        line: where.line ?? 0,
        snippet: `${pkg.name}@${pkg.version} · ${ref}`,
        ...(fix ? { fix: fixMessage({ ...where, name: pkg.name, version: pkg.version }, fix), fixedVersion: fix.version } : {}),
      });
    }
    return { detections, checked: pkgs.length, notes, incomplete: read.incomplete };
  } catch (e) {
    const msg = (e as Error).message;
    // Node's fetch says only "fetch failed" when the host can't be reached (offline, proxy, firewall).
    const unreachable = /fetch failed|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|aborted|timeout|proxy/i.test(msg);
    const hint = process.env.HTTPS_PROXY || process.env.https_proxy ? ' Check the proxy in HTTPS_PROXY, or add its CA with --ca.' : ' Behind a company proxy? Set HTTPS_PROXY. No internet at all? Use --osv-db.';
    const error = unreachable ? `could not reach ${new URL(base).host} (${msg}).${hint}` : msg;
    return { detections: [], checked: 0, error, notes, incomplete: true };
  }
}
