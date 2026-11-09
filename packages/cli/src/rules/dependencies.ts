import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

import type { Severity } from '@fortis/shared';

import { cycloneDx, ecosystemOf, findLockfiles, GRADLE_BUILD, isJvmBuild, isPomXml, isRequirements, manifestFor, missingLockfiles, parseLockfile, pomParent, SBT_BUILD, VERSION_CATALOG, type Ecosystem, type Locked } from './lockfiles';
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

type OsvVuln = { id: string; summary?: string; aliases?: string[]; database_specific?: { severity?: string }; severity?: { type: string; score: string }[]; affected?: OsvAffected[] };

/** The base score of a CVSS 3 vector, as a severity. Many PyPI and Go advisories carry only this. */
export function cvssSeverity(vector: string): Severity | null {
  const m = Object.fromEntries(vector.split('/').map((part) => part.split(':') as [string, string]));
  if (!/^CVSS:3/.test(vector) || !m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;
  const impactOf = (x: string) => ({ H: 0.56, L: 0.22, N: 0 })[x] ?? 0;
  const changed = m.S === 'C';
  const iss = 1 - (1 - impactOf(m.C)) * (1 - impactOf(m.I)) * (1 - impactOf(m.A));
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 'info';
  const av = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 })[m.AV] ?? 0;
  const ac = ({ L: 0.77, H: 0.44 })[m.AC] ?? 0;
  const pr = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[m.PR] ?? 0;
  const ui = ({ N: 0.85, R: 0.62 })[m.UI] ?? 0;
  const raw = Math.min((changed ? 1.08 : 1) * (impact + 8.22 * av * ac * pr * ui), 10);
  const score = Math.ceil(raw * 10) / 10;
  return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
}

/** Severity from the advisory, then its GitHub alias, then its CVSS vector. */
function severityOf(v: OsvVuln, details: Map<string, OsvVuln>): Severity {
  const own = SEVERITY[(v.database_specific?.severity ?? '').toUpperCase()];
  if (own) return own;
  for (const alias of v.aliases ?? []) {
    const known = SEVERITY[(details.get(alias)?.database_specific?.severity ?? '').toUpperCase()];
    if (known) return known;
  }
  const vector = v.severity?.find((x) => x.type === 'CVSS_V3')?.score;
  return (vector && cvssSeverity(vector)) || 'medium';
}

/**
 * A text file, however Windows wrote it. `pip freeze > requirements.txt` in Windows PowerShell gives
 * UTF-16, and read as UTF-8 that looks like a file with no packages at all.
 */
function readText(path: string): string {
  const bytes = readFileSync(path);
  const text = bytes[0] === 0xff && bytes[1] === 0xfe ? bytes.toString('utf16le') : bytes.toString('utf8');
  return text.replace(/^﻿/, '');
}

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
      const sbom = cycloneDx(readText(abs));
      packages.push(...sbom.packages.map((p) => ({ ...p, file })));
      for (const p of sbom.packages) seen.add(p.ecosystem);
      sbomRead = true;
    } catch (e) {
      notes.push(`Could not read the SBOM ${file}: ${(e as Error).message}.`);
      incomplete = true;
    }
  }

  let pomFiles = 0;
  let jvmBuilds = 0;
  let pomChecked = 0;
  let pomSkipped = 0;
  let skippedElsewhere = 0;
  const skippedByFile: { file: string; names: string[]; count: number }[] = [];
  let directOnlyFiles = 0;
  for (const file of findLockfiles(files, opts.ignore)) {
    if (sbomRead && (isPomXml(file) || isRequirements(file) || isJvmBuild(file))) continue; // the SBOM already has this, and more
    const abs = join(root, file);
    if (!existsSync(abs)) continue;
    try {
      const manifestName = manifestFor(file);
      const manifestPath = manifestName ? join(root, dirname(file), manifestName) : null;
      const manifest = manifestPath && existsSync(manifestPath) ? readText(manifestPath) : jvmContext(root, file);
      const parsed = parseLockfile(file, readText(abs), manifest);
      packages.push(...parsed.packages.map((p) => ({ ...p, file })));
      seen.add(ecosystemOf(file));
      if (parsed.directOnly && isRequirements(file)) directOnlyFiles++;
      if (isJvmBuild(file)) jvmBuilds++;
      if (isPomXml(file)) {
        pomFiles++;
        pomChecked += parsed.packages.length;
        pomSkipped += parsed.skipped;
      } else {
        skippedElsewhere += parsed.skipped;
        if (parsed.skipped) skippedByFile.push({ file, names: parsed.skippedNames ?? [], count: parsed.skipped });
      }
    } catch (e) {
      notes.push(`Could not read ${file}: ${(e as Error).message}.`);
      incomplete = true;
    }
  }

  if (pomFiles) {
    const declared = pomChecked + pomSkipped;
    const versions = pomSkipped ? `; the other ${pomSkipped} get their version from a parent POM or BOM` : '';
    notes.push(`pom.xml: checked ${pomChecked} of ${declared} declared dependencies${versions}. Transitive dependencies aren't covered: generate a CycloneDX SBOM and pass --sbom for those (fortis ci init adds the step).`);
  }
  if (jvmBuilds) notes.push(`Gradle and sbt build files: only the dependencies they declare were checked. Transitive dependencies need a CycloneDX SBOM passed with --sbom (fortis ci init adds the step for Gradle), Gradle dependency locking, or sbt-dependency-lock's build.sbt.lock.`);
  if (directOnlyFiles) notes.push(`requirements files: only the packages they list were checked. Unless they're a full pip freeze, transitive dependencies aren't covered: use uv, Poetry or pip-compile, or pass --sbom for those.`);
  if (skippedElsewhere) {
    notes.push(`${skippedElsewhere === 1 ? '1 dependency has' : `${skippedElsewhere} dependencies have`} no exact version (pinned by range, unpinned or installed from a branch), so ${skippedElsewhere === 1 ? "it wasn't" : "they weren't"} checked.`);
    for (const s of skippedByFile) notes.push(`  ${s.file}: ${skippedList(s.names, s.count)}. ${pinAdvice(s.file)}`);
  }

  if (opts.allPaths) {
    const missing = missingLockfiles(opts.allPaths, opts.ignore ?? [], seen);
    if (missing.length) incomplete = true;
    notes.push(...missing);
  }
  return { packages, notes, incomplete };
}

/**
 * What a JVM build file needs from elsewhere in the repository: a pom.xml's parent POMs (found
 * through <relativePath>), the build scripts that use a Gradle version catalog, or the build.sbt
 * next to an sbt project folder.
 */
function jvmContext(root: string, file: string): string | undefined {
  const read = (rel: string) => {
    const abs = join(root, rel);
    return existsSync(abs) ? readText(abs) : undefined;
  };
  if (isPomXml(file)) {
    const parents: string[] = [];
    let at = file;
    let text = read(file);
    for (let i = 0; i < 5 && text; i++) {
      const parent = pomParent(text);
      if (!parent) break;
      const rel = relative(root, resolve(root, dirname(at), parent.relativePath.replace(/\/?$/, '').replace(/(?<!\.xml)$/, '/pom.xml'))).replace(/\\/g, '/');
      const parentText = rel.startsWith('..') ? undefined : read(rel);
      if (!parentText || (parent.artifactId && !parentText.includes(`<artifactId>${parent.artifactId}</artifactId>`))) break;
      parents.push(parentText);
      at = rel;
      text = parentText;
    }
    return parents.length ? JSON.stringify(parents) : undefined;
  }
  if (VERSION_CATALOG.test(file)) {
    // The project the catalog belongs to: the folder holding gradle/.
    const project = dirname(dirname(file));
    const builds: string[] = [];
    const walk = (rel: string, depth: number) => {
      if (depth > 3) return;
      let names: string[] = [];
      try {
        names = readdirSync(join(root, rel));
      } catch {
        return;
      }
      for (const n of names) {
        const child = rel === '.' ? n : `${rel}/${n}`;
        if (GRADLE_BUILD.test(n)) builds.push(readText(join(root, child)));
        else if (!/^(?:\.|build$|node_modules$)/.test(n) && statSync(join(root, child), { throwIfNoEntry: false })?.isDirectory()) walk(child, depth + 1);
      }
    };
    walk(project, 0);
    return builds.join('\n');
  }
  if (SBT_BUILD.test(file) && /(^|\/)project\/[^/]+\.scala$/.test(file)) return read(`${dirname(dirname(file))}/build.sbt`);
  return undefined;
}

/** "fastapi, pydantic, uvicorn and 17 more" */
function skippedList(names: string[], count: number): string {
  const shown = names.slice(0, 5);
  if (!shown.length) return `${count} not checked`;
  const rest = count - shown.length;
  return `${shown.join(', ')}${rest > 0 ? ` and ${rest} more` : ''}`;
}

/** How to get exact versions for this kind of file. */
export function pinAdvice(file: string): string {
  const base = file.slice(file.lastIndexOf('/') + 1);
  if (/^Pipfile\.lock$/.test(base)) return 'Run pipenv lock so every package has an exact version.';
  if (/^composer\.lock$/.test(base)) return 'Branch installs have no release to check: require a tagged version (composer require vendor/pkg:^x).';
  if (/\.(txt|in)$/.test(base)) return 'Lock exact versions to check them: uv lock or poetry lock, or pip-compile (uv pip compile requirements.in -o requirements.txt), or pip freeze > requirements.txt.';
  if (/\.versions\.toml$|^build\.gradle(\.kts)?$|^build\.sbt$|\.scala$/.test(base)) return 'A version from a BOM or a variable, or a dynamic one (1.+), has no one version to check here: a CycloneDX SBOM, Gradle dependency locking or build.sbt.lock covers them.';
  return 'Pin exact versions in the lockfile to check them.';
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
      const lookUp = async (id: string) => {
        try {
          const r = await fetchImpl(`${base}/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(10_000) });
          if (!r.ok) return;
          const v = (await r.json()) as OsvVuln;
          // Keep only what the CLI reads, so the cache stays small.
          const slim: OsvVuln = { id: v.id, summary: v.summary, aliases: v.aliases, database_specific: { severity: v.database_specific?.severity }, severity: v.severity, affected: v.affected?.map((a) => ({ package: a.package, ranges: a.ranges })) };
          details.set(id, slim);
          cache?.setVuln(id, slim);
        } catch {
          /* keep going without severity */
        }
      };
      await inPool(missing.slice(0, MAX_ADVISORIES), ADVISORY_CONCURRENCY, lookUp);
      // Some advisories carry no severity of their own, but their GitHub alias does.
      const aliases = [...new Set([...details.values()].filter((v) => !v.database_specific?.severity).flatMap((v) => (v.aliases ?? []).filter((a) => a.startsWith('GHSA-') && !details.has(a))))];
      const aliasesToFetch: string[] = [];
      for (const id of aliases) {
        const v = cache?.vuln<OsvVuln>(id);
        if (v) details.set(id, v);
        else aliasesToFetch.push(id);
      }
      await inPool(aliasesToFetch.slice(0, Math.max(0, MAX_ADVISORIES - details.size)), ADVISORY_CONCURRENCY, lookUp);
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
        .map((v) => severityOf(v, details))
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
