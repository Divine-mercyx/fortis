import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { SEVERITY_RANK, type RulePack, type Severity } from '@fortis/shared';

import { scanDependencies } from './rules/dependencies';
import { SUPPORTED_LOCKFILES } from './rules/lockfiles';
import { rulesFor } from './rules/index';
import { JS_TS, TEST_PATH, type Detection, type ProjectContext, type SourceFile } from './rules/types';
import { loadFiles } from './files';
import { allFiles, changedFiles, type PushedRef } from './git';

export type ScanOptions = {
  root: string;
  scope: 'changed' | 'full';
  /** From the git hook's stdin: the refs being pushed (pre-push scope only). */
  pushed?: PushedRef[];
  packs: readonly RulePack[];
  ignore?: string[];
  offline?: boolean;
  fetchImpl?: typeof fetch;
};

export type ScanResult = {
  detections: Detection[];
  filesScanned: number;
  packagesChecked: number;
  durationMs: number;
  notes: string[];
};

export async function runScan(opts: ScanOptions): Promise<ScanResult> {
  const started = Date.now();
  const notes: string[] = [];
  const paths = opts.scope === 'changed' ? changedFiles(opts.root, opts.pushed) : allFiles(opts.root);
  const files = loadFiles(opts.root, paths, opts.ignore);
  const rules = rulesFor(opts.packs);
  // Repository-wide facts (e.g. idempotency middleware defined elsewhere), even for pre-push scans.
  const ctx = buildContext(opts.scope === 'full' ? files : loadFiles(opts.root, allFiles(opts.root), opts.ignore));

  const seen = new Set<string>();
  const detections: Detection[] = [];
  for (const file of files) {
    for (const rule of rules) {
      if (!rule.appliesTo.test(file.path)) continue;
      if (rule.skipTests && TEST_PATH.test(file.path)) continue;
      for (const d of rule.run(file, ctx)) {
        const key = `${d.ruleId}|${d.file}|${d.line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        detections.push(d);
      }
    }
  }

  let packagesChecked = 0;
  if (opts.packs.includes('dependencies') && opts.scope === 'full') {
    const missing = missingLockfileNote(opts.root);
    if (missing) notes.push(missing);
  }
  const lockTouched = opts.scope === 'full' || paths.some((f) => (SUPPORTED_LOCKFILES as readonly string[]).includes(f));
  if (opts.packs.includes('dependencies') && lockTouched) {
    if (opts.offline) notes.push('Dependency check skipped (--offline).');
    else {
      const deps = await scanDependencies(opts.root, { fetchImpl: opts.fetchImpl });
      packagesChecked = deps.checked;
      detections.push(...deps.detections);
      if (deps.error) notes.push(`Dependency check skipped: ${deps.error}`);
    }
  }

  detections.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return { detections, filesScanned: files.length, packagesChecked, durationMs: Date.now() - started, notes };
}

/** Names exported from modules that implement idempotency keys, e.g. withPaymentGuard. */
export function buildContext(files: SourceFile[]): ProjectContext {
  const idempotencyHelpers = new Set<string>();
  for (const f of files) {
    if (!JS_TS.test(f.path) || TEST_PATH.test(f.path) || !/idempoten/i.test(f.text)) continue;
    for (const m of f.text.matchAll(/\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|\bexport\s+(?:const|let)\s+([A-Za-z_$][\w$]*)/g)) {
      idempotencyHelpers.add((m[1] ?? m[2])!);
    }
  }
  return { idempotencyHelpers };
}

export const meetsThreshold = (sev: Severity, failOn: Severity) => SEVERITY_RANK[sev] >= SEVERITY_RANK[failOn];

/** When there is no lockfile we can read, say so instead of reporting a clean result. */
export function missingLockfileNote(root: string): string | null {
  const has = (f: string) => existsSync(join(root, f));
  if (SUPPORTED_LOCKFILES.some(has) || !has('package.json')) return null;
  const other = ['bun.lock', 'bun.lockb'].find(has);
  return other
    ? `Dependency check skipped: ${other} is not supported yet (npm, pnpm and yarn lockfiles are).`
    : 'Dependency check skipped: no lockfile. Run npm, pnpm or yarn install to create one.';
}
