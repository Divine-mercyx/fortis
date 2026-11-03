import { SEVERITY_RANK, type RulePack, type Severity } from '@fortis/shared';

import { scanDependencies } from './rules/dependencies';
import { rulesFor } from './rules/index';
import type { Detection } from './rules/types';
import { loadFiles } from './files';
import { allFiles, changedFiles } from './git';

export type ScanOptions = {
  root: string;
  scope: 'changed' | 'full';
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
  const paths = opts.scope === 'changed' ? changedFiles(opts.root) : allFiles(opts.root);
  const files = loadFiles(opts.root, paths, opts.ignore);
  const rules = rulesFor(opts.packs);

  const seen = new Set<string>();
  const detections: Detection[] = [];
  for (const file of files) {
    for (const rule of rules) {
      if (!rule.appliesTo.test(file.path)) continue;
      for (const d of rule.run(file)) {
        const key = `${d.ruleId}|${d.file}|${d.line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        detections.push(d);
      }
    }
  }

  let packagesChecked = 0;
  const lockTouched = opts.scope === 'full' || paths.includes('package-lock.json');
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

export const meetsThreshold = (sev: Severity, failOn: Severity) => SEVERITY_RANK[sev] >= SEVERITY_RANK[failOn];
