import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { maskSnippet } from '@fortis/shared';

import { VERSION } from './env';
import type { Detection } from './rules/types';

export const BASELINE_FILE = '.fortis-baseline.json';

/**
 * Same identity the API uses: rule + file + masked line (not the line number, which shifts as
 * code moves). Keep this in step with apps/api/src/modules/ingest.service.ts.
 */
export function fingerprintOf(d: Pick<Detection, 'ruleId' | 'file' | 'snippet' | 'line'>): string {
  const file = d.file.replace(/\\/g, '/').replace(/^\.\//, '');
  const masked = d.snippet ? maskSnippet(d.snippet) : '';
  const anchor = masked ? masked.replace(/\s+/g, ' ').trim() : `line:${d.line ?? 0}`;
  return createHash('sha256').update(`${d.ruleId}|${file}|${anchor}`).digest('hex').slice(0, 40);
}

export type Baseline = { version: 1; createdAt: string; cliVersion: string; fingerprints: string[] };

export function readBaseline(root: string): Set<string> | null {
  const p = join(root, BASELINE_FILE);
  if (!existsSync(p)) return null;
  try {
    const b = JSON.parse(readFileSync(p, 'utf8')) as Baseline;
    return new Set(b.fingerprints);
  } catch {
    throw new Error(`${BASELINE_FILE} is not valid JSON`);
  }
}

export function writeBaseline(root: string, detections: Detection[]): number {
  const fingerprints = [...new Set(detections.map(fingerprintOf))].sort();
  const body: Baseline = { version: 1, createdAt: new Date().toISOString(), cliVersion: VERSION, fingerprints };
  writeFileSync(join(root, BASELINE_FILE), `${JSON.stringify(body, null, 2)}\n`);
  return fingerprints.length;
}

/** Splits findings into new ones (which can block) and ones already accepted in the baseline. */
export function splitByBaseline(detections: Detection[], baseline: Set<string> | null) {
  if (!baseline) return { fresh: detections, known: [] as Detection[] };
  const fresh: Detection[] = [];
  const known: Detection[] = [];
  for (const d of detections) (baseline.has(fingerprintOf(d)) ? known : fresh).push(d);
  return { fresh, known };
}
