/**
 * Turns false positives marked in the dashboard into candidate benchmark cases.
 *
 *   DATABASE_URL=... pnpm --filter @fortis/api false-positive-shapes > shapes.json
 *   pnpm --filter fortis-watchdog feedback shapes.json
 *
 * Each shape the rule still flags is written to bench/candidates/<RULE>/. Review one, turn it into
 * realistic code if the shape alone isn't enough, and move it to bench/cases/<RULE>/ with no @hit.
 * The benchmark then fails until the rule stops flagging it.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { FalsePositiveShape } from '@fortis/shared';

import { FILE_RULES } from '../src/rules/index';
import { emptyContext } from '../src/rules/types';

const here = dirname(fileURLToPath(import.meta.url));

/** True when the rule flags this shape as it stands. */
export function stillFlagged(shape: FalsePositiveShape): boolean {
  const path = `src/shape.${shape.extension}`;
  const file = { path, text: shape.shape, lines: [shape.shape] };
  return FILE_RULES.filter((r) => r.id === shape.rule && r.appliesTo.test(path)).some((r) => r.run(file, emptyContext()).some((d) => d.ruleId === shape.rule));
}

const COMMENT_STYLE: Record<string, string> = { py: '#', rb: '#', yml: '#', yaml: '#', env: '#', sh: '#' };

/** Sorts shapes into those to review now, and those the rule no longer flags or can't be tried alone. */
export function candidates(shapes: FalsePositiveShape[]) {
  const flagged = shapes.filter(stillFlagged);
  return {
    flagged,
    other: shapes.length - flagged.length,
    files: flagged.map((s) => {
      const comment = COMMENT_STYLE[s.extension] ?? '//';
      const id = createHash('sha256').update(`${s.rule}|${s.extension}|${s.shape}`).digest('hex').slice(0, 10);
      return { path: join(s.rule, `shape-${id}.${s.extension}`), text: `${comment} From dashboard feedback: ${s.workspaces} workspaces marked this shape a false positive.\n${s.shape}\n` };
    }),
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const input = process.argv[2];
  if (!input) {
    console.error('Usage: pnpm --filter fortis-watchdog feedback <shapes.json>');
    process.exit(2);
  }
  const shapes = JSON.parse(readFileSync(input, 'utf8')) as FalsePositiveShape[];
  const { files, other } = candidates(shapes);
  for (const f of files) {
    const path = join(here, 'candidates', f.path);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, f.text);
    console.log(`bench/candidates/${f.path.replace(/\\/g, '/')}`);
  }
  console.log(`\n${files.length} shape(s) to review. ${other} other(s) aren't flagged on their own, so they need surrounding code to reproduce.`);
}
