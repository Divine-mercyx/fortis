/**
 * Accuracy benchmark. Every folder in bench/cases is one rule; a line marked `@hit` must be
 * flagged by that rule, and a flag on any other line is a false positive. Prints precision and
 * recall per rule and fails if any rule drops below bench/thresholds.json.
 *
 *   pnpm --filter fortis-watchdog bench            # check
 *   pnpm --filter fortis-watchdog bench --update   # record current scores as the new floor
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { FILE_RULES } from '../src/rules/index';
import { emptyContext, TEST_PATH, type SourceFile } from '../src/rules/types';
import { buildContext } from '../src/scan';

const here = dirname(fileURLToPath(import.meta.url));
const casesDir = join(here, 'cases');
const thresholdsFile = join(here, 'thresholds.json');

// Key-shaped values are built at runtime so the repository never contains anything a secret scanner flags.
const rand = (n: number, abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') =>
  Array.from({ length: n }, (_, i) => abc[(i * 7 + 3) % abc.length]).join('');
const FAKES: Record<string, string> = {
  PAYSTACK_LIVE: ['sk', 'live', rand(40, '0123456789abcdef')].join('_'),
  PAYSTACK_TEST: ['sk', 'test', rand(40, '0123456789abcdef')].join('_'),
  STRIPE_LIVE: ['sk', 'live', `51${rand(97)}`].join('_'),
  STRIPE_RESTRICTED: ['rk', 'live', `51${rand(97)}`].join('_'),
  STRIPE_WEBHOOK: `whsec_${rand(32)}`,
  FLW_LIVE: `FLWSECK-${rand(32)}-X`,
  MONNIFY_PROD: ['MK', 'PROD', rand(10, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')].join('_'),
  AWS_KEY: `AKIA${rand(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}`,
  GH_TOKEN: `ghp_${rand(36)}`,
  GENERIC: rand(28),
};

type Score = { tp: number; fp: number; fn: number; misses: string[]; falsePositives: string[] };

export function runBench(): Record<string, Score> {
  const scores: Record<string, Score> = {};
  for (const ruleId of readdirSync(casesDir)) {
    const rule = FILE_RULES.find((r) => r.id === ruleId);
    if (!rule) throw new Error(`bench/cases/${ruleId}: no rule with that ID`);
    const files: SourceFile[] = readdirSync(join(casesDir, ruleId)).map((name) => {
      const text = readFileSync(join(casesDir, ruleId, name), 'utf8').replace(/\{\{(\w+)\}\}/g, (_, k: string) => FAKES[k] ?? k);
      // A realistic app path, so path-based rules (money words, test folders) behave as in a repo.
      return { path: `src/${name.replace(/\.(txt)$/, '')}`, text, lines: text.split('\n') };
    });
    const ctx = files.length ? buildContext(files) : emptyContext();
    const s: Score = { tp: 0, fp: 0, fn: 0, misses: [], falsePositives: [] };
    for (const f of files) {
      const expected = new Set(f.lines.flatMap((l, i) => (l.includes('@hit') ? [i + 1] : [])));
      const flagged = new Set(
        rule.appliesTo.test(f.path) && !(rule.skipTests && TEST_PATH.test(f.path))
          ? rule.run(f, ctx).filter((d) => d.ruleId === ruleId).map((d) => d.line)
          : [],
      );
      for (const line of flagged) {
        if (expected.has(line)) s.tp++;
        else { s.fp++; s.falsePositives.push(`${f.path}:${line}`); }
      }
      for (const line of expected) if (!flagged.has(line)) { s.fn++; s.misses.push(`${f.path}:${line}`); }
    }
    scores[ruleId] = s;
  }
  return scores;
}

const pct = (n: number) => `${Math.round(n * 100)}%`.padStart(5);
export const precision = (s: Score) => (s.tp + s.fp ? s.tp / (s.tp + s.fp) : 1);
export const recall = (s: Score) => (s.tp + s.fn ? s.tp / (s.tp + s.fn) : 1);

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const scores = runBench();
  const update = process.argv.includes('--update');
  const floors: Record<string, { precision: number; recall: number }> = update ? {} : JSON.parse(readFileSync(thresholdsFile, 'utf8'));
  let failed = false;
  console.log(`${'rule'.padEnd(12)} ${'cases'.padStart(5)} ${'prec'.padStart(5)} ${'recall'.padStart(6)}  notes`);
  for (const [id, s] of Object.entries(scores)) {
    const p = precision(s);
    const r = recall(s);
    const floor = floors[id];
    const bad = floor && (p < floor.precision - 1e-9 || r < floor.recall - 1e-9);
    if (bad) failed = true;
    if (update) floors[id] = { precision: Math.round(p * 1000) / 1000, recall: Math.round(r * 1000) / 1000 };
    const notes = [...s.falsePositives.map((x) => `FP ${x}`), ...s.misses.map((x) => `missed ${x}`)].join(', ');
    console.log(`${id.padEnd(12)} ${String(s.tp + s.fn).padStart(5)} ${pct(p)} ${pct(r).padStart(6)}  ${bad ? 'BELOW FLOOR ' : ''}${notes}`);
  }
  if (update) {
    writeFileSync(thresholdsFile, `${JSON.stringify(floors, null, 2)}\n`);
    console.log(`\nSaved floors to ${thresholdsFile}`);
  } else if (failed) {
    console.error('\nA rule got less accurate. Fix it, or run with --update if the change is intended.');
    process.exit(1);
  }
}
