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

import { ALL_LANGUAGES, loadGrammars } from '../src/analysis/parser';
import { createProject } from '../src/analysis/project';
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
  SEERBIT_LIVE: ['SBSECK', rand(40)].join('_'),
  SEERBIT_TEST: ['SBTESTSECK', rand(40)].join('_'),
  SEERBIT_PUBLIC: ['SBPUBK', rand(40)].join('_'),
  OPAY_PRIVATE: ['OPAY', 'PRV', rand(30, '0123456789')].join(''),
  OPAY_PUBLIC: ['OPAY', 'PUB', rand(30, '0123456789')].join(''),
  SQUAD_SANDBOX: ['sandbox', 'sk', rand(44, '0123456789abcdef')].join('_'),
  MONNIFY_PROD: ['MK', 'PROD', rand(10, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')].join('_'),
  AWS_KEY: `AKIA${rand(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}`,
  GH_TOKEN: `ghp_${rand(36)}`,
  GENERIC: rand(28),
  SENDGRID: ['SG', rand(22), rand(43)].join('.'),
  MAILGUN: `key-${rand(32, '0123456789abcdef')}`,
  RESEND: ['re', rand(8), rand(24)].join('_'),
  SLACK_HOOK: ['https://hooks.slack.com/services', `T${rand(9, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}`, `B${rand(9, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}`, rand(24)].join('/'),
  DISCORD_HOOK: ['https://discord.com/api/webhooks', rand(18, '0123456789'), rand(68)].join('/'),
  TELEGRAM: `${rand(10, '0123456789')}:AA${rand(33)}`,
  OPENAI: ['sk', 'proj', rand(48)].join('-'),
  ANTHROPIC: ['sk', 'ant', 'api03', rand(93)].join('-'),
  AZURE_STORAGE: `DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=${rand(86)}==`,
  DIGITALOCEAN: ['dop', 'v1', rand(64, '0123456789abcdef')].join('_'),
  NPM: ['npm', rand(36)].join('_'),
  PYPI: `pypi-${['AgEI', 'cHlwaS5vcmc'].join('')}${rand(60)}`,
  RUBYGEMS: ['rubygems', rand(48, '0123456789abcdef')].join('_'),
  DOCKER: ['dckr', 'pat', rand(27)].join('_'),
  TWILIO_TOKEN: rand(32, '0123456789abcdef'),
  SUPABASE_SERVICE: [
    Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'),
    Buffer.from(JSON.stringify({ iss: 'supabase', role: 'service_role' })).toString('base64url'),
    rand(43),
  ].join('.'),
  SUPABASE_ANON: [
    Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'),
    Buffer.from(JSON.stringify({ iss: 'supabase', role: 'anon' })).toString('base64url'),
    rand(43),
  ].join('.'),
  LIVE_PLACEHOLDER: ['sk', 'live', 'X'.repeat(25)].join('_'),
  TEST_PLACEHOLDER: ['sk', 'test', `${'X'.repeat(20)}5678`].join('_'),
  WEBHOOK_SECRET: ['whsec', rand(32)].join('_'),
};

type Score = { tp: number; fp: number; fn: number; misses: string[]; falsePositives: string[] };

/** Scored per language, so a strong JavaScript score can't hide a weak Python one. */
const scoreKey = (ruleId: string, path: string) => (/\.py$/.test(path) ? `${ruleId}:py` : ruleId);

export async function runBench(): Promise<Record<string, Score>> {
  await loadGrammars(ALL_LANGUAGES);
  const scores: Record<string, Score> = {};
  for (const ruleId of readdirSync(casesDir)) {
    const rules = FILE_RULES.filter((r) => r.id === ruleId);
    if (!rules.length) throw new Error(`bench/cases/${ruleId}: no rule with that ID`);
    const files: SourceFile[] = readdirSync(join(casesDir, ruleId)).map((name) => {
      const text = readFileSync(join(casesDir, ruleId, name), 'utf8').replace(/\{\{(\w+)\}\}/g, (_, k: string) => FAKES[k] ?? k);
      // A realistic app path, so path-based rules (money words, test folders) behave as in a repo.
      return { path: `src/${name.replace(/\.(txt)$/, '')}`, text, lines: text.split(/\r?\n/) };
    });
    const ctx = files.length ? buildContext(files) : emptyContext();
    // Each folder is one small project, so a case can follow a call into another file in it.
    ctx.project = createProject(files.map((f) => f.path), (p) => files.find((f) => f.path === p) ?? null);
    for (const f of files) {
      const s = (scores[scoreKey(ruleId, f.path)] ??= { tp: 0, fp: 0, fn: 0, misses: [], falsePositives: [] });
      const expected = new Set(f.lines.flatMap((l, i) => (l.includes('@hit') ? [i + 1] : [])));
      const flagged = new Set(
        rules.flatMap((rule) =>
          rule.appliesTo.test(f.path) && !(rule.skipTests && TEST_PATH.test(f.path))
            ? rule.run(f, ctx).filter((d) => d.ruleId === ruleId).map((d) => d.line)
            : [],
        ),
      );
      for (const line of flagged) {
        if (expected.has(line)) s.tp++;
        else { s.fp++; s.falsePositives.push(`${f.path}:${line}`); }
      }
      for (const line of expected) if (!flagged.has(line)) { s.fn++; s.misses.push(`${f.path}:${line}`); }
    }
  }
  return scores;
}

const pct = (n: number) => `${Math.round(n * 100)}%`.padStart(5);
export const precision = (s: Score) => (s.tp + s.fp ? s.tp / (s.tp + s.fp) : 1);
export const recall = (s: Score) => (s.tp + s.fn ? s.tp / (s.tp + s.fn) : 1);

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const scores = await runBench();
  const update = process.argv.includes('--update');
  const floors: Record<string, { precision: number; recall: number }> = update ? {} : JSON.parse(readFileSync(thresholdsFile, 'utf8'));
  let failed = false;
  console.log(`${'rule'.padEnd(15)} ${'cases'.padStart(5)} ${'prec'.padStart(5)} ${'recall'.padStart(6)}  notes`);
  for (const [id, s] of Object.entries(scores)) {
    const p = precision(s);
    const r = recall(s);
    const floor = floors[id];
    const bad = floor && (p < floor.precision - 1e-9 || r < floor.recall - 1e-9);
    if (bad) failed = true;
    if (update) floors[id] = { precision: Math.round(p * 1000) / 1000, recall: Math.round(r * 1000) / 1000 };
    const notes = [...s.falsePositives.map((x) => `FP ${x}`), ...s.misses.map((x) => `missed ${x}`)].join(', ');
    console.log(`${id.padEnd(15)} ${String(s.tp + s.fn).padStart(5)} ${pct(p)} ${pct(r).padStart(6)}  ${bad ? 'BELOW FLOOR ' : ''}${notes}`);
  }
  if (update) {
    writeFileSync(thresholdsFile, `${JSON.stringify(floors, null, 2)}\n`);
    console.log(`\nSaved floors to ${thresholdsFile}`);
  } else if (failed) {
    console.error('\nA rule got less accurate. Fix it, or run with --update if the change is intended.');
    process.exit(1);
  }
}
