/**
 * Real-world benchmark. Scans open-source fintech and payments projects, pinned to fixed commits, and
 * compares the findings with bench/corpus.json, where each one has been reviewed as right or wrong.
 *
 *   pnpm --filter fortis-watchdog corpus            # check
 *   pnpm --filter fortis-watchdog corpus --report   # also list each finding, masked, to review
 *   pnpm --filter fortis-watchdog corpus --update   # add new findings as "unreviewed"
 *
 * It fails when a reviewed finding disappears, or when a new one appears that nobody has reviewed.
 * Set FORTIS_CORPUS_DIR to keep the clones. Dependencies aren't compared, because advisories change
 * daily: each language only has to go on finding packages in its lockfiles.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { maskSnippet, type RulePack } from '@fortis/shared';

import { runScan } from '../src/scan';

export type Verdict = 'true' | 'false' | 'unreviewed';
export type Expected = { rule: string; file: string; line: number; verdict: Verdict; why?: string };
export type CorpusRepo = { repo: string; commit: string; languages: string[]; minPackages?: number; findings: Expected[] };
export type Corpus = { repos: CorpusRepo[] };

const here = dirname(fileURLToPath(import.meta.url));
const corpusFile = join(here, 'corpus.json');
const PACKS: RulePack[] = ['secrets', 'fintech', 'dependencies'];

const key = (f: { rule: string; file: string; line: number }) => `${f.rule}|${f.file}|${f.line}`;

/** How one repository's findings compare with what was recorded. */
export function compare(expected: Expected[], found: { rule: string; file: string; line: number }[]) {
  const seen = new Set(found.map(key));
  const known = new Set(expected.map(key));
  return {
    unexpected: found.filter((f) => !known.has(key(f))),
    missing: expected.filter((e) => !seen.has(key(e))),
    unreviewed: expected.filter((e) => e.verdict === 'unreviewed'),
  };
}

export type RuleScore = { correct: number; wrong: number; missed: number };

/** Precision and recall per rule, from reviewed findings only. */
export function scoreRules(repos: { expected: Expected[]; found: { rule: string; file: string; line: number }[] }[]): Record<string, RuleScore> {
  const scores: Record<string, RuleScore> = {};
  for (const { expected, found } of repos) {
    const seen = new Set(found.map(key));
    for (const e of expected) {
      if (e.verdict === 'unreviewed') continue;
      const s = (scores[e.rule] ??= { correct: 0, wrong: 0, missed: 0 });
      if (e.verdict === 'false') {
        if (seen.has(key(e))) s.wrong++;
      } else if (seen.has(key(e))) s.correct++;
      else s.missed++;
    }
  }
  return scores;
}

export const precisionOf = (s: RuleScore) => (s.correct + s.wrong ? s.correct / (s.correct + s.wrong) : 1);
export const recallOf = (s: RuleScore) => (s.correct + s.missed ? s.correct / (s.correct + s.missed) : 1);

function checkout(dir: string, repo: string, commit: string) {
  const path = join(dir, repo.replace('/', '__'));
  const git = (...args: string[]) => execFileSync('git', args, { cwd: path, stdio: 'ignore' });
  if (!existsSync(join(path, '.git'))) {
    mkdirSync(path, { recursive: true });
    git('init', '-q');
    git('remote', 'add', 'origin', `https://github.com/${repo}.git`);
  }
  let current = '';
  try {
    current = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: path, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    /* nothing checked out yet */
  }
  if (current !== commit) {
    git('fetch', '-q', '--depth', '1', 'origin', commit);
    // Long paths and line endings shouldn't depend on the machine doing the scan.
    git('-c', 'core.autocrlf=false', '-c', 'core.longpaths=true', 'checkout', '-q', '--force', 'FETCH_HEAD');
  }
  return path;
}

async function main() {
  const update = process.argv.includes('--update');
  const report = process.argv.includes('--report');
  const only = process.argv.find((a) => a.startsWith('--repo='))?.slice('--repo='.length);
  const dir = process.env.FORTIS_CORPUS_DIR ?? join(tmpdir(), 'fortis-corpus');
  const corpus = JSON.parse(readFileSync(corpusFile, 'utf8')) as Corpus;
  const results: { expected: Expected[]; found: { rule: string; file: string; line: number }[] }[] = [];
  const problems: string[] = [];

  for (const entry of corpus.repos) {
    if (only && entry.repo !== only) continue;
    const root = checkout(dir, entry.repo, entry.commit);
    const scan = await runScan({ root, scope: 'full', packs: PACKS, offline: process.env.FORTIS_CORPUS_OFFLINE === '1' });
    const detections = scan.detections.filter((d) => d.ruleId !== 'DEP-OSV');
    const found = detections.map((d) => ({ rule: d.ruleId, file: d.file, line: d.line }));
    const { unexpected, missing, unreviewed } = compare(entry.findings, found);
    results.push({ expected: entry.findings, found });
    console.log(`${entry.repo.padEnd(42)} ${String(scan.filesScanned).padStart(6)} files ${String(found.length).padStart(5)} findings ${String(scan.packagesChecked).padStart(5)} packages  ${unexpected.length} new, ${missing.length} gone, ${unreviewed.length} unreviewed`);
    if (report) {
      for (const d of detections) console.log(`    ${d.ruleId.padEnd(12)} ${d.file}:${d.line}  ${maskSnippet(d.snippet).slice(0, 150)}`);
    }
    for (const f of unexpected) problems.push(`${entry.repo}: new finding ${f.rule} at ${f.file}:${f.line}`);
    for (const m of missing) problems.push(`${entry.repo}: ${m.rule} at ${m.file}:${m.line} (${m.verdict}) is no longer found`);
    for (const u of unreviewed) problems.push(`${entry.repo}: ${u.rule} at ${u.file}:${u.line} hasn't been reviewed`);
    if (entry.minPackages && process.env.FORTIS_CORPUS_OFFLINE !== '1' && scan.packagesChecked < entry.minPackages) {
      problems.push(`${entry.repo}: only ${scan.packagesChecked} packages read from its lockfiles (expected at least ${entry.minPackages})`);
    }
    if (update) {
      entry.findings.push(...unexpected.map((f) => ({ ...f, verdict: 'unreviewed' as const })));
      entry.findings.sort((a, b) => key(a).localeCompare(key(b)));
    }
  }

  if (update) writeFileSync(corpusFile, `${JSON.stringify(corpus, null, 2)}\n`);

  console.log(`\n${'rule'.padEnd(14)} ${'right'.padStart(6)} ${'wrong'.padStart(6)} ${'missed'.padStart(6)} ${'prec'.padStart(6)} ${'recall'.padStart(6)}`);
  const pct = (n: number) => `${Math.round(n * 100)}%`.padStart(6);
  for (const [rule, s] of Object.entries(scoreRules(results)).sort()) {
    console.log(`${rule.padEnd(14)} ${String(s.correct).padStart(6)} ${String(s.wrong).padStart(6)} ${String(s.missed).padStart(6)} ${pct(precisionOf(s))} ${pct(recallOf(s))}`);
  }

  if (problems.length && !update) {
    console.error(`\n${problems.length} change(s) from the recorded results:`);
    for (const p of problems) console.error(`  ${p}`);
    console.error('\nFix the rule, or review the finding and record it in bench/corpus.json.');
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
