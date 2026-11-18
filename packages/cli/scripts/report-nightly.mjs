#!/usr/bin/env node
// Keeps one open issue for the nightly accuracy run: opens it on the first failure, comments on later
// ones, and closes it once a run passes. Usage: report-nightly.mjs success|failure <run URL>
// NEEDS (optional): the workflow's `toJSON(needs)`, so the issue can name the jobs that failed.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const ISSUE_TITLE = 'Nightly accuracy run is failing';
export const ISSUE_LABELS = ['area: stability', 'P1'];

/** Every job the report waits on (the workflow's `needs`), and what to do when it fails. */
export const CHECKS = {
  'live-osv': {
    name: 'Live OSV tests',
    advice: 'something changed on OSV\'s side, such as its format, ecosystem names or rate limits. Run `FORTIS_LIVE_OSV=1 pnpm --filter fortis-watchdog exec vitest run tests/osv-live.test.ts`.',
  },
  'live-verify': {
    name: 'Live --verify tests',
    advice: 'a provider changed how it answers for a key `fortis scan --verify` asks about. Run `FORTIS_LIVE_VERIFY=1 pnpm --filter fortis-watchdog exec vitest run tests/verify-live.test.ts`. The working and revoked test keys are repository secrets; without them those checks are skipped.',
  },
  'live-resolve': {
    name: 'Live --resolve tests',
    advice: 'Gradle\'s or Maven\'s dependency output changed, or the runner image\'s tools did. Run `FORTIS_LIVE_RESOLVE=1 pnpm --filter fortis-watchdog exec vitest run tests/resolve-live.test.ts` with Java, Gradle and Maven installed.',
  },
  corpus: {
    name: 'Real-world corpus',
    advice: 'a rule\'s findings changed on the pinned repositories. Run `pnpm --filter fortis-watchdog corpus --report`, then fix the rule or record the review in `packages/cli/bench/corpus.json`.',
  },
};

/** The checks that didn't pass, by the workflow's job results; every check when the results aren't known. */
export function failedChecks(needs) {
  if (!needs) return Object.keys(CHECKS).map((id) => ({ id, ...CHECKS[id] }));
  return Object.entries(needs)
    .filter(([, job]) => job?.result !== 'success')
    .map(([id, job]) => ({ id, name: CHECKS[id]?.name ?? id, advice: CHECKS[id]?.advice, result: job?.result }));
}

const label = (c) => `**${c.name}**${c.result && c.result !== 'failure' ? ` (${c.result})` : ''}`;

/**
 * What to do, given the run's result, any issue already open, and each job's result when the workflow passes
 * them. Each entry is a set of `gh` arguments.
 */
export function plan(result, runUrl, openIssue, needs) {
  if (result === 'success') {
    if (!openIssue) return [];
    return [['issue', 'close', String(openIssue), '--comment', `The nightly run passes again: ${runUrl}`]];
  }
  const failed = failedChecks(needs);
  if (openIssue) {
    const which = needs && failed.length ? ` Failed: ${failed.map(label).join(', ')}.` : '';
    return [['issue', 'comment', String(openIssue), '--body', `It failed again: ${runUrl}${which}`]];
  }
  const intro = needs
    ? [`Failed: ${failed.map(label).join(', ')}.`]
    : [`It runs ${failed.length} checks. The job that failed says which one this is:`];
  const body = [
    `The nightly run failed: ${runUrl}`,
    '',
    ...intro,
    '',
    ...failed.map((c) => `- **${c.name}:** ${c.advice ?? 'see the job\'s log.'}`),
    '',
    'This issue closes itself when a run passes.',
  ].join('\n');
  return [['issue', 'create', '--title', ISSUE_TITLE, '--body', body, ...ISSUE_LABELS.flatMap((l) => ['--label', l])]];
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [result, runUrl] = process.argv.slice(2);
  let needs;
  try {
    needs = process.env.NEEDS ? JSON.parse(process.env.NEEDS) : undefined;
  } catch {
    needs = undefined;
  }
  const gh = (args) => execFileSync('gh', args, { encoding: 'utf8' });
  const open = JSON.parse(gh(['issue', 'list', '--state', 'open', '--search', `"${ISSUE_TITLE}" in:title`, '--json', 'number,title']));
  const existing = open.find((i) => i.title === ISSUE_TITLE)?.number;
  for (const args of plan(result, runUrl, existing, needs)) console.log(gh(args).trim());
}
