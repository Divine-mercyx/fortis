#!/usr/bin/env node
// Keeps one open issue for the nightly accuracy run: opens it on the first failure, comments on later
// ones, and closes it once a run passes. Usage: report-nightly.mjs success|failure <run URL>
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const ISSUE_TITLE = 'Nightly accuracy run is failing';
export const ISSUE_LABELS = ['area: stability', 'P1'];

/** What to do, given the run's result and any issue already open. Each entry is a set of `gh` arguments. */
export function plan(result, runUrl, openIssue) {
  if (result === 'success') {
    if (!openIssue) return [];
    return [['issue', 'close', String(openIssue), '--comment', `The nightly run passes again: ${runUrl}`]];
  }
  if (openIssue) return [['issue', 'comment', String(openIssue), '--body', `It failed again: ${runUrl}`]];
  const body = [
    `The nightly run failed: ${runUrl}`,
    '',
    'It runs two checks. The job that failed says which one this is:',
    '',
    '- **Live OSV tests:** something changed on OSV\'s side, such as its format, ecosystem names or rate limits. Run `FORTIS_LIVE_OSV=1 pnpm --filter fortis-watchdog exec vitest run tests/osv-live.test.ts`.',
    '- **Real-world corpus:** a rule\'s findings changed on the pinned repositories. Run `pnpm --filter fortis-watchdog corpus --report`, then fix the rule or record the review in `packages/cli/bench/corpus.json`.',
    '',
    'This issue closes itself when a run passes.',
  ].join('\n');
  return [['issue', 'create', '--title', ISSUE_TITLE, '--body', body, ...ISSUE_LABELS.flatMap((l) => ['--label', l])]];
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [result, runUrl] = process.argv.slice(2);
  const gh = (args) => execFileSync('gh', args, { encoding: 'utf8' });
  const open = JSON.parse(gh(['issue', 'list', '--state', 'open', '--search', `"${ISSUE_TITLE}" in:title`, '--json', 'number,title']));
  const existing = open.find((i) => i.title === ISSUE_TITLE)?.number;
  for (const args of plan(result, runUrl, existing)) console.log(gh(args).trim());
}
