import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

// @ts-expect-error a plain script with no type declarations
import { CHECKS, failedChecks, plan } from '../scripts/report-nightly.mjs';

/*
 * The nightly run's issue says which of its checks failed and how to rerun that one (#88). It ran two checks when the
 * issue's text was written, and four now, so the workflow's job list and the script's are kept in step here.
 */

const URL = 'https://github.com/o/r/actions/runs/1';
const workflow = readFileSync(join(__dirname, '..', '..', '..', '.github', 'workflows', 'nightly.yml'), 'utf8');
const needs = (results: Record<string, string>) => Object.fromEntries(Object.entries(results).map(([id, result]) => [id, { result, outputs: {} }]));
const body = (steps: string[][]) => steps[0]![steps[0]!.indexOf('--body') + 1]!;

describe('the nightly issue names what failed', () => {
  it('opens an issue that names the failed job and gives only its advice', () => {
    const text = body(plan('failure', URL, undefined, needs({ 'live-osv': 'success', 'live-verify': 'failure', 'live-resolve': 'success', corpus: 'success' })));
    expect(text).toContain('Failed: **Live --verify tests**.');
    expect(text).toContain('tests/verify-live.test.ts');
    expect(text).not.toContain('osv-live');
    expect(text).not.toContain('corpus --report');
  });

  it('says when a job was cancelled or skipped rather than failed', () => {
    const text = body(plan('failure', URL, undefined, needs({ 'live-osv': 'cancelled', 'live-verify': 'success', 'live-resolve': 'failure', corpus: 'success' })));
    expect(text).toContain('Failed: **Live OSV tests** (cancelled), **Live --resolve tests**.');
  });

  it('names the failed jobs when it comments on an issue already open', () => {
    expect(plan('failure', URL, 12, needs({ 'live-osv': 'success', 'live-verify': 'success', 'live-resolve': 'success', corpus: 'failure' }))).toEqual([
      ['issue', 'comment', '12', '--body', `It failed again: ${URL} Failed: **Real-world corpus**.`],
    ]);
  });

  it('lists every check when the job results are unknown', () => {
    const text = body(plan('failure', URL, undefined));
    expect(text).toContain('It runs 4 checks.');
    for (const c of Object.values(CHECKS) as { name: string }[]) expect(text).toContain(`**${c.name}:**`);
  });

  it('still names a job it has no advice for', () => {
    expect(failedChecks(needs({ 'live-new': 'failure' }))).toEqual([{ id: 'live-new', name: 'live-new', advice: undefined, result: 'failure' }]);
  });
});

describe('the workflow and the script agree on the checks', () => {
  it('the report waits on every check, and only those', () => {
    const waitsOn = /report:[\s\S]*?needs: \[([^\]]+)\]/.exec(workflow)![1]!.split(',').map((s) => s.trim());
    expect(waitsOn.sort()).toEqual(Object.keys(CHECKS).sort());
  });

  it('a run passes only when every check passed', () => {
    const result = /RESULT: \$\{\{ \((.*)\) && 'success'/.exec(workflow)![1]!;
    for (const id of Object.keys(CHECKS)) expect(result).toContain(`needs.${id}.result == 'success'`);
  });

  it('passes each job’s result to the script', () => {
    expect(workflow).toContain('NEEDS: ${{ toJSON(needs) }}');
  });
});
