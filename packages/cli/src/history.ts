import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

import { maskSnippet } from '@fortis/shared';

import { makeFilter } from './files';
import { genericSecretRule, paymentKeyRule } from './rules/secrets';
import type { Detection, SourceFile } from './rules/types';

export type HistoryResult = { detections: Detection[]; commitsScanned: number; stillPresent: number };

/**
 * Secrets anywhere in git history: every line ever added on any branch. A key that was
 * committed and later deleted is still readable by anyone who can clone the repository, so it
 * must be rotated. Each secret is reported once, at the commit that first introduced it.
 */
export async function scanHistory(root: string, opts: { since?: string; ignore?: string[]; currentFiles?: Map<string, string> } = {}): Promise<HistoryResult> {
  const keep = makeFilter(opts.ignore);
  const args = ['log', '-p', '--all', '--no-color', '--unified=0', '--no-ext-diff', '--format=commit %H', '--diff-filter=AM'];
  if (opts.since) args.push(`${opts.since}..HEAD`);
  const child = spawn('git', args, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] });
  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });

  // Oldest introduction wins: git log lists newest first, so later sightings overwrite earlier ones.
  const found = new Map<string, Detection>();
  let commit = '';
  let path = '';
  let added: string[] = [];
  let commits = 0;

  const flush = () => {
    if (!path || !added.length || !keep(path)) return void (added = []);
    const text = added.join('\n');
    const file: SourceFile = { path, text, lines: added };
    for (const rule of [paymentKeyRule, genericSecretRule]) {
      if (!rule.appliesTo.test(path)) continue;
      for (const d of rule.run(file, { idempotencyHelpers: new Set() })) {
        const key = `${d.ruleId}|${path}|${maskSnippet(d.snippet)}`;
        found.set(key, { ...d, line: 0, commit, title: `${d.title} (in git history)` });
      }
    }
    added = [];
  };

  for await (const line of rl) {
    if (line.startsWith('commit ')) {
      flush();
      commit = line.slice(7).trim();
      commits++;
    } else if (line.startsWith('+++ ')) {
      flush();
      path = line.startsWith('+++ b/') ? line.slice(6) : '';
    } else if (line.startsWith('+') && path) {
      if (added.length < 20_000) added.push(line.slice(1));
    }
  }
  flush();
  await new Promise((resolve) => child.on('close', resolve));

  const detections = [...found.values()];
  let stillPresent = 0;
  for (const d of detections) {
    const current = opts.currentFiles?.get(d.file);
    if (current && current.includes(d.snippet.trim())) stillPresent++;
  }
  return { detections, commitsScanned: commits, stillPresent };
}
