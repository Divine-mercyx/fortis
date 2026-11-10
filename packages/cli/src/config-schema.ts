import { SEVERITIES } from '@fortis/shared';

/*
 * What .fortis.json can hold. The same schema is published as fortis.schema.json for editors, and a
 * test keeps the two in step. Checked by hand here, so the CLI needs no schema library.
 */

export const SCHEMA_URL = 'https://cdn.jsdelivr.net/npm/fortis-watchdog/fortis.schema.json';

export const CONFIG_JSON_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: SCHEMA_URL,
  title: 'Fortis project settings (.fortis.json)',
  type: 'object',
  additionalProperties: false,
  properties: {
    $schema: { type: 'string', description: 'Where editors find this schema.' },
    projectId: { type: 'string', description: 'The Fortis project this repository belongs to. Written by fortis init.' },
    apiUrl: { type: 'string', format: 'uri', description: 'The Fortis API address, if it is not the default.' },
    failOn: { type: 'string', enum: [...SEVERITIES], default: 'critical', description: 'Block a push or build at this severity or above.' },
    ignore: { type: 'array', items: { type: 'string' }, description: 'Paths to leave out of scans, as globs. For example: fixtures/**' },
    target: { type: 'string', format: 'uri', description: 'The default staging URL for fortis test and fortis access.' },
  },
} as const;

export type ConfigIssue = { key: string; message: string };

const distance = (a: string, b: string) => {
  let row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const next = [i];
    for (let j = 1; j <= b.length; j++) next[j] = Math.min(row[j]! + 1, next[j - 1]! + 1, row[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    row = next;
  }
  return row[b.length]!;
};

/** The closest allowed value, if it's close enough to be a typo. Ignores case, so "failon" finds failOn. */
export function didYouMean(word: string, options: readonly string[]): string | null {
  let best: string | null = null;
  let bestDistance = Infinity;
  for (const option of options) {
    const d = distance(word.toLowerCase(), option.toLowerCase());
    if (d < bestDistance) {
      best = option;
      bestDistance = d;
    }
  }
  return bestDistance <= Math.max(2, Math.floor(word.length / 3)) ? best : null;
}

const hint = (word: string, options: readonly string[]) => {
  const guess = didYouMean(word, options);
  return guess ? ` Did you mean "${guess}"?` : '';
};

const isHttpUrl = (value: string) => {
  try {
    return /^https?:$/.test(new URL(value).protocol);
  } catch {
    return false;
  }
};

/** Every problem with parsed .fortis.json contents: unknown keys and wrong types. */
export function validateProjectConfig(raw: unknown): ConfigIssue[] {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return [{ key: '', message: 'It must be a JSON object, like { "failOn": "critical" }.' }];
  const known = Object.keys(CONFIG_JSON_SCHEMA.properties);
  const issues: ConfigIssue[] = [];
  const wrongType = (key: string, wanted: string) => issues.push({ key, message: `"${key}" must be ${wanted}.` });
  for (const [key, value] of Object.entries(raw)) {
    if (!known.includes(key)) {
      issues.push({ key, message: `"${key}" isn't a setting, so it does nothing.${hint(key, known)}` });
      continue;
    }
    if (key === 'failOn') {
      if (typeof value !== 'string' || !SEVERITIES.includes(value as never)) {
        issues.push({ key, message: `"failOn" must be one of: ${SEVERITIES.join(', ')}.${typeof value === 'string' ? hint(value, SEVERITIES) : ''}` });
      }
    } else if (key === 'ignore') {
      if (!Array.isArray(value) || value.some((g) => typeof g !== 'string')) wrongType(key, 'a list of paths, like ["fixtures/**"]');
    } else if (key === 'apiUrl' || key === 'target') {
      if (typeof value !== 'string' || !isHttpUrl(value)) wrongType(key, 'an http(s) URL');
    } else if (typeof value !== 'string') {
      wrongType(key, 'text');
    }
  }
  return issues;
}
