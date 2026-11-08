import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { precision, recall, runBench } from '../bench/run';
import { FILE_RULES } from '../src/rules/index';

const floors = JSON.parse(readFileSync(join(__dirname, '../bench/thresholds.json'), 'utf8')) as Record<string, { precision: number; recall: number }>;

const scores = await runBench();

describe('accuracy benchmark', () => {
  for (const [id, s] of Object.entries(scores)) {
    it(`${id} keeps its precision and recall`, () => {
      expect(floors[id], `no floor recorded for ${id}; run pnpm bench --update`).toBeDefined();
      expect(precision(s)).toBeGreaterThanOrEqual(floors[id]!.precision - 1e-9);
      expect(recall(s)).toBeGreaterThanOrEqual(floors[id]!.recall - 1e-9);
    });
  }

  it('has at least 20 cases for every rule', () => {
    const cases: Record<string, number> = {};
    for (const [id, s] of Object.entries(scores)) {
      const rule = id.replace(/:py$/, '');
      cases[rule] = (cases[rule] ?? 0) + s.tp + s.fn;
    }
    expect(Object.entries(cases).filter(([, n]) => n < 20)).toEqual([]);
    for (const rule of FILE_RULES) expect(cases[rule.id], `${rule.id} has no benchmark cases`).toBeDefined();
  });
});
