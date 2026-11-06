import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { controlsFor, findRule } from '@fortis/shared';
import { describe, expect, it } from 'vitest';

import { precision, recall, runBench } from '../bench/run';

const floors = JSON.parse(readFileSync(join(__dirname, '../bench/thresholds.json'), 'utf8')) as Record<string, { precision: number; recall: number }>;

describe('accuracy benchmark', () => {
  const scores = runBench();
  for (const [id, s] of Object.entries(scores)) {
    it(`${id} keeps its precision and recall`, () => {
      expect(floors[id], `no floor recorded for ${id}; run pnpm bench --update`).toBeDefined();
      expect(precision(s)).toBeGreaterThanOrEqual(floors[id]!.precision - 1e-9);
      expect(recall(s)).toBeGreaterThanOrEqual(floors[id]!.recall - 1e-9);
    });
  }

  for (const rule of ['FX-MONEY-001', 'FX-PCI-001', 'FX-REF-001', 'FX-AMT-001']) {
    it(`${rule} has at least 20 cases, 95% precision, and an explanation and compliance mapping`, () => {
      const parts = Object.entries(scores).filter(([id]) => id.replace(/:py$/, '') === rule).map(([, s]) => s);
      expect(parts.reduce((n, s) => n + s.tp + s.fn, 0)).toBeGreaterThanOrEqual(20);
      const tp = parts.reduce((n, s) => n + s.tp, 0);
      const fp = parts.reduce((n, s) => n + s.fp, 0);
      expect(tp / (tp + fp)).toBeGreaterThanOrEqual(0.95);
      expect(findRule(rule)?.summary).toBeTruthy();
      expect(findRule(rule)?.fix).toBeTruthy();
      expect(controlsFor(rule).some((c) => c.framework === 'pci' || c.framework === 'cbn')).toBe(true);
    });
  }
});
