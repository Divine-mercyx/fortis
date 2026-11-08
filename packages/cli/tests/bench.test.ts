import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { precision, recall, runBench } from '../bench/run';

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

  for (const rule of ['FX-OWN-001', 'FX-HOOK-001', 'FX-TXN-001', 'FX-PII-002', 'FX-OTP-001', 'FX-IDEM-001']) {
    it(`${rule} on PHP has 95% precision and 90% recall`, () => {
      const s = scores[`${rule}:php`];
      expect(s, `no PHP cases for ${rule}`).toBeDefined();
      expect(s!.tp + s!.fn).toBeGreaterThanOrEqual(5);
      expect(precision(s!)).toBeGreaterThanOrEqual(0.95);
      expect(recall(s!)).toBeGreaterThanOrEqual(0.9);
    });
  }
});
