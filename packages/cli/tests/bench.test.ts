import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { controlsFor, findRule } from '@fortis/shared';
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
      const rule = id.replace(/:[a-z]+$/, '');
      cases[rule] = (cases[rule] ?? 0) + s.tp + s.fn;
    }
    expect(Object.entries(cases).filter(([, n]) => n < 20)).toEqual([]);
    for (const rule of FILE_RULES) expect(cases[rule.id], `${rule.id} has no benchmark cases`).toBeDefined();
  });

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

  for (const rule of ['FX-OWN-001', 'FX-HOOK-001', 'FX-TXN-001', 'FX-PII-002', 'FX-OTP-001', 'FX-IDEM-001']) {
    for (const language of ['go', 'cs']) {
      it(`${rule} on ${language} has 95% precision and 90% recall`, () => {
        const s = scores[`${rule}:${language}`];
        expect(s, `no ${language} cases for ${rule}`).toBeDefined();
        expect(s!.tp + s!.fn).toBeGreaterThanOrEqual(5);
        expect(precision(s!)).toBeGreaterThanOrEqual(0.95);
        expect(recall(s!)).toBeGreaterThanOrEqual(0.9);
      });
    }
  }
});
