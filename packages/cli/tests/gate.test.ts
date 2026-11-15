import { describe, expect, it } from 'vitest';

import { exitCode, gateLines, type GateVerdict } from '../src/gate';

const strip = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, '');
const base = { enforced: true as const, policy: { minSeverity: 'high', blockLiveSecrets: true }, manageUrl: 'https://app.fortis.dev/projects/p1#release-gate' };
const finding = { findingId: 'f1', ruleId: 'FX-OWN-001', severity: 'critical', title: 'Money record read without an ownership check', file: 'src/transfers.ts', line: 41, liveSecret: false };

describe('the release gate decides the exit code when it is enforced', () => {
  it('fails on a failed gate and passes on a passed or excepted one, whatever --fail-on found', () => {
    expect(exitCode({ ...base, status: 'failed', blockingCount: 1, blocking: [finding] }, 0)).toBe(1);
    expect(exitCode({ ...base, status: 'passed', blockingCount: 0, blocking: [] }, 3)).toBe(0);
    expect(exitCode({ ...base, status: 'excepted', blockingCount: 1, blocking: [finding], exception: { reason: 'Hotfix', by: 'Ada', expiresAt: new Date().toISOString(), commit: null } }, 2)).toBe(0);
  });

  it('falls back to --fail-on without an enforced gate (Free, Core, no gate, upload failed)', () => {
    const off: GateVerdict = { enforced: false, reason: 'No release gate is turned on for this project.' };
    expect(exitCode(off, 0)).toBe(0);
    expect(exitCode(off, 2)).toBe(1);
    expect(exitCode(undefined, 1)).toBe(1);
    expect(exitCode(null, 0)).toBe(0);
  });
});

describe('what the CI log says', () => {
  it('names each blocking finding and where to go next on a failure', () => {
    const lines = gateLines({ ...base, status: 'failed', blockingCount: 1, blocking: [{ ...finding, liveSecret: true }] }).map(strip);
    expect(lines[0]).toBe('✖ Release gate failed: 1 open finding at the level this project blocks (high or critical findings and live leaked keys).');
    expect(lines[1]).toContain('CRITICAL  Money record read without an ownership check (live key)  src/transfers.ts:41');
    expect(lines.at(-1)).toContain('https://app.fortis.dev/projects/p1#release-gate');
  });

  it('says who approved an exception, why, and until when', () => {
    const lines = gateLines({ ...base, status: 'excepted', blockingCount: 2, blocking: [finding, finding], exception: { reason: 'Hotfix for the payout outage', by: 'Ada Okafor', expiresAt: '2026-11-16T10:00:00.000Z', commit: 'a1b2c3d' } }).map(strip);
    expect(lines[0]).toBe('! Release gate: 2 open findings would block this release, but Ada Okafor approved it.');
    expect(lines[1]).toBe('  Reason: Hotfix for the payout outage');
    expect(lines[2]).toBe('  Approval ends Mon, 16 Nov 2026 10:00:00 GMT and covers commit a1b2c3d only.');
  });

  it('caps a long list at ten, and is one line when it passes', () => {
    const many = Array.from({ length: 14 }, (_, i) => ({ ...finding, findingId: `f${i}` }));
    const lines = gateLines({ ...base, status: 'failed', blockingCount: 14, blocking: many }).map(strip);
    expect(lines.filter((l) => l.includes('CRITICAL'))).toHaveLength(10);
    expect(lines).toContain('    …and 4 more');
    expect(gateLines({ ...base, status: 'passed', blockingCount: 0, blocking: [] }).map(strip)).toEqual(['✔ Release gate passed (blocks high or critical findings and live leaked keys)']);
    expect(gateLines({ enforced: false, reason: 'x' })).toEqual([]);
  });
});
