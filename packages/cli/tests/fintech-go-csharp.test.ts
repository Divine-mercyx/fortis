import { describe, expect, it } from 'vitest';

import { findRule, fixFor } from '@fortis/shared';

import { csCode } from '../src/rules/fintech-csharp';
import { FILE_RULES } from '../src/rules/index';
import { emptyContext, TEST_PATH } from '../src/rules/types';
import { runScan } from '../src/scan';

const flagged = (path: string, text: string) => {
  const file = { path, text, lines: text.split('\n') };
  return FILE_RULES.filter((r) => r.appliesTo.test(path)).flatMap((r) => r.run(file, emptyContext())).map((d) => `${d.ruleId}:${d.line}`);
};

describe('reading C# strings', () => {
  it('keeps the values in an interpolated string, and blanks the rest', () => {
    expect(csCode('Log($"bvn {user.Bvn} and {nin}");')).toContain('user.Bvn');
    expect(csCode('Log($"bvn {user.Bvn}");')).not.toContain('bvn ');
    expect(csCode('Log("user.Bvn");')).not.toContain('user.Bvn');
  });
});

describe('rules stay in their own language', () => {
  it('does not run Go patterns on C#, or C# patterns on Go', () => {
    expect(flagged('src/a.go', 'var r = new Random().Next(); // otp')).toEqual([]);
    expect(flagged('src/a.cs', 'otp := rand.Intn(9) // "math/rand"')).toEqual([]);
  });

  it('honours an ignore comment', () => {
    expect(flagged('src/a.go', 'package a\nimport "math/rand"\nfunc f() { otp := rand.Intn(9) } // fortis-ignore')).toEqual([]);
    expect(flagged('src/a.cs', 'var otp = new Random().Next(); // fortis-ignore')).toEqual([]);
  });

  it("recognises each language's test files, so the fintech rules skip them", () => {
    for (const path of ['pkg/wallet_test.go', 'pkg/testdata/a.go', 'BTCPayServer.Tests/Wallet.cs', 'src/App.UnitTests/Wallet.cs', 'src/WalletTests.cs', 'src/WalletTest.cs']) expect(TEST_PATH.test(path), path).toBe(true);
    for (const path of ['pkg/wallet.go', 'src/Wallet.cs', 'src/Contest.cs', 'src/Latest/Wallet.cs']) expect(TEST_PATH.test(path), path).toBe(false);
  });
});

describe('the fix shown for a finding', () => {
  it("uses the language's own words", () => {
    const hook = findRule('FX-HOOK-001')!;
    expect(fixFor(hook, 'a.go')).toContain('hmac.Equal');
    expect(fixFor(hook, 'a.cs')).toContain('FixedTimeEquals');
    expect(fixFor(hook, 'a.py')).toContain('compare_digest');
    expect(fixFor(findRule('FX-OTP-001')!, 'a.go')).toContain('crypto/rand');
    expect(fixFor(findRule('FX-OTP-001')!, 'a.cs')).toContain('RandomNumberGenerator');
    expect(fixFor(findRule('FX-TXN-001')!, 'a.go')).toContain('db.Transaction');
    expect(fixFor(findRule('FX-TXN-001')!, 'a.cs')).toContain('BeginTransaction');
    expect(fixFor(findRule('FX-OWN-001')!, 'a.cs')).toContain('[Authorize]');
  });
});

describe('the note about languages not covered', () => {
  it('no longer lists Go or C#', async () => {
    const { execFileSync } = await import('node:child_process');
    const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'fortis-lang-'));
    try {
      execFileSync('git', ['init', '-q', dir]);
      for (const name of ['a.go', 'b.cs', 'c.php']) writeFileSync(join(dir, name), '// nothing\n');
      execFileSync('git', ['add', '-A'], { cwd: dir });
      const scan = await runScan({ root: dir, scope: 'full', packs: ['fintech'], offline: true });
      const note = scan.notes.find((n) => n.includes('Fintech code rules cover'))!;
      expect(note).toContain('JavaScript, TypeScript, Python, Go and C#');
      expect(note).toContain('1 PHP');
      expect(note).not.toMatch(/\d+ (Go|C#)/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
