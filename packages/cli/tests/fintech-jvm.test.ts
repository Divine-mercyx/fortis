import { describe, expect, it } from 'vitest';

import { findRule, fixFor } from '@fortis/shared';

import { jvmCode } from '../src/rules/fintech-jvm';
import { FILE_RULES } from '../src/rules/index';
import { emptyContext, TEST_PATH } from '../src/rules/types';

const flagged = (path: string, text: string) => {
  const file = { path, text, lines: text.split('\n') };
  return FILE_RULES.filter((r) => r.appliesTo.test(path)).flatMap((r) => r.run(file, emptyContext())).map((d) => `${d.ruleId}:${d.line}`);
};

describe('reading strings', () => {
  it("keeps Kotlin's template values, and blanks everything else", () => {
    expect(jvmCode('log.info("bvn $bvn and ${user.nin}")')).toContain('bvn');
    expect(jvmCode('log.info("bvn $bvn and ${user.nin}")')).toContain('user.nin');
    expect(jvmCode('log.info("the bvn")')).not.toContain('bvn');
  });
});

describe('what the rules leave alone', () => {
  it('honours an ignore comment', () => {
    expect(flagged('src/A.java', 'class A { int otp = new Random().nextInt(9); }')).toEqual(['FX-OTP-001:1']);
    expect(flagged('src/A.java', 'class A { int otp = new Random().nextInt(9); } // fortis-ignore')).toEqual([]);
    expect(flagged('src/A.kt', 'val otp = Random().nextInt(9) // fortis-ignore')).toEqual([]);
  });

  it('accepts SecureRandom, in both languages', () => {
    expect(flagged('src/A.java', 'class A { SecureRandom otp = new SecureRandom(); }')).toEqual([]);
    expect(flagged('src/A.kt', 'val otp = SecureRandom()')).toEqual([]);
  });

  it("skips staff screens for ownership, but not a folder called backend", () => {
    const code = '@RestController\nclass A {\n  @GetMapping("/{id}")\n  public Loan get(@PathVariable Long id) {\n    return loanRepository.findById(id).orElseThrow();\n  }\n}\n';
    expect(flagged('src/admin/LoanController.java', code)).toEqual([]);
    expect(flagged('src/StaffLoanController.java', code)).toEqual([]);
    expect(flagged('backend/src/LoanController.java', code)).toEqual(['FX-OWN-001:5']);
  });

  it('does not run on other languages', () => {
    expect(flagged('src/a.py', 'otp = new Random().nextInt(9)')).toEqual([]);
  });

  it('recognises test files', () => {
    for (const path of ['src/test/java/WalletTest.java', 'src/main/WalletTest.java', 'src/main/WalletTests.kt', 'src/main/WalletIT.java', 'integration-tests/src/Wallet.java']) expect(TEST_PATH.test(path), path).toBe(true);
    for (const path of ['src/main/Wallet.java', 'src/main/Contest.java', 'src/main/Audit.kt']) expect(TEST_PATH.test(path), path).toBe(false);
  });
});

describe('the fix shown for a finding', () => {
  it("uses Spring's own words", () => {
    for (const file of ['a.java', 'a.kt']) {
      expect(fixFor(findRule('FX-OWN-001')!, file)).toContain('@PreAuthorize');
      expect(fixFor(findRule('FX-HOOK-001')!, file)).toContain('MessageDigest.isEqual');
      expect(fixFor(findRule('FX-TXN-001')!, file)).toContain('@Transactional');
      expect(fixFor(findRule('FX-OTP-001')!, file)).toContain('SecureRandom');
    }
    expect(fixFor(findRule('FX-OTP-001')!, 'a.js')).not.toContain('SecureRandom');
  });
});
