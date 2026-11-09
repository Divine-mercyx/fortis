import { describe, expect, it } from 'vitest';

import { findRule, fixFor } from '@fortis/shared';

import { phpCode } from '../src/rules/fintech-php';
import { FILE_RULES } from '../src/rules/index';
import { emptyContext } from '../src/rules/types';

const flagged = (path: string, text: string) => {
  const file = { path, text, lines: text.split('\n') };
  return FILE_RULES.filter((r) => r.appliesTo.test(path)).flatMap((r) => r.run(file, emptyContext())).map((d) => `${d.ruleId}:${d.line}`);
};

describe('reading PHP strings', () => {
  it('keeps variables in double quotes, and blanks everything else', () => {
    expect(phpCode('Log::info("bvn {$user->bvn} and $nin");')).toContain('$user->bvn');
    expect(phpCode('Log::info("bvn {$user->bvn} and $nin");')).toContain('$nin');
    expect(phpCode("Log::info('$nin');")).not.toContain('$nin');
    expect(phpCode('Log::info("the bvn");')).not.toContain('bvn');
  });

  it('removes comments, but keeps attributes', () => {
    expect(phpCode('$a = 1; # $bvn')).not.toContain('$bvn');
    expect(phpCode('$a = 1; // $bvn')).not.toContain('$bvn');
    expect(phpCode('#[Route]\n$a = 1;')).toContain('Route');
  });
});

describe('what the rules leave alone', () => {
  const otp = '<?php\n$otp = rand(1000, 9999);';

  it('honours an ignore comment', () => {
    expect(flagged('src/a.php', otp)).toEqual(['FX-OTP-001:2']);
    expect(flagged('src/a.php', '<?php\n$otp = rand(1000, 9999); // fortis-ignore')).toEqual([]);
    expect(flagged('src/a.php', '<?php\n$otp = rand(1000, 9999); # fortis-ignore')).toEqual([]);
  });

  it('skips Blade templates, language files and config', () => {
    for (const path of ['resources/views/a.blade.php', 'lang/en/auth.php', 'resources/lang/en/a.php', 'config/services.php']) expect(flagged(path, otp), path).toEqual([]);
  });

  it('only looks for ownership in code that handles requests', () => {
    const code = '<?php\nfunction get($id) {\n  return Loan::findOrFail($id);\n}';
    expect(flagged('app/Http/Controllers/LoanController.php', code)).toEqual(['FX-OWN-001:3']);
    expect(flagged('app/Services/LoanService.php', code)).toEqual([]);
    expect(flagged('app/Http/Controllers/Auth/LoanController.php', code)).toEqual([]);
    expect(flagged('packages/Admin/src/Http/Controllers/LoanController.php', code)).toEqual([]);
    expect(flagged('app/Http/Requests/LoanRequest.php', code)).toEqual([]);
  });

  it('does not run on other languages, or other languages on PHP', () => {
    expect(flagged('src/a.js', '$otp = rand(1000, 9999);')).toEqual([]);
    expect(flagged('src/a.php', '<?php\n// Math.random otp\n$a = 1;')).toEqual([]);
  });
});

describe('the fix shown for a finding', () => {
  it("uses PHP's own words", () => {
    expect(fixFor(findRule('FX-OWN-001')!, 'a.php')).toContain('$this->authorize');
    expect(fixFor(findRule('FX-HOOK-001')!, 'a.php')).toContain('hash_equals');
    expect(fixFor(findRule('FX-TXN-001')!, 'a.php')).toContain('lockForUpdate');
    expect(fixFor(findRule('FX-OTP-001')!, 'a.php')).toContain('random_int');
    expect(fixFor(findRule('FX-OTP-001')!, 'a.js')).not.toContain('random_int');
  });
});
