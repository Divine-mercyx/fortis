import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// @ts-expect-error: a plain .mjs script with no type declarations
import { notaryResult, PLATFORMS, signingPlan } from '../scripts/check-signing.mjs';

const cli = join(__dirname, '..');
const read = (p: string) => readFileSync(join(cli, '..', '..', p), 'utf8').replace(/\r\n/g, '\n');
const workflow = read('.github/workflows/release-cli.yml');
const signMac = read('packages/cli/scripts/sign-macos.sh');
const signWindows = read('packages/cli/scripts/sign-windows.ps1');

// Shaped like the real files, built at runtime: a DER blob, and a PEM header around nothing secret.
const p12 = Buffer.concat([Buffer.from([0x30, 0x82]), Buffer.alloc(900, 7)]).toString('base64');
const pem = [['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' '), 'AAAA', ['-----END', 'PRIVATE', 'KEY-----'].join(' ')].join('\n');
const mac = {
  APPLE_CERT_P12_BASE64: p12,
  APPLE_CERT_PASSWORD: 'pw',
  APPLE_API_KEY_P8_BASE64: Buffer.from(pem).toString('base64'),
  APPLE_API_KEY_ID: 'AB12CD34EF',
  APPLE_API_ISSUER_ID: '69a6de7e-1111-47e3-e053-5b8c7c11a4d1',
};
const win = { WINDOWS_CERT_PFX_BASE64: p12, WINDOWS_CERT_PASSWORD: 'pw' };

describe('checking the signing secrets', () => {
  it('signs when every secret is set and looks right', () => {
    expect(signingPlan('macos', mac)).toEqual({ sign: true, errors: [] });
    expect(signingPlan('windows', win)).toEqual({ sign: true, errors: [] });
  });

  it('builds unsigned, with a warning saying what users will see, when none are set', () => {
    expect(signingPlan('macos', {})).toMatchObject({ sign: false, errors: [], warning: expect.stringMatching(/Apple cannot check it/) });
    expect(signingPlan('windows', { WINDOWS_CERT_PASSWORD: '  ' })).toMatchObject({ sign: false, errors: [], warning: expect.stringMatching(/Windows protected your PC/) });
  });

  it('fails a half-finished setup, naming each missing secret', () => {
    const { APPLE_API_KEY_ID: _id, APPLE_API_ISSUER_ID: _issuer, ...some } = mac;
    const plan = signingPlan('macos', some);
    expect(plan.sign).toBe(false);
    expect(plan.errors.map((e: string) => e.split(' ')[0])).toEqual(['APPLE_API_KEY_ID', 'APPLE_API_ISSUER_ID']);
  });

  it('catches the usual mistakes, without repeating the value', () => {
    const keyFileName = `AuthKey_${mac.APPLE_API_KEY_ID}.p8`; // the file's name, not its ID
    const cases: Array<[string, Record<string, string>, RegExp]> = [
      ['windows', { ...win, WINDOWS_CERT_PFX_BASE64: 'C:\\certs\\fortis.pfx' }, /WINDOWS_CERT_PFX_BASE64 isn't a base64-encoded/],
      ['windows', { ...win, WINDOWS_CERT_PFX_BASE64: Buffer.from('hello').toString('base64') }, /isn't a base64-encoded/],
      ['macos', { ...mac, APPLE_CERT_P12_BASE64: pem }, /APPLE_CERT_P12_BASE64 holds PEM text/],
      ['macos', { ...mac, APPLE_API_KEY_P8_BASE64: pem }, /APPLE_API_KEY_P8_BASE64 holds the \.p8 text itself/],
      ['macos', { ...mac, APPLE_API_KEY_P8_BASE64: p12 }, /doesn't decode to an App Store Connect API key/],
      ['macos', { ...mac, APPLE_API_KEY_ID: keyFileName }, /10-character key ID/],
      ['macos', { ...mac, APPLE_API_ISSUER_ID: 'TEAM123456' }, /issuer ID \(a UUID\)/],
    ];
    for (const [platform, env, message] of cases) {
      const plan = signingPlan(platform, env);
      expect(plan.sign, String(message)).toBe(false);
      expect(plan.errors.join(' ')).toMatch(message);
      for (const value of Object.values(env)) if (value.length > 3) expect(plan.errors.join(' ')).not.toContain(value);
    }
  });

  it('Linux needs nothing', () => {
    expect(signingPlan('linux', {})).toMatchObject({ sign: false, errors: [] });
  });

  it('as a command: writes sign= for the workflow, and exits 1 on a half-finished setup', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortis-sign-'));
    const run = (env: Record<string, string>) => {
      const out = join(dir, `out-${Math.random()}`);
      writeFileSync(out, '');
      try {
        const stdout = execFileSync(process.execPath, ['scripts/check-signing.mjs', 'secrets', 'windows'], { cwd: cli, env: { PATH: process.env.PATH, ...env, GITHUB_OUTPUT: out }, encoding: 'utf8' });
        return { code: 0, stdout, output: readFileSync(out, 'utf8') };
      } catch (e) {
        const err = e as { status: number; stdout: string };
        return { code: err.status, stdout: err.stdout, output: readFileSync(out, 'utf8') };
      }
    };
    expect(run(win)).toMatchObject({ code: 0, output: 'sign=true\n' });
    expect(run({})).toMatchObject({ code: 0, output: 'sign=false\n', stdout: expect.stringMatching(/^::warning::/) });
    expect(run({ WINDOWS_CERT_PASSWORD: 'pw' })).toMatchObject({ code: 1, output: 'sign=false\n', stdout: expect.stringMatching(/^::error::WINDOWS_CERT_PFX_BASE64 isn't set/) });
  });
});

describe('reading the notarization result', () => {
  it('passes only when Apple accepted it', () => {
    expect(notaryResult('{"id":"a1","status":"Accepted","message":"Processing complete"}')).toMatchObject({ ok: true, id: 'a1' });
    const invalid = notaryResult('{"id":"b2","status":"Invalid","message":"Processing complete"}');
    expect(invalid).toEqual({ ok: false, id: 'b2', message: 'Notarization b2 ended as "Invalid": Processing complete.' });
  });

  it('says when the wait ran out, and copes with no JSON at all', () => {
    expect(notaryResult('{"id":"c3","status":"In Progress"}').message).toMatch(/timed out.*not published/);
    expect(notaryResult('Error: HTTP status code: 401. Unable to authenticate.')).toMatchObject({ ok: false, id: '', message: expect.stringMatching(/didn't print a result: Error: HTTP status code: 401/) });
  });
});

describe('the release workflow and signing scripts', () => {
  const binaries = workflow.slice(workflow.indexOf('  binaries:'), workflow.indexOf('\n  musl:'));

  it('passes the signing job every secret the check knows about, and no others', () => {
    const passed = [...binaries.matchAll(/^ {6}(\w+): \$\{\{ secrets\.(\w+) \}\}$/gm)].map((m) => [m[1], m[2]]);
    const known = [...Object.keys(PLATFORMS.macos.secrets), ...Object.keys(PLATFORMS.windows.secrets)];
    expect(passed).toEqual(known.map((n) => [n, n]));
  });

  it('checks the secrets before building, and signs only when the check says so', () => {
    expect(binaries.indexOf('id: signing')).toBeGreaterThan(-1);
    expect(binaries.indexOf('id: signing')).toBeLessThan(binaries.indexOf('build:binary'));
    expect(binaries).toContain("if: runner.os == 'macOS' && steps.signing.outputs.sign == 'true'");
    expect(binaries).toContain("if: runner.os == 'Windows' && steps.signing.outputs.sign == 'true'");
    expect(binaries).toContain('GITHUB_STEP_SUMMARY');
  });

  it('macOS: checks the signature, and trusts the notarization result over the exit code', () => {
    expect(signMac).toContain('Authority=Developer ID Application');
    expect(signMac).toContain('--output-format json');
    expect(signMac).toMatch(/if ! ID=\$\(node "\$SCRIPTS\/check-signing\.mjs" notary /);
    expect(signMac).toContain('notarytool log "$ID"');
  });

  it('Windows: requires a timestamp, so the signature outlives the certificate', () => {
    expect(signWindows).toContain('/tr http://timestamp.digicert.com');
    expect(signWindows).toContain('TimeStamperCertificate');
  });
});
