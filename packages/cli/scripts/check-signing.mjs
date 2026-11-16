#!/usr/bin/env node
// Signing checks for the release workflow. Never prints a secret's value.
//
//   check-signing.mjs secrets macos|windows|linux
//     Before building: are this platform's signing secrets all set, and do they look right?
//     All set: sign=true. None set: sign=false, with a warning that users will see a security
//     prompt. Some set, or one malformed: fails, naming the secret, so a half-finished setup
//     doesn't ship unsigned binaries.
//
//   check-signing.mjs notary <result.json>
//     After `notarytool submit --wait --output-format json`: fails unless Apple accepted it.
//     Prints the submission ID on stdout, so the caller can fetch Apple's log.
import { appendFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const BASE64 = /^[A-Za-z0-9+/=\s]+$/;
const decode = (v) => (BASE64.test(v) ? Buffer.from(v, 'base64') : null);
/** A PKCS#12 file is DER: it starts with a SEQUENCE tag. */
const looksLikePkcs12 = (v) => {
  const b = decode(v);
  return !!b && b.length > 500 && b[0] === 0x30;
};

const nonEmpty = () => null;
const pkcs12 = (what) => (v) =>
  v.includes('-----BEGIN') ? `holds PEM text. Export the ${what} as a .p12/.pfx file, then base64-encode that file.` : looksLikePkcs12(v) ? null : `isn't a base64-encoded ${what} (.p12/.pfx).`;

export const PLATFORMS = {
  macos: {
    name: 'macOS',
    secrets: {
      APPLE_CERT_P12_BASE64: pkcs12('Developer ID Application certificate'),
      APPLE_CERT_PASSWORD: nonEmpty,
      APPLE_API_KEY_P8_BASE64: (v) => {
        if (v.includes('-----BEGIN')) return 'holds the .p8 text itself. Base64-encode the file: base64 -i AuthKey_XXXXXXXXXX.p8';
        const text = decode(v)?.toString('utf8') ?? '';
        return text.includes('-----BEGIN PRIVATE KEY-----') ? null : "doesn't decode to an App Store Connect API key (.p8).";
      },
      APPLE_API_KEY_ID: (v) => (/^[A-Z0-9]{10}$/.test(v.trim()) ? null : 'should be the 10-character key ID shown beside the key in App Store Connect.'),
      APPLE_API_ISSUER_ID: (v) =>
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v.trim()) ? null : 'should be the issuer ID (a UUID) at the top of App Store Connect → Users and Access → Integrations.',
    },
    unsigned: 'Gatekeeper will say the macOS binary "can\'t be opened because Apple cannot check it".',
  },
  windows: {
    name: 'Windows',
    secrets: {
      WINDOWS_CERT_PFX_BASE64: pkcs12('code-signing certificate and its private key'),
      WINDOWS_CERT_PASSWORD: nonEmpty,
    },
    unsigned: 'SmartScreen will say "Windows protected your PC" for the Windows binary.',
  },
  linux: { name: 'Linux', secrets: {}, unsigned: '' },
};

/** What to do for this platform, given the environment. */
export function signingPlan(platform, env) {
  const p = PLATFORMS[platform];
  if (!p) throw new Error(`Unknown platform ${platform}. Use one of: ${Object.keys(PLATFORMS).join(', ')}`);
  const names = Object.keys(p.secrets);
  if (!names.length) return { sign: false, errors: [], notice: 'Linux binaries are not signed: checksums and build attestations cover them.' };
  const set = names.filter((n) => (env[n] ?? '').trim() !== '');
  if (!set.length) return { sign: false, errors: [], warning: `No ${p.name} signing secrets are set, so this binary is unsigned. ${p.unsigned}` };
  const errors = names
    .filter((n) => !set.includes(n))
    .map((n) => `${n} isn't set. ${p.name} signing needs all of: ${names.join(', ')}.`);
  for (const n of set) {
    const problem = p.secrets[n](env[n]);
    if (problem) errors.push(`${n} ${problem}`);
  }
  return { sign: errors.length === 0, errors };
}

/** Reads the JSON `notarytool submit --wait --output-format json` prints. */
export function notaryResult(text) {
  let r;
  try {
    r = JSON.parse(text);
  } catch {
    return { ok: false, id: '', message: `notarytool didn't print a result: ${text.trim().slice(0, 300) || '(nothing)'}` };
  }
  const id = typeof r.id === 'string' ? r.id : '';
  if (r.status === 'Accepted') return { ok: true, id, message: `Apple accepted notarization ${id}.` };
  const status = r.status ?? 'no status';
  const why = status === 'In Progress' ? ' The wait timed out; Apple may still accept it, but this binary is not published.' : '';
  return { ok: false, id, message: `Notarization ${id || '(no ID)'} ended as "${status}"${r.message ? `: ${r.message}` : ''}.${why}` };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [command, arg] = process.argv.slice(2);
  if (command === 'secrets') {
    const plan = signingPlan(arg, process.env);
    for (const e of plan.errors) console.log(`::error::${e}`);
    if (plan.warning) console.log(`::warning::${plan.warning}`);
    if (plan.notice) console.log(plan.notice);
    if (plan.sign) console.log(`All ${PLATFORMS[arg].name} signing secrets are set.`);
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `sign=${plan.sign}\n`);
    process.exitCode = plan.errors.length ? 1 : 0;
  } else if (command === 'notary') {
    const r = notaryResult(readFileSync(arg, 'utf8'));
    console.error(r.message);
    console.log(r.id);
    process.exitCode = r.ok ? 0 : 1;
  } else {
    console.error('Usage: check-signing.mjs secrets macos|windows|linux, or check-signing.mjs notary <result.json>');
    process.exitCode = 2;
  }
}
