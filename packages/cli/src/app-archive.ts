import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { inflateRawSync } from 'node:zlib';

import { genericSecretRule, paymentKeyRule } from './rules/secrets';
import { tlsFindings } from './rules/mobile';
import { emptyContext, type Detection, type SourceFile } from './rules/types';

/*
 * `fortis mobile app.apk|app.aab|app.ipa`: what a built app gives away. APKs, app bundles and IPAs
 * are ZIP files, so this reads the archive, pulls the text out of what's inside (the JavaScript
 * bundle, configuration files, the strings table of every .dex file, readable strings from native
 * libraries and the iOS binary), and runs the secret checks over it, plus the mobile checks that
 * still make sense on a build: plain-HTTP and App Transport Security settings, bundled .env files.
 *
 * No dependencies: the ZIP reader handles stored and deflated entries, which is what Android and
 * Xcode produce, and refuses anything else.
 */

export type ZipEntry = { name: string; method: number; compressedSize: number; size: number; offset: number };

/** The entries of a ZIP archive, from its central directory. */
export function zipEntries(buf: Buffer): ZipEntry[] {
  // The end-of-central-directory record is in the last 64 KB + 22 bytes.
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd === -1) throw new Error('Not a ZIP archive (no end-of-central-directory record). APK, AAB and IPA files are ZIP archives.');
  let count = buf.readUInt16LE(eocd + 10);
  let dir = buf.readUInt32LE(eocd + 16);
  // ZIP64: the real values are in the ZIP64 end record.
  if (dir === 0xffffffff || count === 0xffff) {
    const loc = eocd - 20;
    if (loc >= 0 && buf.readUInt32LE(loc) === 0x07064b50) {
      const rec = Number(buf.readBigUInt64LE(loc + 8));
      count = Number(buf.readBigUInt64LE(rec + 32));
      dir = Number(buf.readBigUInt64LE(rec + 48));
    }
  }
  const out: ZipEntry[] = [];
  let p = dir;
  for (let n = 0; n < count && p + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    let compressedSize = buf.readUInt32LE(p + 20);
    let size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let offset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    // ZIP64 sizes and offset live in the extra field.
    let e = p + 46 + nameLen;
    const end = e + extraLen;
    while (e + 4 <= end) {
      const id = buf.readUInt16LE(e);
      const len = buf.readUInt16LE(e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (size === 0xffffffff) { size = Number(buf.readBigUInt64LE(q)); q += 8; }
        if (compressedSize === 0xffffffff) { compressedSize = Number(buf.readBigUInt64LE(q)); q += 8; }
        if (offset === 0xffffffff) offset = Number(buf.readBigUInt64LE(q));
      }
      e += 4 + len;
    }
    out.push({ name, method, compressedSize, size, offset });
    p = end + commentLen;
  }
  return out;
}

/** One entry's bytes. */
export function zipRead(buf: Buffer, entry: ZipEntry): Buffer {
  const h = entry.offset;
  if (buf.readUInt32LE(h) !== 0x04034b50) throw new Error(`Bad local header for ${entry.name}`);
  const start = h + 30 + buf.readUInt16LE(h + 26) + buf.readUInt16LE(h + 28);
  const data = buf.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) return Buffer.from(data);
  if (entry.method === 8) return inflateRawSync(data);
  throw new Error(`${entry.name} uses ZIP compression method ${entry.method}, which isn't supported`);
}

/** Every string in a .dex file's string table: class names, constants, and any key someone hard-coded. */
export function dexStrings(dex: Buffer): string[] {
  if (dex.length < 0x70 || dex.toString('latin1', 0, 4) !== 'dex\n') return [];
  const count = dex.readUInt32LE(0x38);
  const ids = dex.readUInt32LE(0x3c);
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const at = ids + i * 4;
    if (at + 4 > dex.length) break;
    let p = dex.readUInt32LE(at);
    // ULEB128 length (in UTF-16 units), then MUTF-8 bytes up to a zero.
    let shift = 0;
    while (p < dex.length) {
      const b = dex[p++]!;
      if (!(b & 0x80) || (shift += 7) > 28) break;
    }
    const end = dex.indexOf(0, p);
    if (end === -1) break;
    out.push(dex.toString('utf8', p, end));
  }
  return out;
}

/** Runs of printable characters, like `strings`: for native libraries and binaries. */
export function printableStrings(buf: Buffer, min = 8): string[] {
  const out: string[] = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const b = i < buf.length ? buf[i]! : 0;
    const printable = b >= 0x20 && b < 0x7f;
    if (printable && start === -1) start = i;
    else if (!printable && start !== -1) {
      if (i - start >= min) out.push(buf.toString('latin1', start, i));
      start = -1;
    }
  }
  return out;
}

const TEXT_ENTRY = /\.(?:js|jsbundle|bundle|json|xml|plist|properties|txt|html|yaml|yml|env|conf|config|cfg|ini|strings)$|(?:^|\/)\.env(?:\.[\w.-]+)?$|index\.android\.bundle$|main\.jsbundle$/i;
const BINARY_ENTRY = /\.(?:so|dylib)$|(?:^|\/)Payload\/[^/]+\.app\/[^/.]+$|\/flutter_assets\/kernel_blob\.bin$/;
const SKIP_ENTRY = /\.(?:png|jpe?g|gif|webp|ttf|otf|woff2?|mp3|mp4|wav|ogg|car|nib|storyboardc|lottie|arsc|RSA|SF|MF|DSA)$|^META-INF\/(?!.*\.json$)|\/_CodeSignature\//i;
const MAX_ENTRY = 64 * 1024 * 1024;

export type ArchiveResult = { detections: Detection[]; entries: number; read: number; kind: 'Android' | 'iOS'; notes: string[] };

/** Scan a built app. Detections point at `app.apk!/path/inside`, with line 0 for binaries. */
export function scanAppArchive(path: string, data: Buffer = readFileSync(path)): ArchiveResult {
  const entries = zipEntries(data);
  const kind = entries.some((e) => /^Payload\/[^/]+\.app\//.test(e.name)) ? 'iOS' : 'Android';
  const label = basename(path);
  const detections: Detection[] = [];
  const notes: string[] = [];
  const seen = new Set<string>();
  let read = 0;
  const ctx = emptyContext();
  const push = (d: Detection) => {
    const key = `${d.ruleId}|${d.file}|${d.snippet}`;
    if (seen.has(key)) return;
    seen.add(key);
    detections.push(d);
  };
  const runSecrets = (file: SourceFile, binary: boolean) => {
    for (const rule of [paymentKeyRule, genericSecretRule]) {
      for (const d of rule.run(file, ctx)) push(binary ? { ...d, line: 0 } : d);
    }
  };
  for (const e of entries) {
    if (e.name.endsWith('/') || SKIP_ENTRY.test(e.name) || e.size > MAX_ENTRY) continue;
    const isDex = /(?:^|\/)classes\d*\.dex$/.test(e.name);
    const isText = TEXT_ENTRY.test(e.name);
    const isBinary = BINARY_ENTRY.test(e.name);
    if (!isDex && !isText && !isBinary) continue;
    let bytes: Buffer;
    try {
      bytes = zipRead(data, e);
    } catch (err) {
      notes.push(`Skipped ${e.name}: ${(err as Error).message}`);
      continue;
    }
    read++;
    const where = `${label}!/${e.name}`;
    if (/(?:^|\/)\.env(?:\.[\w.-]+)?$/.test(e.name)) {
      push({ ruleId: 'MOB-KEY-001', severity: 'high', title: 'App ships a .env file', file: where, line: 0, snippet: e.name, fix: 'Remove .env from the app\'s assets: everything in it can be read from the download. Keep secrets on your backend and rotate any that shipped.' });
    }
    if (isDex) {
      const text = dexStrings(bytes).join('\n');
      runSecrets({ path: `${where}.txt`, text, lines: text.split('\n') }, true);
      continue;
    }
    if (isBinary) {
      const text = printableStrings(bytes).join('\n');
      runSecrets({ path: `${where}.txt`, text, lines: text.split('\n') }, true);
      continue;
    }
    // Binary plists start with bplist00: read their strings instead.
    const raw = bytes.toString('latin1', 0, 8) === 'bplist00' ? printableStrings(bytes, 4).join('\n') : bytes.toString('utf8');
    const file: SourceFile = { path: where, text: raw, lines: raw.split(/\r?\n/) };
    runSecrets(file, false);
    if (/Info\.plist$/.test(e.name)) {
      if (bytes.toString('latin1', 0, 8) === 'bplist00') notes.push(`${e.name} is a binary plist; its App Transport Security settings weren't judged. \`fortis scan\` checks them in the source.`);
      else for (const f of tlsFindings({ ...file, path: e.name })) push({ ruleId: 'MOB-TLS-001', severity: f.severity, title: f.title, file: where, line: f.line, snippet: (file.lines[f.line - 1] ?? '').trim(), fix: f.fix });
    }
    if (/network_security_config[\w-]*\.xml$/.test(e.name) && /<network-security-config/.test(raw)) {
      for (const f of tlsFindings({ ...file, path: e.name })) push({ ruleId: 'MOB-TLS-001', severity: f.severity, title: f.title, file: where, line: f.line, snippet: (file.lines[f.line - 1] ?? '').trim(), fix: f.fix });
    }
  }
  if (kind === 'Android' && entries.some((e) => e.name === 'AndroidManifest.xml')) {
    notes.push('AndroidManifest.xml in a build is binary XML; cleartext and network-security settings are checked in the source repository by `fortis scan`.');
  }
  return { detections, entries: entries.length, read, kind, notes };
}
