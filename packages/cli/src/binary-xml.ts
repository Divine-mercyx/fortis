/*
 * Readers for the two binary formats inside built apps, turned back into text so the same checks
 * that read source files can read builds:
 *
 *   - Android binary XML (AXML): AndroidManifest.xml and every res/xml file in an APK or AAB.
 *   - Binary property lists (bplist00): Info.plist in most IPAs.
 *
 * Both are small, well-documented formats. These readers handle what apps contain and stop quietly
 * on anything they don't understand, returning what they have so far.
 */

/* ------------------------------------------------- Android binary XML */

const RES_STRING_POOL = 0x0001;
const RES_XML = 0x0003;
const RES_XML_START_ELEMENT = 0x0102;
const RES_XML_END_ELEMENT = 0x0103;
const RES_XML_CDATA = 0x0104;
const RES_XML_RESOURCE_MAP = 0x0180;
const UTF8_FLAG = 0x100;

/** Android attribute resource IDs, for APKs whose attribute names were stripped by a shrinker. */
const ATTR_BY_ID: Record<number, string> = {
  0x010104ec: 'usesCleartextTraffic',
  0x01010527: 'networkSecurityConfig',
  0x01010003: 'name',
  0x01010001: 'label',
  0x0101000f: 'debuggable',
  0x01010280: 'allowBackup',
};

export const isAxml = (buf: Buffer) => buf.length >= 8 && buf.readUInt16LE(0) === RES_XML && buf.readUInt16LE(2) === 8;

function readStringPool(buf: Buffer, at: number): string[] {
  const headerSize = buf.readUInt16LE(at + 2);
  const count = buf.readUInt32LE(at + 8);
  const flags = buf.readUInt32LE(at + 16);
  const stringsStart = buf.readUInt32LE(at + 20);
  const utf8 = (flags & UTF8_FLAG) !== 0;
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const offAt = at + headerSize + i * 4;
    if (offAt + 4 > buf.length) break;
    let p = at + stringsStart + buf.readUInt32LE(offAt);
    if (p >= buf.length) { out.push(''); continue; }
    if (utf8) {
      // UTF-16 length, then UTF-8 byte length; each one or two bytes.
      p += buf[p]! & 0x80 ? 2 : 1;
      let len = buf[p]!;
      if (len & 0x80) { len = ((len & 0x7f) << 8) | buf[p + 1]!; p += 2; } else p += 1;
      out.push(buf.toString('utf8', p, Math.min(buf.length, p + len)));
    } else {
      let len = buf.readUInt16LE(p);
      if (len & 0x8000) { len = ((len & 0x7fff) << 16) | buf.readUInt16LE(p + 2); p += 4; } else p += 2;
      out.push(buf.toString('utf16le', p, Math.min(buf.length, p + len * 2)));
    }
  }
  return out;
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

/** The value of a typed attribute, as it would read in the source XML. */
function typedValue(type: number, data: number, raw: string | undefined): string {
  if (raw !== undefined) return raw;
  switch (type) {
    case 0x12: return data !== 0 ? 'true' : 'false';
    case 0x10: return String(data | 0);
    case 0x11: return `0x${(data >>> 0).toString(16)}`;
    case 0x01: return `@0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    case 0x02: return `?0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    default: return String(data >>> 0);
  }
}

/** Android binary XML back to text, one element per line, with `android:` attribute prefixes. */
export function decodeAxml(buf: Buffer): string {
  if (!isAxml(buf)) throw new Error('Not Android binary XML');
  let strings: string[] = [];
  let resourceIds: number[] = [];
  const out: string[] = [];
  let depth = 0;
  let p = 8;
  while (p + 8 <= buf.length) {
    const type = buf.readUInt16LE(p);
    const size = buf.readUInt32LE(p + 4);
    if (size < 8 || p + size > buf.length) break;
    if (type === RES_STRING_POOL) strings = readStringPool(buf, p);
    else if (type === RES_XML_RESOURCE_MAP) {
      const n = (size - 8) / 4;
      resourceIds = Array.from({ length: n }, (_, i) => buf.readUInt32LE(p + 8 + i * 4));
    } else if (type === RES_XML_START_ELEMENT) {
      const ext = p + buf.readUInt16LE(p + 2);
      const name = strings[buf.readUInt32LE(ext + 4)] ?? '?';
      const attrStart = buf.readUInt16LE(ext + 8);
      const attrSize = buf.readUInt16LE(ext + 10);
      const attrCount = buf.readUInt16LE(ext + 12);
      const attrs: string[] = [];
      for (let i = 0; i < attrCount; i++) {
        const a = ext + attrStart + i * attrSize;
        if (a + 20 > buf.length) break;
        const ns = buf.readInt32LE(a);
        const nameIdx = buf.readUInt32LE(a + 4);
        const rawIdx = buf.readInt32LE(a + 8);
        const dataType = buf[a + 15]!;
        const data = buf.readUInt32LE(a + 16);
        let attrName = strings[nameIdx] ?? '';
        if (!attrName && resourceIds[nameIdx] !== undefined) attrName = ATTR_BY_ID[resourceIds[nameIdx]!] ?? `0x${resourceIds[nameIdx]!.toString(16)}`;
        const prefix = ns !== -1 && /android/.test(strings[ns] ?? '') ? 'android:' : '';
        attrs.push(`${prefix}${attrName}="${esc(typedValue(dataType, data, rawIdx >= 0 ? strings[rawIdx] : undefined))}"`);
      }
      out.push(`${'  '.repeat(depth)}<${name}${attrs.length ? ` ${attrs.join(' ')}` : ''}>`);
      depth++;
    } else if (type === RES_XML_END_ELEMENT) {
      depth = Math.max(0, depth - 1);
      const ext = p + buf.readUInt16LE(p + 2);
      const name = strings[buf.readUInt32LE(ext + 4)] ?? '?';
      // Put an element's text on its own line: <domain>api.example</domain>.
      const last = out[out.length - 1] ?? '';
      if (last.trimStart().startsWith(`<${name}`) && last.endsWith('>') && !last.endsWith('/>')) out[out.length - 1] = `${last}</${name}>`;
      else if (/^\s*[^<\s]/.test(last) && out.length >= 2 && out[out.length - 2]!.trimStart().startsWith(`<${name}`)) {
        const text = out.pop()!.trim();
        out[out.length - 1] = `${out[out.length - 1]}${esc(text)}</${name}>`;
      } else out.push(`${'  '.repeat(depth)}</${name}>`);
    } else if (type === RES_XML_CDATA) {
      const ext = p + buf.readUInt16LE(p + 2);
      const text = strings[buf.readUInt32LE(ext)] ?? '';
      if (text.trim()) out.push(`${'  '.repeat(depth)}${text.trim()}`);
    }
    p += size;
  }
  return out.join('\n');
}

/* ------------------------------------------------- binary property lists */

export const isBplist = (buf: Buffer) => buf.length >= 40 && buf.toString('latin1', 0, 8) === 'bplist00';

export type PlistValue = null | boolean | number | bigint | string | Date | Buffer | PlistValue[] | { [k: string]: PlistValue };

/** A binary plist as JavaScript values: dicts become objects, arrays arrays, and so on. */
export function decodeBplist(buf: Buffer): PlistValue {
  if (!isBplist(buf)) throw new Error('Not a binary plist');
  const t = buf.length - 32;
  const offsetSize = buf[t + 6]!;
  const refSize = buf[t + 7]!;
  const numObjects = Number(buf.readBigUInt64BE(t + 8));
  const top = Number(buf.readBigUInt64BE(t + 16));
  const tableAt = Number(buf.readBigUInt64BE(t + 24));
  const uint = (at: number, n: number) => {
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + buf[at + i]!;
    return v;
  };
  const offsetOf = (i: number) => uint(tableAt + i * offsetSize, offsetSize);
  const seen = new Set<number>();
  const read = (i: number, level = 0): PlistValue => {
    if (i >= numObjects || level > 64 || seen.has(i)) return null;
    seen.add(i);
    try {
      const at = offsetOf(i);
      const marker = buf[at]!;
      const hi = marker >> 4;
      const lo = marker & 0x0f;
      // Lengths of 15 or more are written as an int object after the marker.
      const length = (): [number, number] => {
        if (lo !== 0x0f) return [lo, at + 1];
        const n = 1 << (buf[at + 1]! & 0x0f);
        return [uint(at + 2, n), at + 2 + n];
      };
      switch (hi) {
        case 0x0: return lo === 0x08 ? false : lo === 0x09 ? true : null;
        case 0x1: { const n = 1 << lo; return n <= 6 ? uint(at + 1, n) : Number(buf.readBigInt64BE(at + 1)); }
        case 0x2: return lo === 2 ? buf.readFloatBE(at + 1) : buf.readDoubleBE(at + 1);
        case 0x3: return new Date(Date.UTC(2001, 0, 1) + buf.readDoubleBE(at + 1) * 1000);
        case 0x4: { const [n, s] = length(); return buf.subarray(s, s + n); }
        case 0x5: { const [n, s] = length(); return buf.toString('latin1', s, s + n); }
        case 0x6: {
          const [n, s] = length();
          const chars = Buffer.alloc(n * 2);
          for (let k = 0; k < n; k++) chars.writeUInt16LE(buf.readUInt16BE(s + k * 2), k * 2);
          return chars.toString('utf16le');
        }
        case 0x8: return uint(at + 1, lo + 1);
        case 0xa: {
          const [n, s] = length();
          return Array.from({ length: n }, (_, k) => read(uint(s + k * refSize, refSize), level + 1));
        }
        case 0xd: {
          const [n, s] = length();
          const obj: { [k: string]: PlistValue } = {};
          for (let k = 0; k < n; k++) {
            const key = read(uint(s + k * refSize, refSize), level + 1);
            obj[String(key)] = read(uint(s + (n + k) * refSize, refSize), level + 1);
          }
          return obj;
        }
        default: return null;
      }
    } finally {
      seen.delete(i);
    }
  };
  return read(top);
}

/** A plist value as XML plist text, one key or value per line, as Xcode writes it. */
export function plistToXml(value: PlistValue, depth = 0): string {
  const pad = '  '.repeat(depth);
  if (value === null) return `${pad}<string></string>`;
  if (value === true) return `${pad}<true/>`;
  if (value === false) return `${pad}<false/>`;
  if (typeof value === 'number' || typeof value === 'bigint') return `${pad}<integer>${value}</integer>`;
  if (typeof value === 'string') return `${pad}<string>${esc(value)}</string>`;
  if (value instanceof Date) return `${pad}<date>${value.toISOString()}</date>`;
  if (Buffer.isBuffer(value)) return `${pad}<data>${value.toString('base64')}</data>`;
  if (Array.isArray(value)) return [`${pad}<array>`, ...value.map((v) => plistToXml(v, depth + 1)), `${pad}</array>`].join('\n');
  return [`${pad}<dict>`, ...Object.entries(value).flatMap(([k, v]) => [`${pad}  <key>${esc(k)}</key>`, plistToXml(v, depth + 1)]), `${pad}</dict>`].join('\n');
}
