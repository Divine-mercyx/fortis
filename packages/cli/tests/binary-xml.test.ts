import { describe, expect, it } from 'vitest';

import { scanAppArchive } from '../src/app-archive';
import { decodeAxml, decodeBplist, isAxml, isBplist, plistToXml, type PlistValue } from '../src/binary-xml';
import { tlsFindings } from '../src/rules/mobile';
import { zipFor } from './zip-helper';

/* ------------------------------------------------- an Android binary XML writer, for the tests */

type El = { name: string; attrs?: [string, string | boolean | number, boolean?][]; text?: string; children?: El[] };
const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

/** Writes AXML the way aapt2 does: a UTF-16 string pool, then namespace, element and text chunks. */
function axml(root: El, opts: { utf8?: boolean; stripAttrNames?: Record<string, number> } = {}): Buffer {
  const strings: string[] = [];
  const idx = (s: string) => { let i = strings.indexOf(s); if (i === -1) { strings.push(s); i = strings.length - 1; } return i; };
  const resMap: number[] = [];
  // Attribute names first, so the resource map lines up with them.
  const walkAttrs = (e: El) => { for (const [n] of e.attrs ?? []) { const id = opts.stripAttrNames?.[n]; if (id !== undefined && !strings.includes(`#${n}`)) { strings.push(`#${n}`); resMap.push(id); } } e.children?.forEach(walkAttrs); };
  walkAttrs(root);
  idx(ANDROID_NS); idx('android');
  const chunks: Buffer[] = [];
  const chunk = (type: number, headerSize: number, body: Buffer) => {
    const h = Buffer.alloc(8);
    h.writeUInt16LE(type, 0); h.writeUInt16LE(headerSize, 2); h.writeUInt32LE(8 + body.length, 4);
    return Buffer.concat([h, body]);
  };
  const node = (lineNo: number) => { const b = Buffer.alloc(8); b.writeUInt32LE(lineNo, 0); b.writeInt32LE(-1, 4); return b; };
  const nsChunk = (type: number) => { const ext = Buffer.alloc(8); ext.writeUInt32LE(idx('android'), 0); ext.writeUInt32LE(idx(ANDROID_NS), 4); return chunk(type, 16, Buffer.concat([node(1), ext])); };
  const body: Buffer[] = [nsChunk(0x0100)];
  const emit = (e: El) => {
    const attrs = (e.attrs ?? []).map(([n, v, ns]) => {
      const a = Buffer.alloc(20);
      a.writeInt32LE(ns === false ? -1 : idx(ANDROID_NS), 0);
      a.writeUInt32LE(opts.stripAttrNames?.[n] !== undefined ? strings.indexOf(`#${n}`) : idx(n), 4);
      if (typeof v === 'boolean') { a.writeInt32LE(-1, 8); a.writeUInt16LE(8, 12); a[15] = 0x12; a.writeUInt32LE(v ? 0xffffffff : 0, 16); }
      else if (typeof v === 'number') { a.writeInt32LE(-1, 8); a.writeUInt16LE(8, 12); a[15] = 0x10; a.writeUInt32LE(v, 16); }
      else { a.writeInt32LE(idx(v), 8); a.writeUInt16LE(8, 12); a[15] = 0x03; a.writeUInt32LE(idx(v), 16); }
      return a;
    });
    const ext = Buffer.alloc(20);
    ext.writeInt32LE(-1, 0); ext.writeUInt32LE(idx(e.name), 4); ext.writeUInt16LE(20, 8); ext.writeUInt16LE(20, 10); ext.writeUInt16LE(attrs.length, 12);
    body.push(chunk(0x0102, 16, Buffer.concat([node(1), ext, ...attrs])));
    if (e.text) { const t = Buffer.alloc(12); t.writeUInt32LE(idx(e.text), 0); body.push(chunk(0x0104, 16, Buffer.concat([node(1), t]))); }
    e.children?.forEach(emit);
    const end = Buffer.alloc(8); end.writeInt32LE(-1, 0); end.writeUInt32LE(idx(e.name), 4);
    body.push(chunk(0x0103, 16, Buffer.concat([node(1), end])));
  };
  emit(root);
  body.push(nsChunk(0x0101));
  // String pool.
  const encoded = strings.map((s) => {
    if (opts.utf8) { const b = Buffer.from(s, 'utf8'); return Buffer.concat([Buffer.from([s.length, b.length]), b, Buffer.from([0])]); }
    const b = Buffer.from(s, 'utf16le'); const len = Buffer.alloc(2); len.writeUInt16LE(s.length, 0); return Buffer.concat([len, b, Buffer.alloc(2)]);
  });
  const offsets = Buffer.alloc(strings.length * 4);
  let off = 0;
  encoded.forEach((e, i) => { offsets.writeUInt32LE(off, i * 4); off += e.length; });
  const poolHeader = Buffer.alloc(20);
  poolHeader.writeUInt32LE(strings.length, 0); poolHeader.writeUInt32LE(0, 4); poolHeader.writeUInt32LE(opts.utf8 ? 0x100 : 0, 8); poolHeader.writeUInt32LE(28 + offsets.length, 12);
  let data = Buffer.concat(encoded);
  if (data.length % 4) data = Buffer.concat([data, Buffer.alloc(4 - (data.length % 4))]);
  chunks.push(chunk(0x0001, 28, Buffer.concat([poolHeader, offsets, data])));
  if (resMap.length) { const m = Buffer.alloc(resMap.length * 4); resMap.forEach((id, i) => m.writeUInt32LE(id, i * 4)); chunks.push(chunk(0x0180, 8, m)); }
  chunks.push(...body);
  const all = Buffer.concat(chunks);
  const header = Buffer.alloc(8);
  header.writeUInt16LE(0x0003, 0); header.writeUInt16LE(8, 2); header.writeUInt32LE(8 + all.length, 4);
  return Buffer.concat([header, all]);
}

/* ------------------------------------------------- a binary plist writer, for the tests */

function bplist(root: PlistValue): Buffer {
  const objects: Buffer[] = [];
  const add = (v: PlistValue): number => {
    const i = objects.length;
    objects.push(Buffer.alloc(0));
    const lenMarker = (type: number, n: number) => (n < 15 ? Buffer.from([(type << 4) | n]) : Buffer.from([(type << 4) | 0xf, 0x10, n]));
    if (v === true) objects[i] = Buffer.from([0x09]);
    else if (v === false) objects[i] = Buffer.from([0x08]);
    else if (typeof v === 'number') objects[i] = Buffer.from([0x10, v]);
    else if (typeof v === 'string') objects[i] = Buffer.concat([lenMarker(0x5, v.length), Buffer.from(v, 'latin1')]);
    else if (Array.isArray(v)) { const refs = v.map(add); objects[i] = Buffer.concat([lenMarker(0xa, refs.length), Buffer.from(refs)]); }
    else if (v && typeof v === 'object') {
      const entries = Object.entries(v as Record<string, PlistValue>);
      const keys = entries.map(([k]) => add(k));
      const vals = entries.map(([, x]) => add(x));
      objects[i] = Buffer.concat([lenMarker(0xd, entries.length), Buffer.from(keys), Buffer.from(vals)]);
    }
    return i;
  };
  const top = add(root);
  const head = Buffer.from('bplist00', 'latin1');
  const offsets: number[] = [];
  let at = head.length;
  for (const o of objects) { offsets.push(at); at += o.length; }
  const table = Buffer.alloc(offsets.length * 2);
  offsets.forEach((o, i) => table.writeUInt16BE(o, i * 2));
  const trailer = Buffer.alloc(32);
  trailer[6] = 2; trailer[7] = 1;
  trailer.writeBigUInt64BE(BigInt(objects.length), 8);
  trailer.writeBigUInt64BE(BigInt(top), 16);
  trailer.writeBigUInt64BE(BigInt(at), 24);
  return Buffer.concat([head, ...objects, table, trailer]);
}

const manifest = (cleartext: boolean | null): El => ({
  name: 'manifest',
  attrs: [['package', 'com.nolt.app', false]],
  children: [
    { name: 'uses-permission', attrs: [['name', 'android.permission.INTERNET']] },
    { name: 'application', attrs: [['label', 'Nolt'], ...(cleartext === null ? [] : [['usesCleartextTraffic', cleartext] as [string, boolean]]), ['networkSecurityConfig', 0x7f150000]] },
  ],
});

const securityConfig: El = {
  name: 'network-security-config',
  children: [
    { name: 'base-config', attrs: [['cleartextTrafficPermitted', true, false]], children: [{ name: 'trust-anchors', children: [{ name: 'certificates', attrs: [['src', 'system', false]] }, { name: 'certificates', attrs: [['src', 'user', false]] }] }] },
    { name: 'domain-config', attrs: [['cleartextTrafficPermitted', true, false]], children: [{ name: 'domain', attrs: [['includeSubdomains', true, false]], text: '10.0.2.2' }] },
  ],
};

describe('Android binary XML', () => {
  it('decodes a manifest, typed values and namespaces included', () => {
    const buf = axml(manifest(true));
    expect(isAxml(buf)).toBe(true);
    const text = decodeAxml(buf);
    expect(text).toContain('<manifest package="com.nolt.app">');
    expect(text).toContain('<uses-permission android:name="android.permission.INTERNET"></uses-permission>');
    expect(text).toContain('android:usesCleartextTraffic="true"');
    expect(text).toContain('android:networkSecurityConfig="2132082688"');
    expect(tlsFindings({ path: 'AndroidManifest.xml', text, lines: text.split('\n') }).map((f) => f.title)).toEqual(['App allows plain HTTP (usesCleartextTraffic)']);
  });

  it('reads UTF-8 string pools and attribute names stripped by a shrinker', () => {
    const text = decodeAxml(axml(manifest(true), { utf8: true, stripAttrNames: { usesCleartextTraffic: 0x010104ec } }));
    expect(text).toMatch(/android:(?:usesCleartextTraffic|#usesCleartextTraffic)="true"/);
    const stripped = decodeAxml(axml(manifest(false), { stripAttrNames: { usesCleartextTraffic: 0x010104ec } }));
    expect(stripped).toMatch(/="false"/);
  });

  it('decodes network security config with element text, and the TLS checks judge it', () => {
    const text = decodeAxml(axml(securityConfig));
    expect(text).toContain('<domain includeSubdomains="true">10.0.2.2</domain>');
    expect(tlsFindings({ path: 'res/xml/network_security_config.xml', text, lines: text.split('\n') }).map((f) => f.title)).toEqual([
      'App allows plain HTTP (cleartextTrafficPermitted)',
      'App trusts user-installed certificates',
    ]);
  });

  it('refuses what isn\'t binary XML, and stops quietly on truncated input', () => {
    expect(isAxml(Buffer.from('<manifest/>'))).toBe(false);
    expect(() => decodeAxml(Buffer.from('<manifest/>'))).toThrow();
    const buf = axml(manifest(true));
    expect(() => decodeAxml(buf.subarray(0, buf.length - 30))).not.toThrow();
  });
});

describe('binary plists', () => {
  it('decodes dicts, arrays, strings, booleans and numbers, and renders them as XML', () => {
    const value = { CFBundleIdentifier: 'com.nolt.app', NSAppTransportSecurity: { NSAllowsArbitraryLoads: true, NSAllowsLocalNetworking: false }, UIDeviceFamily: [1, 2] };
    const buf = bplist(value);
    expect(isBplist(buf)).toBe(true);
    expect(decodeBplist(buf)).toEqual(value);
    const xml = plistToXml(decodeBplist(buf));
    expect(xml).toMatch(/<key>NSAllowsArbitraryLoads<\/key>\n\s*<true\/>/);
    expect(tlsFindings({ path: 'Info.plist', text: xml, lines: xml.split('\n') }).map((f) => f.title)).toEqual(['App Transport Security turned off (NSAllowsArbitraryLoads)']);
  });

  it('reads long strings and keeps quiet on a broken trailer', () => {
    const long = 'x'.repeat(40);
    expect(decodeBplist(bplist({ k: long }))).toEqual({ k: long });
    const broken = Buffer.concat([Buffer.from('bplist00'), Buffer.alloc(40)]);
    expect(decodeBplist(broken)).toBeNull();
  });
});

describe('fortis mobile with binary files', () => {
  it('judges a binary manifest and a renamed binary network security config in an APK', () => {
    const apk = zipFor({
      'AndroidManifest.xml': axml(manifest(true)),
      'res/xml/a1.xml': axml(securityConfig),
      'res/xml/file_paths.xml': axml({ name: 'paths', children: [{ name: 'cache-path', attrs: [['name', 'cache', false]] }] }),
    });
    const r = scanAppArchive('nolt.apk', apk);
    expect(r.detections.map((d) => `${d.ruleId} ${d.file} ${d.title}`).sort()).toEqual([
      'MOB-TLS-001 nolt.apk!/AndroidManifest.xml App allows plain HTTP (usesCleartextTraffic)',
      'MOB-TLS-001 nolt.apk!/res/xml/a1.xml App allows plain HTTP (cleartextTrafficPermitted)',
      'MOB-TLS-001 nolt.apk!/res/xml/a1.xml App trusts user-installed certificates',
    ]);
    expect(r.notes.join(' ')).not.toMatch(/binary XML/);
  });

  it('passes a safe binary manifest', () => {
    expect(scanAppArchive('ok.apk', zipFor({ 'AndroidManifest.xml': axml(manifest(false)) })).detections).toEqual([]);
  });

  it('judges a binary Info.plist in an IPA', () => {
    const ipa = zipFor({ 'Payload/Nolt.app/Info.plist': bplist({ CFBundleIdentifier: 'com.nolt.app', NSAppTransportSecurity: { NSAllowsArbitraryLoads: true } }) });
    const r = scanAppArchive('Nolt.ipa', ipa);
    expect(r.detections.map((d) => `${d.ruleId} ${d.title}`)).toEqual(['MOB-TLS-001 App Transport Security turned off (NSAllowsArbitraryLoads)']);
    expect(r.notes).toEqual([]);
  });
});
