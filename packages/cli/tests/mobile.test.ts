import { deflateRawSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { dexStrings, printableStrings, scanAppArchive, zipEntries, zipRead } from '../src/app-archive';
import { appEntry, isSecretName, MOBILE_RULES, mobileKeyRule, mobilePinningRule, mobileTlsRule, tlsFindings } from '../src/rules/mobile';
import { buildContext } from '../src/scan';
import { emptyContext, type FileRule, type SourceFile } from '../src/rules/types';

const file = (path: string, text: string): SourceFile => ({ path, text, lines: text.split('\n') });
const titles = (rule: FileRule, path: string, text: string, ctx = emptyContext()) => rule.run(file(path, text), ctx).map((d) => `${d.line}:${d.severity}:${d.title}`);
const lines = (rule: FileRule, path: string, text: string, ctx = emptyContext()) => rule.run(file(path, text), ctx).map((d) => d.line);

// Built at runtime, so this repository never contains a key-shaped string.
const LIVE_KEY = ['sk', 'live', 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'].join('_');

/** A ZIP file, with deflated or stored entries, like an APK or IPA. */
function zip(files: Record<string, string | Buffer>, store = false): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const packed = store ? data : deflateRawSync(data);
    const nameBuf = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(store ? 0 : 8, 8);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(local, nameBuf, packed);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(store ? 0 : 8, 10);
    cd.writeUInt32LE(packed.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, nameBuf);
    offset += 30 + nameBuf.length + packed.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(Object.keys(files).length, 8);
  eocd.writeUInt16LE(Object.keys(files).length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cdBuf, eocd]);
}

/** A .dex file with just a header and a string table. */
function dex(strings: string[]): Buffer {
  const header = Buffer.alloc(0x70);
  header.write('dex\n035\0', 0, 'latin1');
  const ids = Buffer.alloc(strings.length * 4);
  const data: Buffer[] = [];
  let at = 0x70 + ids.length;
  strings.forEach((s, i) => {
    const bytes = Buffer.from(s, 'utf8');
    const entry = Buffer.concat([Buffer.from([s.length & 0x7f]), bytes, Buffer.from([0])]);
    ids.writeUInt32LE(at, i * 4);
    data.push(entry);
    at += entry.length;
  });
  header.writeUInt32LE(strings.length, 0x38);
  header.writeUInt32LE(0x70, 0x3c);
  return Buffer.concat([header, ids, ...data]);
}

describe('MOB-KEY-001: server secrets in the app bundle', () => {
  it('tells server secrets from public keys', () => {
    for (const n of ['PAYSTACK_SECRET_KEY', 'STRIPE_SK', 'SUPABASE_SERVICE_ROLE_KEY', 'JWT_SECRET', 'ADMIN_TOKEN', 'DB_PASSWORD', 'PRIVATE_KEY', 'API_SECRET']) expect(isSecretName(n), n).toBe(true);
    for (const n of ['PAYSTACK_PUBLIC_KEY', 'STRIPE_PUBLISHABLE_KEY', 'SUPABASE_ANON_KEY', 'API_URL', 'SENTRY_DSN', 'GOOGLE_CLIENT_ID', 'POSTHOG_KEY']) expect(isSecretName(n), n).toBe(false);
  });

  it('flags secret names behind public prefixes in .env files and code', () => {
    expect(titles(mobileKeyRule, '.env', [
      'EXPO_PUBLIC_API_URL=https://api.nolt.example',
      'EXPO_PUBLIC_PAYSTACK_SECRET_KEY=sk_test_x',
      'EXPO_PUBLIC_PAYSTACK_PUBLIC_KEY=pk_test_x',
      'REACT_APP_JWT_SECRET=abc',
      'PAYSTACK_SECRET_KEY=server-only',
      '# EXPO_PUBLIC_OLD_SECRET=gone',
    ].join('\n'))).toEqual([
      '2:high:Server secret exposed to the app bundle (EXPO_PUBLIC_PAYSTACK_SECRET_KEY)',
      '4:high:Server secret exposed to the app bundle (REACT_APP_JWT_SECRET)',
    ]);
    expect(lines(mobileKeyRule, 'src/pay.ts', [
      'const secret = process.env.EXPO_PUBLIC_PAYSTACK_SECRET_KEY;',
      'const pk = process.env.EXPO_PUBLIC_PAYSTACK_PUBLIC_KEY;',
      'const key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;',
      "const label = 'EXPO_PUBLIC_SECRET_KEY is not allowed';",
    ].join('\n'))).toEqual([1, 3]);
  });

  it('flags secrets compiled in by Gradle, put in expo extra, or bundled as a Flutter asset', () => {
    expect(lines(mobileKeyRule, 'app/build.gradle', [
      'android {',
      '  defaultConfig {',
      `    buildConfigField "String", "PAYSTACK_SECRET_KEY", "\\"${LIVE_KEY}\\""`,
      '    buildConfigField "String", "API_URL", "\\"https://api.example\\""',
      '    buildConfigField "String", "MONO_SECRET", "\\"${project.findProperty(\'MONO_SECRET\')}\\""',
      '  }',
      '}',
    ].join('\n'))).toEqual([3]);
    expect(lines(mobileKeyRule, 'app/build.gradle.kts', 'buildConfigField("String", "API_SECRET", "\\"abcdef123456\\"")')).toEqual([1]);
    expect(lines(mobileKeyRule, 'app.json', JSON.stringify({ expo: { extra: { paystackSecretKey: 'sk_test_abcdefgh', paystackPublicKey: 'pk_test_abcdefgh', apiUrl: 'https://api.example' } } }, null, 2))).toEqual([4]);
    expect(lines(mobileKeyRule, 'pubspec.yaml', 'flutter:\n  assets:\n    - .env\n    - assets/images/')).toEqual([3]);
  });
});

describe('MOB-TLS-001: TLS weakened', () => {
  it('reads Android manifests and network security config', () => {
    expect(titles(mobileTlsRule, 'app/src/main/AndroidManifest.xml', '<manifest>\n  <application android:usesCleartextTraffic="true" android:label="Nolt">\n  </application>\n</manifest>')).toEqual(['2:high:App allows plain HTTP (usesCleartextTraffic)']);
    expect(titles(mobileTlsRule, 'app/src/main/res/xml/network_security_config.xml', [
      '<network-security-config>',
      '  <base-config cleartextTrafficPermitted="true">',
      '    <trust-anchors>',
      '      <certificates src="system" />',
      '      <certificates src="user" />',
      '    </trust-anchors>',
      '  </base-config>',
      '  <domain-config cleartextTrafficPermitted="true">',
      '    <domain includeSubdomains="true">10.0.2.2</domain>',
      '    <domain>localhost</domain>',
      '  </domain-config>',
      '  <domain-config cleartextTrafficPermitted="true">',
      '    <domain>api.nolt.example</domain>',
      '  </domain-config>',
      '  <debug-overrides>',
      '    <trust-anchors>',
      '      <certificates src="user" />',
      '    </trust-anchors>',
      '  </debug-overrides>',
      '</network-security-config>',
    ].join('\n'))).toEqual([
      '2:high:App allows plain HTTP (cleartextTrafficPermitted)',
      '5:medium:App trusts user-installed certificates',
      '12:high:App allows plain HTTP (cleartextTrafficPermitted)',
    ]);
  });

  it('flags trust-all code in Kotlin, Java, Dart and Swift', () => {
    expect(titles(mobileTlsRule, 'app/src/main/java/com/nolt/Net.kt', [
      'val trustAll = object : X509TrustManager {',
      '  override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}',
      '  override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}',
      '  override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()',
      '}',
      'val client = OkHttpClient.Builder().hostnameVerifier { _, _ -> true }.build()',
    ].join('\n'))).toEqual(['3:critical:TrustManager accepts any certificate', '6:critical:Host name check turned off']);
    expect(titles(mobileTlsRule, 'src/main/java/Net.java', [
      'public void checkServerTrusted(X509Certificate[] chain, String authType) { }',
      'HttpsURLConnection.setDefaultHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);',
    ].join('\n'))).toEqual(['1:critical:TrustManager accepts any certificate', '2:critical:Host name check turned off']);
    expect(titles(mobileTlsRule, 'lib/api.dart', 'client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;')).toEqual(['1:critical:Flutter HTTP client accepts any certificate (badCertificateCallback)']);
    expect(titles(mobileTlsRule, 'ios/Net.swift', [
      'func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {',
      '  completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))',
      '}',
    ].join('\n'))).toEqual(['2:critical:URLSession accepts any server certificate']);
    // Server-side TLS settings belong to the backend, not the app.
    expect(mobileTlsRule.appliesTo.test('src/http.ts')).toBe(false);
  });

  it('reads Info.plist', () => {
    expect(titles(mobileTlsRule, 'ios/Nolt/Info.plist', '<dict>\n  <key>NSAppTransportSecurity</key>\n  <dict>\n    <key>NSAllowsArbitraryLoads</key>\n    <true/>\n  </dict>\n</dict>')).toEqual(['4:high:App Transport Security turned off (NSAllowsArbitraryLoads)']);
    expect(lines(mobileTlsRule, 'ios/Nolt/Info.plist', '<key>NSAllowsArbitraryLoads</key>\n<false/>')).toEqual([]);
  });

  it('leaves safe code alone', () => {
    expect(lines(mobileTlsRule, 'src/Net.kt', 'val pinner = CertificatePinner.Builder().add("api.nolt.example", "sha256/AAAA").build()\nval client = OkHttpClient.Builder().certificatePinner(pinner).build()')).toEqual([]);
    expect(lines(mobileTlsRule, 'ios/Net.swift', 'func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge) {\n  guard SecTrustEvaluateWithError(trust, nil) else { return }\n  completionHandler(.useCredential, URLCredential(trust: trust))\n}')).toEqual([]);
    expect(tlsFindings(file('app/src/main/res/xml/other.xml', '<resources />'))).toEqual([]);
  });
});

describe('MOB-PIN-001: no certificate pinning', () => {
  it('knows which files are app entry points', () => {
    expect(appEntry(file('android/app/src/main/AndroidManifest.xml', '<manifest>\n<uses-permission android:name="android.permission.INTERNET"/>\n<application android:label="x">'))?.line).toBe(3);
    expect(appEntry(file('ios/Nolt/Info.plist', '<key>CFBundleIdentifier</key>\n<string>com.nolt</string>\n<key>LSRequiresIPhoneOS</key>'))?.kind).toBe('iOS app');
    expect(appEntry(file('app.json', '{\n  "expo": {\n    "ios": {}\n  }\n}'))?.line).toBe(2);
    expect(appEntry(file('pubspec.yaml', 'name: nolt\ndependencies:\n  flutter:\n    sdk: flutter\nflutter:\n  uses-material-design: true'))?.line).toBe(5);
    expect(appEntry(file('node_modules/x/android/src/main/AndroidManifest.xml', '<application>'))).toBeNull();
    expect(appEntry(file('ios/Pods/Target Support Files/Info.plist', '<key>CFBundleIdentifier</key><key>CFBundleExecutable</key>'))).toBeNull();
    expect(appEntry(file('pubspec.yaml', 'flutter:\n  plugin:\n    platforms: {}\n  sdk: flutter'))).toBeNull();
  });

  it('flags an app with no pinning anywhere, and not one that pins', () => {
    const manifest = file('android/app/src/main/AndroidManifest.xml', '<manifest>\n<application android:label="Nolt">\n</application>\n</manifest>');
    expect(mobilePinningRule.run(manifest, emptyContext()).map((d) => d.title)).toEqual(['Android app with no certificate pinning']);
    const ctx = buildContext([manifest, file('android/app/src/main/java/com/nolt/Http.kt', 'val pinner = CertificatePinner.Builder().build()')]);
    expect(ctx.pinning).toBe(true);
    expect(mobilePinningRule.run(manifest, ctx)).toEqual([]);
    expect(buildContext([file('package.json', '{"dependencies":{"react-native-ssl-public-key-pinning":"1.2.0"}}')]).pinning).toBe(true);
  });
});

describe('fortis mobile: built apps', () => {
  it('reads ZIP archives, stored and deflated', () => {
    for (const store of [false, true]) {
      const buf = zip({ 'a.txt': 'hello', 'dir/b.json': '{"x":1}' }, store);
      const entries = zipEntries(buf);
      expect(entries.map((e) => e.name)).toEqual(['a.txt', 'dir/b.json']);
      expect(zipRead(buf, entries[1]!).toString()).toBe('{"x":1}');
    }
    expect(() => zipEntries(Buffer.from('not a zip at all, sorry'))).toThrow(/Not a ZIP/);
  });

  it('reads the string table of a .dex file and printable strings of a binary', () => {
    expect(dexStrings(dex(['Lcom/nolt/Api;', 'https://api.example', LIVE_KEY]))).toEqual(['Lcom/nolt/Api;', 'https://api.example', LIVE_KEY]);
    expect(dexStrings(Buffer.from('not dex'))).toEqual([]);
    expect(printableStrings(Buffer.from([0, 1, ...Buffer.from('short'), 0, ...Buffer.from('long enough string'), 255]))).toEqual(['long enough string']);
  });

  it('finds keys in an APK, a bundled .env and plain-HTTP config', () => {
    const apk = zip({
      'AndroidManifest.xml': Buffer.from([3, 0, 8, 0, 1, 2, 3]),
      'classes.dex': dex(['Lcom/nolt/Pay;', LIVE_KEY]),
      'assets/index.android.bundle': 'var config={apiUrl:"https://api.example"};',
      'assets/.env': 'API_URL=https://api.example',
      'res/xml/network_security_config.xml': '<network-security-config>\n  <base-config cleartextTrafficPermitted="true" />\n</network-security-config>',
      'res/drawable/logo.png': Buffer.alloc(100),
      'META-INF/CERT.RSA': Buffer.alloc(10),
    });
    const r = scanAppArchive('nolt.apk', apk);
    expect(r.kind).toBe('Android');
    expect(r.detections.map((d) => `${d.ruleId} ${d.file}`).sort()).toEqual([
      'FX-SEC-001 nolt.apk!/classes.dex.txt',
      'MOB-KEY-001 nolt.apk!/assets/.env',
      'MOB-TLS-001 nolt.apk!/res/xml/network_security_config.xml',
    ]);
    expect(r.detections.find((d) => d.ruleId === 'FX-SEC-001')!.line).toBe(0);
  });

  it('finds keys in an IPA and reads its Info.plist', () => {
    const ipa = zip({
      'Payload/Nolt.app/Info.plist': '<plist><dict>\n<key>NSAllowsArbitraryLoads</key>\n<true/>\n</dict></plist>',
      'Payload/Nolt.app/main.jsbundle': `var k="${LIVE_KEY}";`,
      'Payload/Nolt.app/Nolt': Buffer.concat([Buffer.alloc(64), Buffer.from('https://api.example/v1'), Buffer.alloc(8)]),
    });
    const r = scanAppArchive('Nolt.ipa', ipa);
    expect(r.kind).toBe('iOS');
    expect(r.detections.map((d) => `${d.ruleId}:${d.line}`).sort()).toEqual(['FX-SEC-001:1', 'MOB-TLS-001:2']);
  });

  it('notes what it could not judge', () => {
    const r = scanAppArchive('x.ipa', zip({ 'Payload/X.app/Info.plist': Buffer.concat([Buffer.from('bplist00'), Buffer.alloc(40)]) }));
    expect(r.notes.join(' ')).toMatch(/binary plist/);
  });
});

describe('the mobile rules', () => {
  it('belong to the mobile pack', () => {
    for (const r of MOBILE_RULES) expect(r.pack).toBe('mobile');
  });
});
