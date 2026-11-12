import type { Detection, FileRule, ProjectContext, SourceFile } from './types';
import { isIgnored } from './types';

/*
 * Mobile app checks. Everything in an app bundle can be read by anyone who downloads the app:
 * unzipping an APK or IPA takes seconds. So a server secret that reaches the bundle is public,
 * and an app that turns TLS checks off, or trusts any certificate, lets anyone on the same Wi-Fi
 * read and change its traffic, PINs and tokens included.
 *
 * MOB-KEY-001  server secrets that end up in the app bundle (EXPO_PUBLIC_*, buildConfigField, app.json extra, a bundled .env)
 * MOB-TLS-001  TLS weakened: cleartext traffic, trust-all certificates or host names, user CAs, NSAllowsArbitraryLoads
 * MOB-PIN-001  a mobile app with no certificate pinning anywhere in the project
 *
 * Android (Kotlin, Java, XML, Gradle), iOS (Swift, Objective-C, Info.plist), React Native and Expo,
 * and Flutter. Server-side TLS settings (a database connection with rejectUnauthorized: false) are
 * out of scope here. Silence a reviewed line with `// fortis-ignore` or `<!-- fortis-ignore -->`.
 */

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string, fix: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
  fix,
});

const ignored = (file: SourceFile, line: number) => isIgnored(file, line) || /fortis-ignore/.test(file.lines[line - 2] ?? '') && /<!--/.test(file.lines[line - 2] ?? '');

/* ------------------------------------------------- MOB-KEY-001: secrets in the bundle */

/** Prefixes that bundlers inline into client code: anything behind them ships to every user. */
export const PUBLIC_PREFIX = /\b(EXPO_PUBLIC_|REACT_APP_|NEXT_PUBLIC_|VITE_|NUXT_PUBLIC_|PUBLIC_|GATSBY_|STORYBOOK_)([A-Z0-9_]+)/;
/** Names that say a value is meant for a server. Public and publishable keys are fine in an app. */
export const SECRET_NAME = /(?:^|_)(?:SECRET|SECRETS|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|ADMIN|MASTER|SK|SIGNING|WEBHOOK_SECRET|CLIENT_SECRET|API_SECRET|SECRET_KEY|PRIVATE_KEY|ACCESS_KEY_SECRET|DB_URL|DATABASE_URL)(?:_|$)/;
const PUBLIC_NAME = /(?:^|_)(?:PUBLIC|PUBLISHABLE|PK|ANON|CLIENT_ID|SITE_KEY)(?:_|$)/;

export const isSecretName = (name: string) => SECRET_NAME.test(name.toUpperCase()) && !PUBLIC_NAME.test(name.toUpperCase());

const KEY_FIX = {
  env: 'Move this call to your backend and keep the secret there. Anything in an EXPO_PUBLIC_, REACT_APP_, NEXT_PUBLIC_ or VITE_ variable is copied into the app bundle, where anyone can read it. Rotate the key: it is already in every build that shipped.',
  gradle: 'Don\'t compile secrets into the app: buildConfigField and resValue values end up in the APK. Call your backend instead, and rotate the key.',
  extra: 'expo.extra is bundled into the app and readable with Constants.expoConfig. Keep secrets on your backend, and rotate this one.',
  dotenv: 'Don\'t list .env as a Flutter asset: it ships inside the app unencrypted. Use --dart-define for public values and your backend for secrets.',
};

export const mobileKeyRule: FileRule = {
  id: 'MOB-KEY-001',
  pack: 'mobile',
  appliesTo: /(?:^|\/)\.env(?:\.[\w.-]+)?$|\.(?:[cm]?[jt]sx?|gradle|kts|json|ya?ml|properties)$|(?:^|\/)app\.config\.[cm]?[jt]s$/i,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    const add = (line: number, severity: Detection['severity'], title: string, fix: string) => {
      if (!ignored(file, line) && !out.some((d) => d.line === line)) out.push(hit(file, line, 'MOB-KEY-001', severity, title, fix));
    };
    const isEnv = /(?:^|\/)\.env(?:\.[\w.-]+)?$/i.test(file.path);
    const isGradle = /\.(?:gradle|kts)$/i.test(file.path);
    const isExpoConfig = /(?:^|\/)app\.(?:json|config\.[cm]?[jt]s)$/i.test(file.path);
    const isPubspec = /(?:^|\/)pubspec\.ya?ml$/i.test(file.path);
    const code = /\.[cm]?[jt]sx?$/i.test(file.path);
    file.lines.forEach((line, i) => {
      const n = i + 1;
      // EXPO_PUBLIC_PAYSTACK_SECRET_KEY=... in .env, or process.env.EXPO_PUBLIC_..._SECRET in code.
      if (isEnv || code) {
        const m = PUBLIC_PREFIX.exec(line);
        if (m && isSecretName(m[2]!)) {
          const defined = isEnv ? /^\s*(?:export\s+)?[A-Z0-9_]+\s*=\s*\S/.test(line) : /process\.env\.|import\.meta\.env\.|Constants\.|env\./.test(line);
          if (defined) add(n, 'high', `Server secret exposed to the app bundle (${m[1]}${m[2]})`, KEY_FIX.env);
        }
      }
      // buildConfigField "String", "PAYSTACK_SECRET_KEY", "\"sk_live_...\"" (Groovy and Kotlin DSL).
      if (isGradle) {
        const m = /\b(?:buildConfigField|resValue)\s*\(?\s*["'][^"']+["']\s*,\s*["']([A-Za-z0-9_]+)["']\s*,\s*["'](.+)["']/.exec(line);
        if (m && isSecretName(m[1]!) && !/System\.getenv|project\.findProperty|providers\.|properties\[|getProperty|localProperties|\$\{?\s*(?:project|rootProject)/.test(m[2]!)) {
          add(n, 'high', `Secret compiled into the app (${m[1]})`, KEY_FIX.gradle);
        }
      }
      // expo.extra: { paystackSecretKey: "sk_live_..." }
      if (isExpoConfig && /extra/.test(file.text)) {
        const m = /["']?([A-Za-z0-9_]*(?:[Ss]ecret|[Pp]rivate|SECRET|PRIVATE|[Pp]assword|PASSWORD|[Ss]erviceRole)[A-Za-z0-9_]*)["']?\s*:\s*["']([^"']{8,})["']/.exec(line);
        if (m && !/publishable|public|anon/i.test(m[1]!) && !/\$\{|process\.env/.test(m[2]!)) add(n, 'high', `Secret in the app config's extra (${m[1]})`, KEY_FIX.extra);
      }
      // Flutter assets: - .env
      if (isPubspec && /^\s*-\s*["']?(?:assets\/)?\.env(?:\.[\w.-]+)?["']?\s*$/.test(line.replace(/\s+#.*$/, ''))) add(n, 'high', 'App bundles its .env file as an asset', KEY_FIX.dotenv);
    });
    return out;
  },
};

/* ------------------------------------------------- MOB-TLS-001: TLS weakened */

const TLS_FIX = {
  cleartext: 'Turn cleartext traffic off (android:usesCleartextTraffic="false", cleartextTrafficPermitted="false") and use HTTPS everywhere. Allow HTTP only for local development hosts, in a domain-config or a debug build.',
  trustAll: 'Remove the trust-all TrustManager or HostnameVerifier and use the platform\'s defaults. To trust your own certificate, pin it with OkHttp\'s CertificatePinner or a network_security_config pin-set instead.',
  userCa: 'Trust user-installed CAs only in <debug-overrides>, so a proxy or malware-installed certificate can\'t read release-build traffic.',
  ats: 'Remove NSAllowsArbitraryLoads and keep App Transport Security on. If one host needs an exception, add it under NSExceptionDomains.',
  dart: 'Remove badCertificateCallback (or make it return false). To trust your own certificate, use a SecurityContext with it, or a pinning package.',
  swift: 'Evaluate the server trust before accepting it (SecTrustEvaluateWithError, plus your pins), and fall back to .performDefaultHandling.',
};

const LOCAL_HOSTS = /localhost|127\.0\.0\.1|10\.0\.2\.2|10\.0\.3\.2|0\.0\.0\.0|\.local\b|\.test\b/i;

export function tlsFindings(file: SourceFile): { line: number; severity: Detection['severity']; title: string; fix: string }[] {
  const out: { line: number; severity: Detection['severity']; title: string; fix: string }[] = [];
  const add = (line: number, severity: Detection['severity'], title: string, fix: string) => {
    if (!out.some((d) => d.line === line)) out.push({ line, severity, title, fix });
  };
  const p = file.path;
  const lines = file.lines;
  if (/AndroidManifest\.xml$/i.test(p)) {
    lines.forEach((l, i) => { if (/android:usesCleartextTraffic\s*=\s*["']true["']/.test(l)) add(i + 1, 'high', 'App allows plain HTTP (usesCleartextTraffic)', TLS_FIX.cleartext); });
  }
  if (/network_security_config[\w-]*\.xml$/i.test(p) || /<network-security-config/.test(file.text)) {
    let section: 'base' | 'domain' | 'debug' | '' = '';
    let domainLocal = false;
    lines.forEach((l, i) => {
      if (/<base-config/.test(l)) section = 'base';
      else if (/<domain-config/.test(l)) { section = 'domain'; domainLocal = true; }
      else if (/<debug-overrides/.test(l)) section = 'debug';
      if (section === 'domain' && /<domain[\s>]/.test(l) && !LOCAL_HOSTS.test(l)) domainLocal = false;
      if (/cleartextTrafficPermitted\s*=\s*["']true["']/.test(l)) {
        const inDomain = section === 'domain' || /<domain-config/.test(l);
        // Look ahead at the domain list of a domain-config that opens on this line.
        if (inDomain && /<domain-config/.test(l)) {
          const end = lines.findIndex((x, k) => k > i && /<\/domain-config>/.test(x));
          domainLocal = lines.slice(i, end === -1 ? undefined : end).filter((x) => /<domain[\s>]/.test(x)).every((x) => LOCAL_HOSTS.test(x));
        }
        if (!(inDomain && domainLocal) && section !== 'debug') add(i + 1, 'high', 'App allows plain HTTP (cleartextTrafficPermitted)', TLS_FIX.cleartext);
      }
      if (/<certificates\s+src\s*=\s*["']user["']/.test(l) && section !== 'debug') add(i + 1, 'medium', 'App trusts user-installed certificates', TLS_FIX.userCa);
      if (/<\/(?:base-config|domain-config|debug-overrides)>/.test(l)) section = '';
    });
  }
  if (/Info\.plist$/i.test(p)) {
    lines.forEach((l, i) => {
      if (/<key>NSAllowsArbitraryLoads(?:InWebContent|ForMedia)?<\/key>/.test(l) && /<true\s*\/>/.test(`${l} ${lines[i + 1] ?? ''}`)) {
        add(i + 1, 'high', 'App Transport Security turned off (NSAllowsArbitraryLoads)', TLS_FIX.ats);
      }
    });
  }
  if (/\.(?:kt|java)$/i.test(p)) {
    lines.forEach((l, i) => {
      const next = lines.slice(i, i + 4).join(' ');
      if (/fun\s+checkServerTrusted\s*\([^)]*\)\s*(?::\s*Unit\s*)?(?:\{\s*\}|=\s*Unit|\{\s*(?:\/\/[^\n]*)?$)/.test(l) && /checkServerTrusted\s*\([^)]*\)[^{]*\{\s*(?:\/\/[^}]*)?\}/.test(next.replace(/\n/g, ' '))) add(i + 1, 'critical', 'TrustManager accepts any certificate', TLS_FIX.trustAll);
      else if (/void\s+checkServerTrusted/.test(l) && /void\s+checkServerTrusted\s*\([^)]*\)[^{]*\{\s*(?:\/\/[^}]*)?\}/.test(next)) add(i + 1, 'critical', 'TrustManager accepts any certificate', TLS_FIX.trustAll);
      const hostAny = /hostnameVerifier\s*(?:=|\(|\{)\s*(?:HostnameVerifier\s*)?\{?\s*_?\w*\s*,\s*_?\w*\s*->\s*true\s*\}|HostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier/.test(l);
      const verifyTrue = /boolean\s+verify\s*\(/.test(l) && /public\s+boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}/.test(lines.slice(i, i + 3).join(' '));
      if ((hostAny || verifyTrue) && !/^\s*(?:\/\/|\*)/.test(l)) add(i + 1, 'critical', 'Host name check turned off', TLS_FIX.trustAll);
      if (/\.sslSocketFactory\s*\([^)]*(?:trustAll|TrustAll|Insecure|Unsafe)|\bgetUnsafeOkHttpClient\s*\(|\bUnsafeOkHttpClient\s*\(/.test(l) && !/^\s*(?:\/\/|\*)|\b(?:fun|class|object|static|public|private)\s+\w*Unsafe/.test(l)) add(i + 1, 'critical', 'HTTP client trusts every certificate', TLS_FIX.trustAll);
    });
  }
  if (/\.dart$/i.test(p)) {
    lines.forEach((l, i) => {
      if (/badCertificateCallback/.test(l) && /badCertificateCallback\s*=\s*\([^)]*\)\s*(?:=>\s*true|\{\s*return\s+true\s*;?\s*\})/.test(lines.slice(i, i + 2).join(' '))) add(i + 1, 'critical', 'Flutter HTTP client accepts any certificate (badCertificateCallback)', TLS_FIX.dart);
    });
  }
  if (/\.swift$/i.test(p) && /didReceive\s+challenge/.test(file.text) && !/SecTrustEvaluate|evaluate\(|pinned|pinning|SecCertificateCopyData|SecTrustCopyCertificateChain|TrustKit/.test(file.text)) {
    lines.forEach((l, i) => { if (/completionHandler\s*\(\s*\.useCredential\s*,\s*URLCredential\s*\(\s*trust\s*:/.test(l)) add(i + 1, 'critical', 'URLSession accepts any server certificate', TLS_FIX.swift); });
  }
  return out;
}

export const mobileTlsRule: FileRule = {
  id: 'MOB-TLS-001',
  pack: 'mobile',
  appliesTo: /\.xml$|Info\.plist$|\.(?:kt|java|dart|swift)$/i,
  skipTests: true,
  run(file) {
    if (!/Cleartext|cleartext|certificates|NSAllowsArbitraryLoads|checkServerTrusted|hostnameVerifier|HostnameVerifier|badCertificateCallback|didReceive|sslSocketFactory|TrustAll|trustAll|UnsafeOkHttp/.test(file.text)) return [];
    return tlsFindings(file).filter((f) => !ignored(file, f.line)).map((f) => hit(file, f.line, 'MOB-TLS-001', f.severity, f.title, f.fix));
  },
};

/* ------------------------------------------------- MOB-PIN-001: no certificate pinning */

/** Anything that pins certificates or public keys, on any of the mobile stacks. */
export const PINNING = /CertificatePinner|<pin-set|<pin\s+digest|TrustKit|react-native-ssl-pinning|react-native-ssl-public-key-pinning|ssl_pinning_plugin|http_certificate_pinning|dio_certificate_pinning|SslPinning|sslPinning|PinningURLSession|pinnedCertificates|pinnedPublicKeys|SecTrustEvaluate|SecCertificateCopyData|AFSecurityPolicy|ServerTrustManager|PublicKeysTrustEvaluator|PinnedCertificatesTrustEvaluator|expo-ssl-pinning|certificatePinner|initializeSslPinning|addPublicKeyPins|isSecureConnection|withPinning/;
/** Files worth reading to find out whether a project pins: small, and only these kinds. */
export const PINNING_FILES = /(?:network_security_config[\w-]*\.xml|\.kt|\.java|\.swift|\.m|\.mm|\.dart|Podfile|package\.json|pubspec\.ya?ml|build\.gradle(?:\.kts)?|\.[cm]?[jt]sx?|Info\.plist)$/i;

const PIN_FIX = 'Pin your API\'s certificate or public key, with a backup pin: OkHttp CertificatePinner or a network_security_config <pin-set> on Android, TrustKit or URLSession trust evaluation on iOS, react-native-ssl-public-key-pinning for React Native and Expo, or a pinning package for Flutter. Without pinning, a certificate from any CA the phone trusts (including one a user was tricked into installing) can read the app\'s traffic.';

/** Where an app declares itself, and the line to report on. Null when the file isn't an app's. */
export function appEntry(file: SourceFile): { line: number; kind: string } | null {
  const p = file.path;
  if (/(?:^|\/)(?:node_modules|Pods|build|\.gradle|ios\/Pods|vendor)\//.test(p)) return null;
  const at = (re: RegExp) => file.lines.findIndex((l) => re.test(l)) + 1;
  if (/(?:^|\/)src\/main\/AndroidManifest\.xml$|(?:^|\/)app\/src\/[\w-]+\/AndroidManifest\.xml$|^AndroidManifest\.xml$/.test(p) && /<application/.test(file.text) && /android\.permission\.INTERNET|<application/.test(file.text)) {
    return { line: at(/<application/), kind: 'Android app' };
  }
  if (/(?:^|\/)ios\/[^/]+\/Info\.plist$|(?:^|\/)[^/]+\/Info\.plist$/.test(p) && /CFBundleIdentifier/.test(file.text) && /CFBundleExecutable|UIApplicationSceneManifest|LSRequiresIPhoneOS|UILaunchStoryboardName/.test(file.text)) {
    return { line: at(/CFBundleIdentifier/), kind: 'iOS app' };
  }
  if (/(?:^|\/)app\.json$/.test(p) && /"expo"\s*:/.test(file.text) && /"(?:ios|android)"\s*:/.test(file.text)) return { line: at(/"expo"\s*:/), kind: 'Expo app' };
  if (/(?:^|\/)pubspec\.ya?ml$/.test(p)) {
    const yaml = file.text.replace(/[ \t]+#.*$/gm, '');
    if (/^flutter:\s*$/m.test(yaml) && /^\s+sdk:\s*flutter/m.test(yaml) && !/^\s*plugin:\s*$/m.test(yaml)) return { line: at(/^flutter:\s*(?:#.*)?$/), kind: 'Flutter app' };
  }
  return null;
}

export const mobilePinningRule: FileRule = {
  id: 'MOB-PIN-001',
  pack: 'mobile',
  appliesTo: /AndroidManifest\.xml$|Info\.plist$|(?:^|\/)app\.json$|(?:^|\/)pubspec\.ya?ml$/i,
  skipTests: true,
  run(file, ctx: ProjectContext) {
    const entry = appEntry(file);
    if (!entry || ctx.pinning || PINNING.test(file.text) || ignored(file, entry.line)) return [];
    return [hit(file, entry.line, 'MOB-PIN-001', 'medium', `${entry.kind} with no certificate pinning`, PIN_FIX)];
  },
};

export const MOBILE_RULES: FileRule[] = [mobileKeyRule, mobileTlsRule, mobilePinningRule];
