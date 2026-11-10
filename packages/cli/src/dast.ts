import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, posix, resolve, win32 } from 'node:path';

import { maskSnippet, maskText, type CliFinding, type Severity } from '@fortis/shared';

/*
 * Running-app tests with OWASP ZAP, run from the official Docker image, or from a ZAP installed on
 * this machine when Docker isn't available.
 *  baseline: spider plus passive checks only. Safe for staging; sends no attacks.
 *  full:     spider plus active scan (attack simulation). Never against production.
 *  api:      OpenAPI-driven active scan of each operation (counts as full).
 */

export const ZAP_IMAGE = process.env.FORTIS_ZAP_IMAGE ?? 'zaproxy/zap-stable';

export type DastMode = 'baseline' | 'full';

export type DastFinding = CliFinding & {
  /** Every URL ZAP saw the alert on (the upload carries the first plus a list in `detail`). */
  urls: string[];
  confidence: string;
  cwe?: number;
};

type ZapInstance = { uri?: string; method?: string; param?: string; evidence?: string };
type ZapAlert = {
  pluginid?: string;
  alertRef?: string;
  alert?: string;
  name?: string;
  riskcode?: string;
  confidence?: string;
  desc?: string;
  solution?: string;
  otherinfo?: string;
  reference?: string;
  cweid?: string;
  instances?: ZapInstance[];
};
export type ZapReport = { site?: { '@name'?: string; alerts?: ZapAlert[] }[] };

const RISK: Record<string, Severity> = { '3': 'high', '2': 'medium', '1': 'low', '0': 'info' };
const CONFIDENCE: Record<string, string> = { '0': 'false positive', '1': 'low', '2': 'medium', '3': 'high', '4': 'confirmed' };

/** ZAP descriptions are HTML fragments; keep plain text. */
export function stripHtml(s = ''): string {
  return s
    .replace(/<\/p>\s*<p>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{2,}/g, '\n')
    .trim();
}

function pathOf(uri: string, origin: string): string {
  try {
    const u = new URL(uri);
    // Query strings can hold tokens or IDs; keep the path only.
    return u.origin === origin ? u.pathname || '/' : `${u.origin}${u.pathname}`;
  } catch {
    return uri.split('?')[0] || '/';
  }
}

/**
 * Turns a ZAP JSON report into one finding per alert type. Findings are keyed by the ZAP alert
 * reference, so the same issue keeps the same identity across runs even as the URLs it shows up
 * on change. Alerts ZAP itself marks as false positives are dropped.
 */
export function parseZapReport(report: ZapReport, targetOrigin: string): DastFinding[] {
  const byRef = new Map<string, DastFinding>();
  const solutions = new Map<string, string>();
  for (const site of report.site ?? []) {
    for (const a of site.alerts ?? []) {
      if (a.confidence === '0') continue;
      const ref = (a.alertRef || a.pluginid || '').replace(/[^0-9A-Za-z-]/g, '');
      if (!ref) continue;
      const severity = RISK[a.riskcode ?? ''] ?? 'info';
      const urls = [...new Set((a.instances ?? []).map((i) => pathOf(i.uri ?? '', targetOrigin)))].sort();
      const existing = byRef.get(ref);
      if (existing) {
        existing.urls = [...new Set([...existing.urls, ...urls])].sort();
        continue;
      }
      solutions.set(ref, stripHtml(a.solution));
      const evidence = (a.instances ?? []).find((i) => i.evidence)?.evidence;
      const cwe = Number(a.cweid);
      byRef.set(ref, {
        ruleId: `ZAP-${ref}`.toUpperCase().slice(0, 40),
        severity,
        title: (a.alert || a.name || `ZAP alert ${ref}`).slice(0, 200),
        file: urls[0] ?? '/',
        snippet: evidence ? maskSnippet(evidence).slice(0, 300) : undefined,
        urls,
        confidence: CONFIDENCE[a.confidence ?? ''] ?? 'unknown',
        cwe: Number.isFinite(cwe) && cwe > 0 ? cwe : undefined,
        detail: stripHtml(a.desc),
        fingerprint: `zap:${ref}`,
      });
    }
  }
  const findings = [...byRef.values()];
  for (const f of findings) {
    const sol = solutions.get(f.fingerprint!.slice(4));
    const where = f.urls.length > 1 ? `\n\nSeen on ${f.urls.length} URLs: ${f.urls.slice(0, 10).join(', ')}${f.urls.length > 10 ? ', …' : ''}` : '';
    const cwe = f.cwe ? `\nCWE-${f.cwe} · confidence ${f.confidence}` : `\nConfidence ${f.confidence}`;
    f.file = f.urls[0] ?? '/';
    f.detail = maskText(`${f.detail}${sol ? `\n\nFix: ${sol}` : ''}${where}${cwe}`).slice(0, 4000);
  }
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  return findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || a.ruleId.localeCompare(b.ruleId));
}

/** Origins in the report, to check an imported report really is for the target. */
export function reportOrigins(report: ZapReport): string[] {
  const out = new Set<string>();
  for (const site of report.site ?? []) {
    try {
      if (site['@name']) out.add(new URL(site['@name']).origin);
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

const LOCAL_HOST = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1|host\.docker\.internal|[\w-]+\.localhost)$/i;
export const isLocalHost = (hostname: string) => LOCAL_HOST.test(hostname);

export function dockerAvailable(): { ok: true } | { ok: false; reason: string } {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
  if (r.error) return { ok: false, reason: 'Docker is not installed.' };
  if (r.status !== 0) return { ok: false, reason: 'Docker is installed but not running (start Docker Desktop or the docker service).' };
  return { ok: true };
}

/** Where a ZAP installed on this machine lives: FORTIS_ZAP_PATH, then PATH, then the usual install folders. */
export function findLocalZap(env: NodeJS.ProcessEnv = process.env, platform: string = process.platform, exists: (p: string) => boolean = existsSync, home = homedir()): string | null {
  const override = env.FORTIS_ZAP_PATH?.trim();
  if (override) return exists(override) ? override : null;
  const windows = platform === 'win32';
  const path = windows ? win32 : posix;
  const names = windows ? ['zap.bat'] : ['zap.sh', 'zaproxy', 'zap'];
  const dirs = (env.PATH ?? env.Path ?? '').split(windows ? ';' : ':').filter(Boolean);
  const onPath = dirs.flatMap((d) => names.map((n) => path.join(d, n)));
  const known = windows
    ? [env.ProgramFiles, env['ProgramFiles(x86)'], env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, 'Programs')].filter((d): d is string => Boolean(d)).map((d) => path.join(d, 'ZAP', 'Zed Attack Proxy', 'zap.bat'))
    : platform === 'darwin'
      ? ['/Applications/ZAP.app/Contents/Java/zap.sh', path.join(home, 'Applications/ZAP.app/Contents/Java/zap.sh')]
      : ['/usr/share/zaproxy/zap.sh', '/opt/zaproxy/zap.sh', '/snap/bin/zaproxy'];
  return [...onPath, ...known].find((p) => exists(p)) ?? null;
}

export type ZapEngine = { kind: 'docker' } | { kind: 'local'; path: string };

/** Docker stays the default, because it needs no Java and pins the ZAP version. FORTIS_ZAP_PATH always wins. */
export function chooseZapEngine(
  env: NodeJS.ProcessEnv = process.env,
  docker: () => { ok: true } | { ok: false; reason: string } = dockerAvailable,
  find: (env: NodeJS.ProcessEnv) => string | null = findLocalZap,
): ZapEngine | { kind: 'none'; reason: string } {
  const local = find(env);
  if (env.FORTIS_ZAP_PATH?.trim()) return local ? { kind: 'local', path: local } : { kind: 'none', reason: `FORTIS_ZAP_PATH points at ${env.FORTIS_ZAP_PATH.trim()}, which doesn't exist.` };
  const d = docker();
  if (d.ok) return { kind: 'docker' };
  return local ? { kind: 'local', path: local } : { kind: 'none', reason: d.reason };
}

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * A ZAP Automation Framework plan with the same steps as the Docker scripts. Written as JSON, which
 * is valid YAML, so paths and URLs never need escaping by hand.
 */
export function zapPlan(opts: { target: string; mode: DastMode; openapi?: string; minutes: number; reportDir: string }) {
  const passive = { type: 'passiveScan-wait', parameters: { maxDuration: Math.max(opts.minutes, 5) } };
  const scan = opts.openapi
    ? [{ type: 'openapi', parameters: { ...(/^https?:/i.test(opts.openapi) ? { apiUrl: opts.openapi } : { apiFile: resolve(opts.openapi) }), targetUrl: opts.target } }]
    : [{ type: 'spider', parameters: { maxDuration: opts.minutes } }];
  const active = opts.openapi || opts.mode === 'full' ? [{ type: 'activeScan', parameters: {} }, passive] : [];
  return {
    env: {
      contexts: [{ name: 'fortis', urls: [opts.target], includePaths: [`${escapeRegex(new URL(opts.target).origin)}.*`] }],
      parameters: { failOnError: true, failOnWarning: false, progressToStdout: true },
    },
    jobs: [
      ...scan,
      passive,
      ...active,
      { type: 'report', parameters: { template: 'traditional-json', reportDir: opts.reportDir, reportFile: 'report.json', reportTitle: 'Fortis' } },
    ],
  };
}

/** The command line for a local ZAP. Node can't start a .bat directly, so Windows goes through cmd.exe. */
export function localZapCommand(zapPath: string, planFile: string, homeDir: string, platform: string = process.platform) {
  const zapArgs = ['-cmd', '-autorun', planFile, '-dir', homeDir, '-silent'];
  if (platform === 'win32') {
    const line = `"${zapPath}" ${zapArgs.map((a) => (a.startsWith('-') ? a : `"${a}"`)).join(' ')}`;
    return { command: 'cmd.exe', args: ['/d', '/s', '/c', `"${line}"`], windowsVerbatimArguments: true };
  }
  return { command: zapPath, args: zapArgs, windowsVerbatimArguments: false };
}

/** The docker command line for a run. Exported for tests. */
/** A test user's credential, sent as one header on requests to the target host only. */
export type ZapAuth = { header: string; value: string };

export function zapCommand(opts: { target: string; mode: DastMode; openapi?: string; minutes: number; name: string; local: boolean; platform?: string; extraArgs?: string; auth?: ZapAuth }) {
  const platform = opts.platform ?? process.platform;
  let target = opts.target;
  let openapi = opts.openapi;
  // Extra docker flags for private networks, e.g. FORTIS_ZAP_DOCKER_ARGS="--add-host staging.internal:10.0.0.5".
  const net: string[] = (opts.extraArgs ?? process.env.FORTIS_ZAP_DOCKER_ARGS ?? '').split(/\s+/).filter(Boolean);
  if (opts.local) {
    // Inside the container, "localhost" is the container. Reach the host instead.
    if (platform === 'linux') net.push('--network', 'host');
    else {
      const swap = (u: string) => u.replace(/\/\/(localhost|127\.0\.0\.1)(?=[:/]|$)/i, '//host.docker.internal');
      target = swap(target);
      openapi = openapi && swap(openapi);
    }
  }
  // ZAP's packaged scans add this header to every request for the site. The value is passed
  // through the environment (-e NAME with no value), so it never appears in the process list.
  const auth = opts.auth
    ? ['-e', `ZAP_AUTH_HEADER=${opts.auth.header}`, '-e', 'ZAP_AUTH_HEADER_VALUE', '-e', `ZAP_AUTH_HEADER_SITE=${new URL(target).hostname}`]
    : [];
  const script = openapi ? 'zap-api-scan.py' : opts.mode === 'full' ? 'zap-full-scan.py' : 'zap-baseline.py';
  const scriptArgs = openapi
    ? ['-t', openapi, '-f', 'openapi', '-O', target]
    : ['-t', target, '-m', String(opts.minutes)];
  return [
    'run', '--rm', '--name', opts.name, ...net, ...auth,
    '-v', 'WORKDIR:/zap/wrk/:rw',
    ZAP_IMAGE, script, ...scriptArgs, '-J', 'report.json', '-I',
  ];
}

export type ZapRun = { report: ZapReport; exitCode: number; stopped: boolean };

/**
 * Runs ZAP and returns its report. `shouldStop` is polled every 20 seconds; when it returns a
 * reason (for example the target was paused in the dashboard) ZAP is stopped.
 */
export async function runZap(
  opts: { target: string; mode: DastMode; openapi?: string; minutes: number; local: boolean; auth?: ZapAuth; engine?: ZapEngine },
  hooks: { onLine?: (line: string) => void; shouldStop?: () => Promise<string | null> } = {},
): Promise<ZapRun> {
  const engine = opts.engine ?? { kind: 'docker' };
  const work = mkdtempSync(join(tmpdir(), 'fortis-zap-'));
  chmodSync(work, 0o777); // the image runs as the unprivileged "zap" user
  const name = `fortis-zap-${process.pid}-${Date.now()}`;
  let stopped = false;
  let timer: NodeJS.Timeout | undefined;
  let stopOnSignal: (() => void) | undefined;
  const tail: string[] = [];
  try {
    const exitCode = await new Promise<number>((done, reject) => {
      const scrub = (l: string) => (opts.auth ? l.split(opts.auth.value).join('••••') : l);
      const onData = (buf: Buffer) =>
        buf.toString().split('\n').filter(Boolean).forEach((l) => {
          const line = scrub(l);
          tail.push(line);
          if (tail.length > 5) tail.shift();
          hooks.onLine?.(line);
        });
      let stop: () => void;
      let child: ReturnType<typeof spawn>;
      if (engine.kind === 'docker') {
        const args = zapCommand({ ...opts, name }).map((a) => (a === 'WORKDIR:/zap/wrk/:rw' ? `${work}:/zap/wrk/:rw` : a));
        const env = opts.auth ? { ...process.env, ZAP_AUTH_HEADER_VALUE: opts.auth.value } : process.env;
        child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'], env });
        stop = () => spawnSync('docker', ['stop', '-t', '5', name]);
      } else {
        const planFile = join(work, 'plan.yaml');
        const homeDir = join(work, 'home'); // its own settings folder, so a ZAP desktop session keeps running
        mkdirSync(homeDir);
        writeFileSync(planFile, JSON.stringify(zapPlan({ ...opts, reportDir: work }), null, 2));
        const { command, args, windowsVerbatimArguments } = localZapCommand(engine.path, planFile, homeDir);
        // ZAP reads these itself. The value goes through the environment, so it never appears in the process list.
        const env = opts.auth
          ? { ...process.env, ZAP_AUTH_HEADER: opts.auth.header, ZAP_AUTH_HEADER_VALUE: opts.auth.value, ZAP_AUTH_HEADER_SITE: new URL(opts.target).hostname }
          : process.env;
        // zap.sh and zap.bat start Java as a child, so stopping has to reach the whole process group.
        const windows = process.platform === 'win32';
        child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], env, cwd: dirname(realpathSync(engine.path)), detached: !windows, windowsVerbatimArguments });
        const pid = child.pid;
        stop = () => {
          if (!pid) return;
          if (windows) spawnSync('taskkill', ['/pid', String(pid), '/t', '/f']);
          else {
            try {
              process.kill(-pid, 'SIGTERM');
            } catch {
              /* already gone */
            }
          }
        };
        // A detached process doesn't get the terminal's Ctrl-C.
        stopOnSignal = () => {
          stop();
          process.exit(130);
        };
        process.once('SIGINT', stopOnSignal);
      }
      child.stdout!.on('data', onData);
      child.stderr!.on('data', onData);
      child.on('error', reject);
      child.on('close', (code) => done(code ?? 3));
      if (hooks.shouldStop) {
        timer = setInterval(async () => {
          const reason = await hooks.shouldStop!().catch(() => null);
          if (reason && !stopped) {
            stopped = true;
            hooks.onLine?.(`Stopping: ${reason}`);
            stop();
          }
        }, 20_000);
      }
    });
    const file = join(work, 'report.json');
    if (!existsSync(file)) {
      if (stopped) return { report: {}, exitCode, stopped };
      if (engine.kind === 'local') throw new Error(`ZAP at ${engine.path} exited with code ${exitCode} and wrote no report. ZAP needs Java 17 or newer, and the target must be reachable from this machine.${tail.length ? `\nLast output:\n${tail.join('\n')}` : ''}`);
      throw new Error(`ZAP exited with code ${exitCode} and wrote no report. Check that the target is reachable from this machine.`);
    }
    let raw = readFileSync(file, 'utf8');
    // Never let the test user's credential reach the report, the terminal or the dashboard.
    if (opts.auth) raw = raw.split(opts.auth.value).join('••••');
    return { report: JSON.parse(raw) as ZapReport, exitCode, stopped };
  } finally {
    if (timer) clearInterval(timer);
    if (stopOnSignal) process.removeListener('SIGINT', stopOnSignal);
    rmSync(work, { recursive: true, force: true });
  }
}

/** Waits until the target answers with anything below 500 (a deploy that's up), for up to `seconds`. */
export async function waitForTarget(url: string, seconds: number, onWait?: (msg: string) => void, fetchImpl: typeof fetch = fetch): Promise<boolean> {
  const deadline = Date.now() + seconds * 1000;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const res = await fetchImpl(url, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(15_000) });
      if (res.status < 500) return true;
      last = `HTTP ${res.status}`;
    } catch (e) {
      last = (e as Error).message;
    }
    onWait?.(`Waiting for ${url} (${last})…`);
    await new Promise((r) => setTimeout(r, 10_000));
  }
  return false;
}
