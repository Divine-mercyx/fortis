import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { maskSnippet, maskText, type CliFinding, type Severity } from '@fortis/shared';

/*
 * Running-app tests with OWASP ZAP, run from the official Docker image.
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

/** The docker command line for a run. Exported for tests. */
export function zapCommand(opts: { target: string; mode: DastMode; openapi?: string; minutes: number; name: string; local: boolean; platform?: string }) {
  const platform = opts.platform ?? process.platform;
  let target = opts.target;
  let openapi = opts.openapi;
  const net: string[] = [];
  if (opts.local) {
    // Inside the container, "localhost" is the container. Reach the host instead.
    if (platform === 'linux') net.push('--network', 'host');
    else {
      const swap = (u: string) => u.replace(/\/\/(localhost|127\.0\.0\.1)(?=[:/]|$)/i, '//host.docker.internal');
      target = swap(target);
      openapi = openapi && swap(openapi);
    }
  }
  const script = openapi ? 'zap-api-scan.py' : opts.mode === 'full' ? 'zap-full-scan.py' : 'zap-baseline.py';
  const scriptArgs = openapi
    ? ['-t', openapi, '-f', 'openapi', '-O', target]
    : ['-t', target, '-m', String(opts.minutes)];
  return [
    'run', '--rm', '--name', opts.name, ...net,
    '-v', 'WORKDIR:/zap/wrk/:rw',
    ZAP_IMAGE, script, ...scriptArgs, '-J', 'report.json', '-I',
  ];
}

export type ZapRun = { report: ZapReport; exitCode: number; stopped: boolean };

/**
 * Runs ZAP and returns its report. `shouldStop` is polled every 20 seconds; when it returns a
 * reason (for example the target was paused in the dashboard) the container is stopped.
 */
export async function runZap(
  opts: { target: string; mode: DastMode; openapi?: string; minutes: number; local: boolean },
  hooks: { onLine?: (line: string) => void; shouldStop?: () => Promise<string | null> } = {},
): Promise<ZapRun> {
  const work = mkdtempSync(join(tmpdir(), 'fortis-zap-'));
  chmodSync(work, 0o777); // the image runs as the unprivileged "zap" user
  const name = `fortis-zap-${process.pid}-${Date.now()}`;
  const args = zapCommand({ ...opts, name }).map((a) => (a === 'WORKDIR:/zap/wrk/:rw' ? `${work}:/zap/wrk/:rw` : a));
  let stopped = false;
  let timer: NodeJS.Timeout | undefined;
  try {
    const exitCode = await new Promise<number>((resolve, reject) => {
      const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
      const onData = (buf: Buffer) => buf.toString().split('\n').filter(Boolean).forEach((l) => hooks.onLine?.(l));
      child.stdout.on('data', onData);
      child.stderr.on('data', onData);
      child.on('error', reject);
      child.on('close', (code) => resolve(code ?? 3));
      if (hooks.shouldStop) {
        timer = setInterval(async () => {
          const reason = await hooks.shouldStop!().catch(() => null);
          if (reason && !stopped) {
            stopped = true;
            hooks.onLine?.(`Stopping: ${reason}`);
            spawnSync('docker', ['stop', '-t', '5', name]);
          }
        }, 20_000);
      }
    });
    const file = join(work, 'report.json');
    if (!existsSync(file)) {
      if (stopped) return { report: {}, exitCode, stopped };
      throw new Error(`ZAP exited with code ${exitCode} and wrote no report. Check that the target is reachable from this machine.`);
    }
    return { report: JSON.parse(readFileSync(file, 'utf8')) as ZapReport, exitCode, stopped };
  } finally {
    if (timer) clearInterval(timer);
    rmSync(work, { recursive: true, force: true });
  }
}
