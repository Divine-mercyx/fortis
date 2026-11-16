import { spawn } from 'node:child_process';
import { join } from 'node:path';

import type { SourceFile } from './types';

/*
 * Helm charts, rendered (#93). A chart's templates decide a Service's type and ports from values
 * (`type: {{ .Values.service.type }}`), which the file checks can't judge. When Helm is installed, `helm template`
 * renders each chart that has a Service template, with its default values, and INF-K8S-001 checks what comes out.
 * Rendering runs no hooks and talks to no cluster. Without Helm the scan says the charts weren't rendered.
 */

export type HelmRunner = (args: string[], opts: { cwd: string; timeoutMs: number }) => Promise<{ code: number | null; stdout: string; stderr: string; missing?: boolean }>;

export const CHART_FILE = /(?:^|\/)Chart\.ya?ml$/;
const HELM_TIMEOUT_MS = 60_000;

/** Chart folders among these paths that have a Service template, found from the paths alone plus a read function. */
export function chartsWithServices(paths: string[], read: (path: string) => string | null): string[] {
  const charts = paths.filter((p) => CHART_FILE.test(p)).map((p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '.'));
  return charts.filter((dir) => {
    const prefix = dir === '.' ? 'templates/' : `${dir}/templates/`;
    return paths.some((p) => p.startsWith(prefix) && /\.ya?ml$/i.test(p) && /kind:\s*Service\b/.test(read(p) ?? ''));
  });
}

/**
 * Splits `helm template` output into one file per template it came from (`# Source: chart/templates/service.yaml`),
 * each named by the template's path in the repository.
 */
export function renderedFiles(output: string, chartDir: string): SourceFile[] {
  const out = new Map<string, string[]>();
  for (const doc of output.split(/^---\s*$/m)) {
    const source = /^# Source: [^/\s]+\/(\S+)/m.exec(doc)?.[1];
    if (!source || !doc.trim()) continue;
    const path = chartDir === '.' ? source : `${chartDir}/${source}`;
    out.set(path, [...(out.get(path) ?? []), doc.trim()]);
  }
  return [...out].map(([path, docs]) => {
    const text = docs.join('\n---\n');
    return { path, text, lines: text.split(/\r?\n/) };
  });
}

/** Renders each chart. Never throws: a chart Helm can't render is named in the notes. */
export async function renderCharts(root: string, charts: string[], run: HelmRunner = runHelm): Promise<{ files: SourceFile[]; notes: string[] }> {
  const files: SourceFile[] = [];
  const notes: string[] = [];
  const failed: string[] = [];
  for (const dir of charts) {
    const res = await run(['template', 'fortis-scan', join(root, dir)], { cwd: root, timeoutMs: HELM_TIMEOUT_MS });
    if (res.missing) {
      notes.push(`Helm isn't installed, so ${charts.length === 1 ? `the chart in ${dir}` : `${charts.length} charts (${charts.slice(0, 3).join(', ')}${charts.length > 3 ? '…' : ''})`} wasn't rendered: a Service whose type or ports come from values through a template wasn't checked. Install Helm, or check the rendered output with fortis scan in CI.`);
      return { files, notes };
    }
    if (res.code !== 0) {
      failed.push(`${dir} (${res.stderr.trim().split(/\r?\n/).pop()?.slice(0, 160) ?? `exit ${res.code}`})`);
      continue;
    }
    files.push(...renderedFiles(res.stdout, dir));
  }
  if (failed.length) notes.push(`helm template couldn't render ${failed.length === 1 ? 'a chart' : `${failed.length} charts`}, so ${failed.length === 1 ? 'its' : 'their'} rendered Services weren't checked: ${failed.join('; ')}. A chart with dependencies needs helm dependency build first.`);
  return { files, notes };
}

/** Runs helm. On Windows, through cmd.exe, so a helm.cmd or helm.bat shim works too. */
export const runHelm: HelmRunner = (args, { cwd, timeoutMs }) =>
  new Promise((done) => {
    const win = process.platform === 'win32';
    const quote = (s: string) => (/[\s"&|<>^]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
    const child = win
      ? spawn('cmd.exe', ['/d', '/s', '/c', `"${['helm', ...args].map(quote).join(' ')}"`], { cwd, windowsVerbatimArguments: true, windowsHide: true })
      : spawn('helm', args, { cwd });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d) => (stdout += d));
    child.stderr?.on('data', (d) => (stderr += d));
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.on('error', (e) => {
      clearTimeout(timer);
      done({ code: null, stdout, stderr: e.message, missing: (e as NodeJS.ErrnoException).code === 'ENOENT' });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      done({ code, stdout, stderr, missing: code === 9009 || code === 127 || /is not recognized as an internal or external command/i.test(stderr) });
    });
  });
