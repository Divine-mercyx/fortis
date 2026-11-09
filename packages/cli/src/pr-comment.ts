import { readFileSync } from 'node:fs';

import { maskText } from '@fortis/shared';

import type { Detection } from './rules/types';

/*
 * One summary comment per pull request, updated in place. It lists only what the pull request adds:
 * findings on lines it adds, or in a file it changes when the finding has no line. The added lines
 * come from the GitHub or GitLab API, so this works on the shallow checkouts CI systems use.
 */

/** Hidden in the comment, so the next run can find it. */
export const COMMENT_MARKER = '<!-- fortis-pr-comment -->';
const MAX_ROWS = 50;
const MAX_PAGES = 30;

export type PrContext = {
  kind: 'github' | 'gitlab';
  /** API address, from the CI system's own environment. */
  api: string;
  /** owner/name on GitHub; the project's ID on GitLab. */
  project: string;
  number: string;
  token: string;
  /** Link to a file at this commit: blob(path, line). */
  blob: (path: string, line: number) => string | null;
};

type Env = Record<string, string | undefined>;

const encodePath = (p: string) => p.split('/').map(encodeURIComponent).join('/');
const anchor = (line: number) => (line ? `#L${line}` : '');

/**
 * Works out which pull request this CI run is for. `context` is null outside a pull request, where
 * there's nothing to comment on. `reason` says why a pull request can't get a comment.
 */
export function prContext(env: Env = process.env, read: (path: string) => string = (p) => readFileSync(p, 'utf8')): { context: PrContext | null; reason?: string } {
  if (env.GITHUB_ACTIONS === 'true') {
    let pr: { number?: number; head?: { sha?: string } } | undefined;
    try {
      pr = (JSON.parse(read(env.GITHUB_EVENT_PATH ?? '')) as { pull_request?: typeof pr }).pull_request;
    } catch {
      return { context: null };
    }
    if (!pr?.number) return { context: null };
    const token = env.GITHUB_TOKEN || env.GH_TOKEN;
    if (!token) return { context: null, reason: 'Set GITHUB_TOKEN to post a pull-request comment.' };
    const repo = env.GITHUB_REPOSITORY ?? '';
    const server = env.GITHUB_SERVER_URL ?? 'https://github.com';
    const sha = pr.head?.sha ?? env.GITHUB_SHA;
    return {
      context: {
        kind: 'github', api: env.GITHUB_API_URL ?? 'https://api.github.com', project: repo, number: String(pr.number), token,
        blob: (path, line) => (sha ? `${server}/${repo}/blob/${sha}/${encodePath(path)}${anchor(line)}` : null),
      },
    };
  }
  if (env.GITLAB_CI === 'true') {
    if (!env.CI_MERGE_REQUEST_IID) return { context: null };
    // CI_JOB_TOKEN can't post comments, so this has to be a project or personal access token.
    const token = env.FORTIS_GITLAB_TOKEN || env.GITLAB_TOKEN;
    if (!token) return { context: null, reason: 'Set FORTIS_GITLAB_TOKEN to a token with the api scope to post a merge-request comment.' };
    const url = env.CI_PROJECT_URL;
    const sha = env.CI_COMMIT_SHA;
    return {
      context: {
        kind: 'gitlab', api: env.CI_API_V4_URL ?? 'https://gitlab.com/api/v4', project: env.CI_PROJECT_ID ?? '', number: env.CI_MERGE_REQUEST_IID, token,
        blob: (path, line) => (url && sha ? `${url}/-/blob/${sha}/${encodePath(path)}${anchor(line)}` : null),
      },
    };
  }
  return { context: null };
}

/** The line numbers a unified diff adds, in the new version of the file. */
export function addedLines(patch: string): Set<number> {
  const added = new Set<number>();
  let line = 0;
  for (const text of patch.split('\n')) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
    if (hunk) line = Number(hunk[1]);
    else if (text.startsWith('+') && !text.startsWith('+++')) added.add(line++);
    else if (text.startsWith(' ')) line++;
  }
  return added;
}

/** What a pull request changes: file → added lines, or null when the whole file counts. */
export type Changed = { files: Map<string, Set<number> | null>; complete: boolean };

/** Findings the pull request adds. History findings aren't in its diff. */
export function newFindings(detections: Detection[], changed: Changed): Detection[] {
  return detections.filter((d) => {
    if (d.commit) return false;
    // Too big for the API to list in full: better a longer comment than a hidden finding.
    if (!changed.complete && !changed.files.has(d.file)) return true;
    if (!changed.files.has(d.file)) return false;
    const lines = changed.files.get(d.file)!;
    return !d.line || lines === null || lines.has(d.line);
  });
}

/** Scanned text in a table cell: it can't break the table, inject HTML or mention anyone. */
const cell = (s: string) => maskText(s).replace(/\s+/g, ' ').replace(/([\\`*_[\]<>|@])/g, '\\$1').slice(0, 300);

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function commentBody(findings: Detection[], ctx: Pick<PrContext, 'kind' | 'blob'>): string {
  const noun = ctx.kind === 'github' ? 'pull request' : 'merge request';
  if (!findings.length) return `${COMMENT_MARKER}\n### Fortis: no new findings\n\nThis ${noun} adds no security findings.\n`;
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const rows = sorted.slice(0, MAX_ROWS).map((d) => {
    const label = cell(d.line ? `${d.file}:${d.line}` : d.file);
    const url = ctx.blob(d.file, d.line);
    return `| ${d.severity} | ${cell(d.ruleId)} | ${url ? `[${label}](${url})` : label} | ${cell(d.title)} |`;
  });
  const more = sorted.length > MAX_ROWS ? `\n\nAnd ${sorted.length - MAX_ROWS} more. See the CI log for the full list.` : '';
  return `${COMMENT_MARKER}\n### Fortis: ${findings.length} new finding${findings.length === 1 ? '' : 's'} in this ${noun}\n\n| Severity | Rule | Where | Finding |\n|---|---|---|---|\n${rows.join('\n')}${more}\n\nRun \`fortis explain <rule>\` for why it matters and how to fix it.\n`;
}

type Fetch = typeof fetch;

function client(ctx: PrContext, fetchImpl: Fetch) {
  const headers: Record<string, string> =
    ctx.kind === 'github'
      ? { authorization: `Bearer ${ctx.token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'fortis-cli' }
      : { 'private-token': ctx.token, accept: 'application/json', 'user-agent': 'fortis-cli' };
  return async <T>(method: string, path: string, body?: object): Promise<T> => {
    const res = await fetchImpl(`${ctx.api}${path}`, {
      method,
      headers: { ...headers, ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'error',
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) throw new Error(`the token can't do this (HTTP ${res.status}). A pull request from a fork gets a read-only token.`);
      throw new Error(`HTTP ${res.status} from ${path.split('?')[0]}`);
    }
    return (await res.json()) as T;
  };
}

export async function postPrComment(ctx: PrContext, detections: Detection[], fetchImpl: Fetch = fetch): Promise<{ action: 'created' | 'updated' | 'none'; newCount: number }> {
  const call = client(ctx, fetchImpl);
  const base = ctx.kind === 'github' ? `/repos/${ctx.project}` : `/projects/${encodeURIComponent(ctx.project)}`;
  const pages = async <T>(path: string): Promise<{ items: T[]; complete: boolean }> => {
    const items: T[] = [];
    for (let page = 1; page <= MAX_PAGES; page++) {
      const batch = await call<T[]>('GET', `${path}?per_page=100&page=${page}`);
      items.push(...batch);
      if (batch.length < 100) return { items, complete: true };
    }
    return { items, complete: false };
  };

  const files = new Map<string, Set<number> | null>();
  let complete: boolean;
  if (ctx.kind === 'github') {
    const got = await pages<{ filename: string; status?: string; patch?: string }>(`${base}/pulls/${ctx.number}/files`);
    complete = got.complete;
    for (const f of got.items) if (f.status !== 'removed') files.set(f.filename, f.patch ? addedLines(f.patch) : null);
  } else {
    const got = await pages<{ new_path: string; deleted_file?: boolean; diff?: string; collapsed?: boolean; too_large?: boolean }>(`${base}/merge_requests/${ctx.number}/diffs`);
    complete = got.complete;
    for (const f of got.items) if (!f.deleted_file) files.set(f.new_path, f.diff && !f.collapsed && !f.too_large ? addedLines(f.diff) : null);
  }
  const fresh = newFindings(detections, { files, complete });

  const commentsPath = ctx.kind === 'github' ? `${base}/issues/${ctx.number}/comments` : `${base}/merge_requests/${ctx.number}/notes`;
  const { items: comments } = await pages<{ id: number; body?: string }>(commentsPath);
  const existing = comments.filter((c) => c.body?.startsWith(COMMENT_MARKER)).at(-1);
  // A pull request with nothing to report stays quiet, unless it needs an earlier comment corrected.
  if (!fresh.length && !existing) return { action: 'none', newCount: 0 };

  const body = commentBody(fresh, ctx);
  if (existing) {
    if (existing.body === body) return { action: 'none', newCount: fresh.length };
    if (ctx.kind === 'github') await call('PATCH', `${base}/issues/comments/${existing.id}`, { body });
    else await call('PUT', `${commentsPath}/${existing.id}`, { body });
    return { action: 'updated', newCount: fresh.length };
  }
  await call('POST', commentsPath, { body });
  return { action: 'created', newCount: fresh.length };
}
