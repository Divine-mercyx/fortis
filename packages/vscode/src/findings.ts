import { realpathSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';

import { findRule, fixFor, type Severity } from '@fortis/shared';

/*
 * Turns `fortis scan --json` output into what the editor shows. Nothing here imports vscode, so it
 * can be tested on its own. Only what the CLI prints is used, and its snippets are already masked.
 */

export type Finding = {
  ruleId: string;
  severity: Severity;
  title: string;
  file: string;
  line: number;
  snippet?: string;
  fix?: string;
  fixedVersion?: string | null;
  /** Accepted in the project's baseline, so it isn't shown. */
  baseline?: boolean;
};

export type ScanOutput = { root: string; detections: Finding[]; notes: string[]; filesScanned?: number };

export function parseScanOutput(stdout: string): ScanOutput {
  const out = JSON.parse(stdout) as Partial<ScanOutput>;
  if (typeof out.root !== 'string' || !Array.isArray(out.detections)) throw new Error('The CLI gave an unexpected answer. Check that it is up to date.');
  return { root: out.root, detections: out.detections, notes: out.notes ?? [], filesScanned: out.filesScanned };
}

const real = (path: string) => {
  try {
    return realpathSync.native(path);
  } catch {
    return path;
  }
};

/**
 * The path of a finding as the editor knows it. The CLI reports paths from the git root with symlinks
 * resolved, while the editor may have opened a subfolder, or a path through a symlink like /tmp on a Mac.
 */
export function editorPath(folder: string, root: string, file: string): string {
  const rel = relative(real(folder), real(join(root, file)));
  return !rel || rel.startsWith('..') || isAbsolute(rel) ? join(root, file) : join(folder, rel);
}

/** The zero-based line to mark. A dependency finding can have no line, so it goes on the first. */
export const lineIndex = (f: Pick<Finding, 'line'>) => Math.max(0, f.line - 1);

/** "<Rule ID>: <title>" is all a problem shows, so the masked line never needs repeating there. */
export const problemMessage = (f: Finding) => f.title;

/** The same text as `fortis explain`, and the advice for this one finding when it has its own. */
export function hoverText(f: Finding): string {
  const rule = findRule(f.ruleId);
  const parts = [`**${f.ruleId}** · ${f.severity}: ${f.title}`];
  if (rule) {
    parts.push(`**Why it matters**\n\n${rule.summary}`);
    if (!f.fix) parts.push(`**How to fix it**\n\n${fixFor(rule, f.file)}`);
  }
  if (f.fix) parts.push(`**How to fix it**\n\n${f.fix}`);
  return parts.join('\n\n');
}

/** The first install command in a dependency finding's advice. */
export function upgradeCommand(f: Pick<Finding, 'fix'>): string | null {
  const fix = f.fix ?? '';
  const direct = /^Upgrade to [^:]+: (.+?)\.(?:\s|$)/.exec(fix);
  if (direct) return direct[1]!;
  const partial = /Upgrading to \S+ \((.+?)\) clears/.exec(fix);
  return partial ? partial[1]! : null;
}

/** The advisory behind a dependency finding, from its snippet: "axios@0.21.1 · CVE-2021-3749". */
export function advisoryUrl(f: Finding): string | null {
  if (f.ruleId !== 'DEP-OSV') return null;
  const id = f.snippet?.split(' · ')[1]?.trim();
  return id && /^[A-Za-z0-9._:-]+$/.test(id) ? `https://osv.dev/vulnerability/${encodeURIComponent(id)}` : null;
}

const HASH = new Set(['python', 'ruby', 'shellscript', 'yaml', 'dockerfile', 'makefile', 'perl', 'r', 'toml', 'properties', 'dotenv', 'powershell', 'terraform', 'ini', 'elixir', 'plaintext']);
const DASH = new Set(['sql', 'lua', 'haskell']);
const MARKUP = new Set(['html', 'xml', 'markdown', 'vue-html']);
const BLOCK = new Set(['css', 'scss', 'less']);

/**
 * The comment that silences a finding on the line below, in this language, or null where a file
 * can't hold one (JSON) or the finding isn't about a line of code (a lockfile).
 */
export function ignoreComment(f: Pick<Finding, 'ruleId'>, languageId: string, indent: string, reason: string): string | null {
  if (f.ruleId === 'DEP-OSV' || languageId === 'json') return null;
  const why = reason.replace(/\*\/|-->/g, '').replace(/\s+/g, ' ').trim();
  const text = `fortis-ignore-next-line${why ? `: ${why}` : ''}`;
  if (HASH.has(languageId)) return `${indent}# ${text}`;
  if (DASH.has(languageId)) return `${indent}-- ${text}`;
  if (MARKUP.has(languageId)) return `${indent}<!-- ${text} -->`;
  if (BLOCK.has(languageId)) return `${indent}/* ${text} */`;
  return `${indent}// ${text}`;
}
