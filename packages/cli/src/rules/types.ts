import type { RulePack, Severity } from '@fortis/shared';

import type { Project } from '../analysis/project';

export type SourceFile = { path: string; text: string; lines: string[] };

export type Detection = {
  ruleId: string;
  severity: Severity;
  title: string;
  file: string;
  /** 1-based line number. */
  line: number;
  /** The offending line, before masking. Masked before printing or upload. */
  snippet: string;
  /** For git-history findings: the commit that introduced it. */
  commit?: string;
  /** How to fix this finding, when it is more specific than the rule's general advice. */
  fix?: string;
  /** Dependency findings: the version that clears every advisory, or null when there is no fix yet. */
  fixedVersion?: string | null;
  /** Secret findings, with --verify: whether the key still works, from one read-only call to its provider. */
  secretStatus?: 'live' | 'revoked' | 'unknown';
};

/** Facts gathered from the whole repository, so a rule can see protection defined in another file. */
export type ProjectContext = {
  /** Names of functions/middleware defined in files that implement idempotency keys. */
  idempotencyHelpers: Set<string>;
  /** The repository's other files, for following calls into them. Without it, calls stop at the file. */
  project?: Project;
  /** A rate limiter guards the whole app (app.use(limiter), DEFAULT_THROTTLE_CLASSES, ...). */
  rateLimitAll?: boolean;
};

export const emptyContext = (): ProjectContext => ({ idempotencyHelpers: new Set() });

/** Test code, fixtures, mocks and generated migrations: fintech checks skip these (secret checks still run). */
const TEST_PATTERN = /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|fixtures?|mocks?|migrations)\/|\.(test|spec|mock|mocks|fixture|stories)\.[cm]?[jt]sx?$|(^|\/)(test_[^/]*|[^/]*_test|conftest)\.py$|_test\.go$|(^|\/)testdata\/|(^|\/)[^/]*\.(Tests?|Specs?|IntegrationTests?|UnitTests?)\/|(^|\/)[\w-]*integration-?tests?\//i;
/** WalletTests.cs and WalletTest.java are tests and Contest.cs isn't, so these parts have to match case. */
const CSHARP_TEST_FILE = /[a-z0-9](?:Tests?|Spec)\.cs$/;
const JVM_TEST_FILE = /[a-z0-9](?:Test|Tests|Spec|IT)\.(?:java|kt)$/;
export const TEST_PATH = { test: (path: string) => TEST_PATTERN.test(path) || CSHARP_TEST_FILE.test(path) || JVM_TEST_FILE.test(path) };

export type FileRule = {
  id: string;
  pack: RulePack;
  /** Only run on files whose path matches. */
  appliesTo: RegExp;
  /** Skip test files, fixtures and mocks. */
  skipTests?: boolean;
  run: (file: SourceFile, ctx: ProjectContext) => Detection[];
};

export const JS_TS = /\.(c|m)?(j|t)sx?$/i;
export const PYTHON = /\.py$/i;
const IGNORE_LINE = /fortis-ignore(?!-next-line)/;
const IGNORE_NEXT = /fortis-ignore-next-line/;

/** Honour `// fortis-ignore` on the line or `// fortis-ignore-next-line` on the line above. */
export function isIgnored(file: SourceFile, line: number): boolean {
  const here = file.lines[line - 1] ?? '';
  const above = file.lines[line - 2] ?? '';
  return IGNORE_LINE.test(here) || IGNORE_NEXT.test(above);
}

/**
 * The code of a statement with the text inside string literals blanked out, but template
 * interpolations kept. "BVN must be 11 digits" becomes "", while `BVN ${bvn}` keeps "bvn".
 */
export function codeOnly(text: string): string {
  let out = '';
  let quote: string | null = null;
  let depth = 0; // ${ … } nesting inside a template literal
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === '\\') { i++; continue; }
      if (quote === '`' && ch === '$' && text[i + 1] === '{') { depth++; i++; out += ' '; continue; }
      if (depth > 0) {
        if (ch === '}') { depth--; out += ' '; continue; }
        out += ch;
        continue;
      }
      if (ch === quote) { quote = null; out += ' '; }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; out += ' '; continue; }
    // Comments end at the line break (or */), not at the end of a multi-line statement.
    if (ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i);
      if (nl === -1) break;
      i = nl;
      out += '\n';
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end === -1) break;
      i = end + 1;
      out += ' ';
      continue;
    }
    out += ch;
  }
  return out;
}

/** The full call starting on `line` (1-based), following open brackets for up to 20 lines. */
export function statementAt(file: SourceFile, line: number): string {
  let text = '';
  let balance = 0;
  for (let i = line - 1; i < Math.min(file.lines.length, line + 19); i++) {
    const l = file.lines[i]!;
    text += `${l}\n`;
    for (const ch of codeOnly(l)) {
      if (ch === '(' || ch === '{' || ch === '[') balance++;
      else if (ch === ')' || ch === '}' || ch === ']') balance--;
    }
    if (balance <= 0) break;
  }
  return text;
}

export function lineOf(text: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}
