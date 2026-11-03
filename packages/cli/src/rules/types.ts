import type { RulePack, Severity } from '@fortis/shared';

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
};

export type FileRule = {
  id: string;
  pack: RulePack;
  /** Only run on files whose path matches. */
  appliesTo: RegExp;
  run: (file: SourceFile) => Detection[];
};

export const JS_TS = /\.(c|m)?(j|t)sx?$/i;
const IGNORE_LINE = /fortis-ignore(?!-next-line)/;
const IGNORE_NEXT = /fortis-ignore-next-line/;

/** Honour `// fortis-ignore` on the line or `// fortis-ignore-next-line` on the line above. */
export function isIgnored(file: SourceFile, line: number): boolean {
  const here = file.lines[line - 1] ?? '';
  const above = file.lines[line - 2] ?? '';
  return IGNORE_LINE.test(here) || IGNORE_NEXT.test(above);
}

export function lineOf(text: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}
