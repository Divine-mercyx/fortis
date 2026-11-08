import type { SourceFile } from './types';

/*
 * Line-level helpers for Python. The fintech rules read Python as syntax trees now (see
 * analysis/python.ts); these are for checks that only need a statement's text.
 */

export { PYTHON } from './types';

/**
 * Python code with the text inside strings blanked out and comments removed, but f-string
 * values kept. "BVN must be 11 digits" becomes blank, while f"BVN {user.bvn}" keeps user.bvn.
 */
export function pyCodeOnly(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '#') {
      const nl = text.indexOf('\n', i);
      if (nl === -1) break;
      i = nl;
      continue;
    }
    if (ch !== '"' && ch !== "'") {
      out += ch;
      i++;
      continue;
    }
    const isF = /(^|\W)(?:[fF][rR]?|[rR][fF])$/.test(text.slice(Math.max(0, i - 3), i));
    const triple = text.startsWith(ch.repeat(3), i);
    const quote = triple ? ch.repeat(3) : ch;
    i += quote.length;
    out += ' ';
    while (i < text.length && !text.startsWith(quote, i)) {
      const c = text[i]!;
      if (c === '\\') {
        i += 2;
      } else if (c === '\n') {
        if (!triple) break; // an unterminated string: stop at the line end
        out += '\n';
        i++;
      } else if (isF && c === '{') {
        if (text[i + 1] === '{') {
          i += 2;
          continue;
        }
        let depth = 1;
        out += ' ';
        i++;
        while (i < text.length && depth > 0) {
          if (text[i] === '{') depth++;
          else if (text[i] === '}') depth--;
          if (depth > 0) out += text[i];
          i++;
        }
        out += ' ';
      } else {
        i++;
      }
    }
    if (text.startsWith(quote, i)) i += quote.length;
    out += ' ';
  }
  return out;
}

/** The full statement starting on `line` (1-based), following open brackets for up to 30 lines. */
export function pyStatementAt(file: SourceFile, line: number): string {
  let text = '';
  let balance = 0;
  for (let i = line - 1; i < Math.min(file.lines.length, line + 29); i++) {
    const l = file.lines[i]!;
    text += `${l}\n`;
    for (const ch of pyCodeOnly(l)) {
      if (ch === '(' || ch === '{' || ch === '[') balance++;
      else if (ch === ')' || ch === '}' || ch === ']') balance--;
    }
    if (balance <= 0 && !l.trimEnd().endsWith('\\')) break;
  }
  return text;
}
