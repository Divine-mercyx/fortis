import type { SourceFile } from './types';

/*
 * Reading Python without a parser, so the CLI stays one dependency-free file. Rules work on
 * whole functions, which Python's indentation makes easy to find.
 */

export const PYTHON = /\.py$/i;

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

export type PyFunction = {
  name: string;
  /** Parameter names, without `self` and `cls`. */
  params: string[];
  /** The whole signature, which may hold `Depends(...)`. */
  signature: string;
  decorators: { line: number; text: string }[];
  className?: string;
  classBases?: string;
  /** Lines of the `def`. */
  line: number;
  /** First line of the body, after the signature. */
  bodyLine: number;
  /** Last line of the body. */
  endLine: number;
  /** The body's text, without the signature. */
  body: string;
};

export type PyClass = { name: string; bases: string; line: number; endLine: number; body: string };

const indentOf = (s: string) => s.length - s.trimStart().length;
const isBlank = (s: string) => {
  const t = s.trim();
  return !t || t.startsWith('#');
};

/** The last line (1-based) of the block opened at `line`, at or below which the indent is deeper than `indent`. */
function blockEnd(file: SourceFile, from: number, indent: number): number {
  let end = from - 1;
  for (let i = from - 1; i < file.lines.length; i++) {
    const l = file.lines[i]!;
    if (isBlank(l)) continue;
    if (indentOf(l) <= indent) break;
    end = i + 1;
  }
  return end;
}

function paramNames(signature: string): string[] {
  const open = signature.indexOf('(');
  if (open === -1) return [];
  let depth = 0;
  let current = '';
  const parts: string[] = [];
  for (const ch of pyCodeOnly(signature.slice(open + 1))) {
    if ('([{'.includes(ch)) depth++;
    if (')]}'.includes(ch)) {
      if (depth === 0) break;
      depth--;
    }
    if (ch === ',' && depth === 0) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts
    .map((p) => /^\s*\*{0,2}(\w+)/.exec(p)?.[1])
    .filter((n): n is string => Boolean(n) && n !== 'self' && n !== 'cls');
}

/** Every function in a file, with its decorators and the class it sits in. */
export function pyFunctions(file: SourceFile): PyFunction[] {
  const out: PyFunction[] = [];
  const classes: { name: string; bases: string; indent: number }[] = [];
  let pending: { line: number; text: string }[] = [];
  for (let i = 0; i < file.lines.length; i++) {
    const l = file.lines[i]!;
    if (isBlank(l)) continue;
    const indent = indentOf(l);
    while (classes.length && indent <= classes[classes.length - 1]!.indent) classes.pop();
    const t = l.trim();
    if (t.startsWith('@')) {
      const stmt = pyStatementAt(file, i + 1);
      pending.push({ line: i + 1, text: stmt });
      i += stmt.trimEnd().split('\n').length - 1;
      continue;
    }
    const cls = /^class\s+(\w+)\s*(?:\(([^)]*)\))?/.exec(t);
    if (cls) {
      classes.push({ name: cls[1]!, bases: cls[2] ?? '', indent });
      pending = [];
      continue;
    }
    const def = /^(?:async\s+)?def\s+(\w+)\s*\(/.exec(t);
    if (def) {
      const signature = pyStatementAt(file, i + 1);
      const signatureEnd = i + signature.trimEnd().split('\n').length;
      const owner = classes[classes.length - 1];
      const endLine = blockEnd(file, signatureEnd + 1, indent);
      out.push({
        name: def[1]!,
        params: paramNames(signature),
        signature,
        decorators: pending,
        className: owner?.name,
        classBases: owner?.bases,
        line: i + 1,
        bodyLine: signatureEnd + 1,
        endLine: Math.max(endLine, signatureEnd),
        body: file.lines.slice(signatureEnd, Math.max(endLine, signatureEnd)).join('\n'),
      });
    }
    pending = [];
  }
  return out;
}

export function pyClasses(file: SourceFile): PyClass[] {
  const out: PyClass[] = [];
  file.lines.forEach((l, i) => {
    const m = /^(\s*)class\s+(\w+)\s*(?:\(([^)]*)\))?\s*:/.exec(l);
    if (!m) return;
    const endLine = blockEnd(file, i + 2, m[1]!.length);
    out.push({ name: m[2]!, bases: m[3] ?? '', line: i + 1, endLine: Math.max(endLine, i + 1), body: file.lines.slice(i + 1, Math.max(endLine, i + 1)).join('\n') });
  });
  return out;
}

const ROUTE_DECORATOR = /^\s*@[\w.]+\.(route|get|post|put|patch|delete|api_route|websocket)\s*\(|^\s*@(api_view|action|require_POST|require_GET|require_http_methods|csrf_exempt)\b/;
const VIEW_METHOD = /^(get|post|put|patch|delete|retrieve|update|partial_update|destroy|list|create)$/;

/** A function that answers a web request: routed by a decorator, a Django view, or a method on a view class. */
export function isRequestHandler(fn: PyFunction): boolean {
  if (fn.decorators.some((d) => ROUTE_DECORATOR.test(d.text))) return true;
  if (fn.className) return VIEW_METHOD.test(fn.name) && /View|ViewSet|Mixin/.test(`${fn.classBases ?? ''} ${fn.className}`);
  return fn.params[0] === 'request';
}

/** The URL a function is routed at, if a decorator says so. */
export function routePath(fn: PyFunction): string {
  for (const d of fn.decorators) {
    const m = /^\s*@[\w.]+\.(?:route|get|post|put|patch|delete|api_route)\s*\(\s*f?["']([^"']*)["']/.exec(d.text);
    if (m) return m[1]!;
  }
  return '';
}

/** Whether the function answers a request that can change data. */
export function acceptsWrites(fn: PyFunction): boolean {
  const decorators = fn.decorators.map((d) => d.text).join('\n');
  if (/^\s*@[\w.]+\.(post|put|patch)\s*\(/m.test(decorators)) return true;
  if (/^\s*@[\w.]+\.(?:route|api_route)\s*\([\s\S]*methods\s*=[^)]*["'](POST|PUT|PATCH)["']/im.test(decorators)) return true;
  if (/^\s*@require_POST\b/m.test(decorators)) return true;
  if (/^\s*@(?:api_view|require_http_methods)\s*\([^)]*["'](POST|PUT|PATCH)["']/im.test(decorators)) return true;
  if (/^\s*@action\s*\([^)]*methods\s*=[^)]*["'](post|put|patch)["']/im.test(decorators)) return true;
  if (fn.className && /^(post|put|patch|create|update|partial_update)$/.test(fn.name)) return true;
  return /request\.method\s*(==|in)\s*[\[(]?\s*["'](POST|PUT|PATCH)["']/.test(fn.body);
}
