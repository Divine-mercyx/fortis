import type { SourceFile } from '../rules/types';

import { parse, type Ast, type Language } from './parser';
import type { Project } from './project';

/*
 * Following calls in Go, C#, PHP, Java and Kotlin (#91), so the account-takeover checks see a rate limiter, lockout
 * or expiry check that sits in a service class in another file, as they already do for JavaScript and Python.
 *
 * Each file becomes a small model: its types (classes, structs, interfaces) with their fields and methods, and each
 * method's calls. A call is resolved through what the code says about the name it's called on: the method's own
 * class (this, $this, self, a Go receiver), a field or constructor parameter with a declared type, a parameter, or a
 * type called statically. An interface or base class leads to its implementations. Anything cleverer counts as not
 * resolved, so the checks fall back to what they could already see. Go, C#, PHP and Java are read with Tree-sitter;
 * Kotlin, which has no grammar here, with a reader of its declarations and braces.
 */

export type OtherLang = 'go' | 'csharp' | 'java' | 'php' | 'kotlin';
const LANG_OF: [RegExp, OtherLang][] = [[/\.go$/i, 'go'], [/\.cs$/i, 'csharp'], [/\.php$/i, 'php'], [/\.java$/i, 'java'], [/\.kts?$/i, 'kotlin']];
export const otherLangOf = (path: string): OtherLang | null => LANG_OF.find(([re]) => re.test(path))?.[1] ?? null;
/** The grammar each language is parsed with; Kotlin has none. */
export const GRAMMAR_OF: Record<OtherLang, Language | null> = { go: 'go', csharp: 'csharp', java: 'java', php: 'php', kotlin: null };

export type Call = { chain: string[]; line: number };
export type Method = { name: string; owner: string | null; file: string; line: number; endLine: number; text: string; params: Map<string, string>; receiver?: string; calls: Call[] };
export type TypeModel = { name: string; file: string; supers: string[]; fields: Map<string, string>; methods: Method[]; isInterface: boolean };
export type FileModel = { types: TypeModel[]; functions: Method[] };

/** `*pkg.Repo[T]`, `IList<Foo>?`, `\App\Services\Otp` → the bare type name. */
export function typeName(raw: string): string {
  const t = raw.replace(/<[\s\S]*>|\[[^\]]*\]/g, '').replace(/[*?&!]/g, '').trim();
  return t.split(/[.\\]/).pop()!.trim();
}

const SELF = new Set(['this', '$this', 'self', 'static', 'base', 'super', 'parent']);
const KEYWORDS = new Set(['if', 'for', 'while', 'when', 'switch', 'catch', 'return', 'new', 'throw', 'super', 'this', 'fun', 'listOf', 'mapOf', 'setOf', 'println', 'require', 'check']);

/* ------------------------------------------------- Tree-sitter models */

const childOf = (n: Ast, field: string) => n.children.find((c) => c.field === field);
const textOf = (src: string, n: Ast | undefined) => (n ? src.slice(n.start, n.end) : '');
function descendants(n: Ast, types: Set<string>, out: Ast[] = [], stopAt?: Set<string>): Ast[] {
  for (const c of n.children) {
    if (types.has(c.type)) out.push(c);
    if (!stopAt?.has(c.type)) descendants(c, types, out, stopAt);
  }
  return out;
}
/** A call's callee as a chain: `this.otp.verify` → [this, otp, verify]; `$this->otp->verify` → [$this, otp, verify]. */
const chainOf = (callee: string) => callee.replace(/\s+/g, '').replace(/\?\.|->|::|\?->/g, '.').split('.').filter(Boolean);

const TYPE_NODES: Record<Exclude<OtherLang, 'kotlin' | 'go'>, Set<string>> = {
  java: new Set(['class_declaration', 'interface_declaration', 'enum_declaration', 'record_declaration']),
  csharp: new Set(['class_declaration', 'interface_declaration', 'record_declaration', 'struct_declaration']),
  php: new Set(['class_declaration', 'interface_declaration', 'trait_declaration', 'enum_declaration']),
};
const CALL_NODES: Record<Exclude<OtherLang, 'kotlin'>, Set<string>> = {
  java: new Set(['method_invocation']),
  csharp: new Set(['invocation_expression']),
  php: new Set(['member_call_expression', 'nullsafe_member_call_expression', 'scoped_call_expression', 'function_call_expression']),
  go: new Set(['call_expression']),
};

function callsIn(lang: Exclude<OtherLang, 'kotlin'>, src: string, body: Ast | undefined): Call[] {
  if (!body) return [];
  const out: Call[] = [];
  for (const c of descendants(body, CALL_NODES[lang])) {
    let callee = '';
    if (lang === 'java') callee = `${textOf(src, childOf(c, 'object'))}.${textOf(src, childOf(c, 'name'))}`;
    else if (lang === 'php') {
      const obj = childOf(c, 'object') ?? childOf(c, 'scope');
      callee = obj ? `${textOf(src, obj)}.${textOf(src, childOf(c, 'name'))}` : textOf(src, childOf(c, 'function'));
    } else callee = textOf(src, childOf(c, 'function'));
    const chain = chainOf(callee);
    if (chain.length && !/[()[\]"'{}]/.test(chain.join(''))) out.push({ chain, line: c.line });
  }
  return out;
}

/** Parameters as name → type, for Java, C# and PHP parameter lists. */
function paramsOf(src: string, list: Ast | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const p of list?.children ?? []) {
    const name = textOf(src, childOf(p, 'name')).replace(/^\$/, '');
    const type = childOf(p, 'type');
    if (name && type) out.set(name, typeName(textOf(src, type)));
  }
  return out;
}

function classModels(lang: 'java' | 'csharp' | 'php', file: SourceFile, root: Ast): FileModel {
  const src = file.text;
  const types: TypeModel[] = [];
  for (const cls of descendants(root, TYPE_NODES[lang])) {
    const name = textOf(src, childOf(cls, 'name'));
    if (!name) continue;
    const supers: string[] = [];
    for (const c of cls.children) {
      if (/^(?:superclass|interfaces|base_list|base_clause|class_interface_clause|super_interfaces|extends_interfaces)$/.test(c.type) || c.field === 'superclass' || c.field === 'interfaces') {
        for (const m of textOf(src, c).replace(/<[^>]*>/g, '').matchAll(/[A-Za-z_\\][\w\\]*/g)) if (!/^(?:extends|implements)$/.test(m[0])) supers.push(typeName(m[0]));
      }
    }
    const t: TypeModel = { name, file: file.path, supers, fields: new Map(), methods: [], isInterface: cls.type === 'interface_declaration' };
    // C# primary constructors and Java records: their parameters are fields.
    for (const c of cls.children) if (c.type === 'parameter_list' || c.type === 'formal_parameters') for (const [k, v] of paramsOf(src, c)) t.fields.set(k, v);
    const body = childOf(cls, 'body');
    for (const m of body?.children ?? []) {
      if (m.type === 'field_declaration' || m.type === 'property_declaration') {
        const declType = childOf(m, 'type') ?? childOf(m.children.find((c) => c.type === 'variable_declaration') ?? m, 'type');
        if (!declType) continue;
        const holder = m.children.find((c) => c.type === 'variable_declaration') ?? m;
        const declared = descendants(holder, new Set(['variable_declarator', 'property_element'])).map((d) => textOf(src, childOf(d, 'name')).replace(/^\$/, ''));
        if (m.type === 'property_declaration' && lang === 'csharp') declared.push(textOf(src, childOf(m, 'name')));
        for (const d of declared) if (d) t.fields.set(d, typeName(textOf(src, declType)));
      } else if (m.type === 'constructor_declaration' || (m.type === 'method_declaration' && textOf(src, childOf(m, 'name')) === '__construct')) {
        const params = paramsOf(src, childOf(m, 'parameters'));
        // Injected through the constructor: `this.otp = otpService`, `_otp = otp`, `$this->otp = $otp`, or PHP's promoted parameters.
        for (const p of childOf(m, 'parameters')?.children ?? []) if (p.type === 'property_promotion_parameter') {
          const n = textOf(src, childOf(p, 'name')).replace(/^\$/, '');
          if (params.has(n)) t.fields.set(n, params.get(n)!);
        }
        for (const a of descendants(m, new Set(['assignment_expression']))) {
          const left = textOf(src, childOf(a, 'left')).replace(/^(?:this\.|\$this->)/, '');
          const right = textOf(src, childOf(a, 'right')).replace(/^\$/, '');
          if (/^\w+$/.test(left) && params.has(right)) t.fields.set(left, params.get(right)!);
        }
        for (const [k, v] of params) if (!t.fields.has(k)) t.fields.set(k, v);
      }
      if (m.type === 'method_declaration' || m.type === 'constructor_declaration') {
        const body2 = childOf(m, 'body');
        t.methods.push({
          name: textOf(src, childOf(m, 'name')),
          owner: name,
          file: file.path,
          line: m.line,
          endLine: m.endLine,
          text: textOf(src, m),
          params: paramsOf(src, childOf(m, 'parameters')),
          calls: callsIn(lang, src, body2),
        });
      }
    }
    types.push(t);
  }
  // PHP functions outside a class.
  const functions = lang === 'php' ? descendants(root, new Set(['function_definition']), [], TYPE_NODES.php).map((f) => ({ name: textOf(src, childOf(f, 'name')), owner: null, file: file.path, line: f.line, endLine: f.endLine, text: textOf(src, f), params: paramsOf(src, childOf(f, 'parameters')), calls: callsIn('php', src, childOf(f, 'body')) })) : [];
  return { types, functions };
}

function goModel(file: SourceFile, root: Ast): FileModel {
  const src = file.text;
  const types: TypeModel[] = [];
  for (const spec of descendants(root, new Set(['type_spec']))) {
    const name = textOf(src, childOf(spec, 'name'));
    const def = childOf(spec, 'type');
    if (!name || !def) continue;
    const t: TypeModel = { name, file: file.path, supers: [], fields: new Map(), methods: [], isInterface: def.type === 'interface_type' };
    for (const f of descendants(def, new Set(['field_declaration']))) {
      const type = childOf(f, 'type');
      const names = f.children.filter((c) => c.field === 'name').map((c) => textOf(src, c));
      if (!type) continue;
      if (names.length) for (const n of names) t.fields.set(n, typeName(textOf(src, type)));
      else t.supers.push(typeName(textOf(src, type))); // an embedded type
    }
    if (t.isInterface) for (const m of descendants(def, new Set(['method_spec', 'method_elem']))) t.methods.push({ name: textOf(src, childOf(m, 'name')), owner: name, file: file.path, line: m.line, endLine: m.endLine, text: textOf(src, m), params: new Map(), calls: [] });
    types.push(t);
  }
  const goParams = (list: Ast | undefined) => {
    const out = new Map<string, string>();
    for (const p of list?.children ?? []) {
      const type = childOf(p, 'type');
      for (const n of p.children.filter((c) => c.field === 'name')) if (type) out.set(textOf(src, n), typeName(textOf(src, type)));
    }
    return out;
  };
  const functions: Method[] = [];
  for (const fn of root.children.filter((c) => c.type === 'function_declaration' || c.type === 'method_declaration')) {
    const recv = childOf(fn, 'receiver')?.children[0];
    const owner = recv ? typeName(textOf(src, childOf(recv, 'type'))) : null;
    const m: Method = {
      name: textOf(src, childOf(fn, 'name')),
      owner,
      file: file.path,
      line: fn.line,
      endLine: fn.endLine,
      text: textOf(src, fn),
      params: goParams(childOf(fn, 'parameters')),
      ...(recv ? { receiver: textOf(src, childOf(recv, 'name')) } : {}),
      calls: callsIn('go', src, childOf(fn, 'body')),
    };
    const t = owner ? types.find((x) => x.name === owner) : undefined;
    if (t) t.methods.push(m);
    else if (owner) {
      // The struct is declared in another file of the package: keep the method on a stub, merged by name later.
      types.push({ name: owner, file: file.path, supers: [], fields: new Map(), methods: [m], isInterface: false });
    } else functions.push(m);
  }
  return { types, functions };
}

/* ------------------------------------------------- Kotlin, without a grammar */

/** The index of the bracket that closes the one at `open`, skipping strings. */
function closing(text: string, open: number, pair: '{}' | '()'): number {
  let depth = 0;
  let quote = '';
  for (let i = open; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '/' && text[i + 1] === '/') { const nl = text.indexOf('\n', i); i = nl < 0 ? text.length : nl; continue; }
    if (ch === pair[0]) depth++;
    else if (ch === pair[1] && --depth === 0) return i;
  }
  return text.length - 1;
}
const lineAt = (text: string, offset: number) => text.slice(0, offset).split('\n').length;
const kotlinParams = (list: string) => {
  const out = new Map<string, string>();
  for (const m of list.matchAll(/(?:^|[,(])\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:private|protected|internal|public|override|open|final)\s+)*(?:val\s+|var\s+)?(\w+)\s*:\s*([\w.<>?, ]+?)(?=\s*(?:=|,|\)|$))/g)) out.set(m[1]!, typeName(m[2]!));
  return out;
};

function kotlinModel(file: SourceFile): FileModel {
  const text = file.text;
  const types: TypeModel[] = [];
  const functions: Method[] = [];
  const decl = /\b(class|interface|object)\s+(\w+)/g;
  const spans: { t: TypeModel; start: number; end: number }[] = [];
  for (const m of text.matchAll(decl)) {
    if (/\bfun\s*$|\.\s*$/.test(text.slice(Math.max(0, m.index! - 6), m.index))) continue;
    let i = m.index! + m[0].length;
    const t: TypeModel = { name: m[2]!, file: file.path, supers: [], fields: new Map(), methods: [], isInterface: m[1] === 'interface' };
    const ctor = /^\s*(?:(?:private|protected|internal|public)\s+)?(?:@\w+\s*)*(?:constructor\s*)?\(/.exec(text.slice(i));
    if (ctor) {
      const open = i + ctor[0].length - 1;
      const close = closing(text, open, '()');
      for (const [k, v] of kotlinParams(text.slice(open + 1, close))) t.fields.set(k, v);
      i = close + 1;
    }
    const head = /^\s*(?::\s*([^{=\n]+))?\s*\{/.exec(text.slice(i));
    if (head?.[1]) for (const s of head[1].split(',')) t.supers.push(typeName(s.replace(/\(.*$/, '')));
    const open = head ? i + head[0].length - 1 : -1;
    const end = open >= 0 ? closing(text, open, '{}') : i;
    if (open >= 0) {
      // Properties at the class's own level.
      const body = text.slice(open + 1, end);
      let depth = 0;
      for (const line of body.split('\n')) {
        if (depth === 0) {
          const p = /^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:private|protected|internal|public|override|open|final|lateinit|const)\s+)*(?:val|var)\s+(\w+)\s*:\s*([\w.<>?]+)/.exec(line);
          if (p) t.fields.set(p[1]!, typeName(p[2]!));
        }
        depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
      }
    }
    types.push(t);
    spans.push({ t, start: m.index!, end });
  }
  for (const m of text.matchAll(/\bfun\s+(?:<[^>]+>\s*)?(?:[\w.]+\.)?(\w+)\s*\(/g)) {
    const pOpen = m.index! + m[0].length - 1;
    const pClose = closing(text, pOpen, '()');
    const rest = text.slice(pClose + 1);
    const bodyAt = /^[^{=\n]*([{=])/.exec(rest);
    let end = pClose;
    if (bodyAt?.[1] === '{') end = closing(text, pClose + 1 + bodyAt.index + bodyAt[0].length - 1, '{}');
    else if (bodyAt?.[1] === '=') { const nl = text.indexOf('\n', pClose); end = nl < 0 ? text.length : nl; }
    const owner = spans.filter((s) => m.index! > s.start && m.index! < s.end).sort((a, b) => b.start - a.start)[0]?.t ?? null;
    const body = text.slice(pClose + 1, end + 1);
    const calls: Call[] = [];
    for (const c of body.matchAll(/([A-Za-z_]\w*(?:\s*\??\.\s*[A-Za-z_]\w*)*)\s*\(/g)) {
      const chain = chainOf(c[1]!);
      if (!chain.length || KEYWORDS.has(chain[0]!) && chain.length === 1) continue;
      calls.push({ chain, line: lineAt(text, pClose + 1 + c.index!) });
    }
    const method: Method = { name: m[1]!, owner: owner?.name ?? null, file: file.path, line: lineAt(text, m.index!), endLine: lineAt(text, end), text: text.slice(m.index!, end + 1), params: kotlinParams(text.slice(pOpen + 1, pClose)), calls };
    if (owner) owner.methods.push(method);
    else functions.push(method);
  }
  return { types, functions };
}

/* ------------------------------------------------- the project index */

type Index = { lang: OtherLang; files: Map<string, FileModel>; types: Map<string, TypeModel[]>; functions: Map<string, Method[]> };
const indexes = new WeakMap<Project, Map<OtherLang, Index>>();
/** Files read per language for the index, so a monorepo can't make one scan parse everything. */
const MAX_FILES = 4000;

/** The model of one file, or null when it can't be read or parsed. */
export function modelOf(file: SourceFile): FileModel | null {
  const lang = otherLangOf(file.path);
  if (!lang) return null;
  try {
    if (lang === 'kotlin') return kotlinModel(file);
    const root = parse(GRAMMAR_OF[lang]!, file.text).root;
    return lang === 'go' ? goModel(file, root) : classModels(lang, file, root);
  } catch {
    return null;
  }
}

function indexFor(project: Project, lang: OtherLang): Index {
  let byLang = indexes.get(project);
  if (!byLang) indexes.set(project, (byLang = new Map()));
  const cached = byLang.get(lang);
  if (cached) return cached;
  const index: Index = { lang, files: new Map(), types: new Map(), functions: new Map() };
  let read = 0;
  for (const path of project.paths) {
    if (otherLangOf(path) !== lang || read++ >= MAX_FILES) continue;
    const file = project.read(path);
    const model = file && modelOf(file);
    if (!model) continue;
    index.files.set(path, model);
    for (const t of model.types) {
      const list = index.types.get(t.name) ?? [];
      // Go spreads a type's methods over files: merge the parts of one type in one package (folder).
      const dir = path.slice(0, path.lastIndexOf('/') + 1);
      const same = lang === 'go' ? list.find((x) => x.file.slice(0, x.file.lastIndexOf('/') + 1) === dir) : undefined;
      if (same) {
        for (const [k, v] of t.fields) same.fields.set(k, v);
        same.supers.push(...t.supers);
        same.methods.push(...t.methods);
        same.isInterface ||= t.isInterface;
      } else {
        list.push(t);
        index.types.set(t.name, list);
      }
    }
    for (const f of model.functions) index.functions.set(f.name, [...(index.functions.get(f.name) ?? []), f]);
  }
  byLang.set(lang, index);
  return index;
}

/** A type's field, including those it inherits. */
function fieldType(index: Index, t: TypeModel, name: string, seen = new Set<string>()): string | undefined {
  if (seen.has(t.name)) return undefined;
  seen.add(t.name);
  if (t.fields.has(name)) return t.fields.get(name);
  for (const s of t.supers) for (const st of index.types.get(s) ?? []) {
    const found = fieldType(index, st, name, seen);
    if (found) return found;
  }
  return undefined;
}

/** A method on a type: its own, inherited, or, for an interface or abstract base, each implementation's. */
function methodsOn(index: Index, t: TypeModel, name: string): Method[] {
  const own = t.methods.filter((m) => m.name === name);
  const inherited = own.length ? [] : t.supers.flatMap((s) => (index.types.get(s) ?? []).flatMap((st) => st.methods.filter((m) => m.name === name)));
  const implementations: Method[] = [];
  const abstract = t.isInterface || own.every((m) => !/\{/.test(m.text.slice(m.text.indexOf(')'))));
  if (abstract) {
    for (const list of index.types.values()) for (const impl of list) {
      if (impl === t || impl.isInterface) continue;
      // Go satisfies interfaces implicitly: any type with the method counts.
      if (index.lang === 'go' ? t.isInterface : impl.supers.includes(t.name)) implementations.push(...impl.methods.filter((m) => m.name === name));
      if (implementations.length > 6) break;
    }
  }
  return [...own, ...inherited, ...implementations];
}

/**
 * The types with this name. An interface declared somewhere the scan doesn't read (a NuGet package, another module)
 * has no model, so the types that name it as a base stand in for it.
 */
function typesNamed(index: Index, name: string | undefined): TypeModel[] {
  if (!name) return [];
  const declared = index.types.get(name);
  if (declared?.length) return declared;
  const implementors: TypeModel[] = [];
  for (const list of index.types.values()) for (const t of list) if (t.supers.includes(name) && implementors.length < 6) implementors.push(t);
  return implementors;
}

/** What a call resolves to. */
function resolve(index: Index, from: Method, call: Call): Method[] {
  const method = call.chain[call.chain.length - 1]!;
  const recv = call.chain.slice(0, -1).map((s) => s.replace(/^\$/, ''));
  const owner = from.owner ? (index.types.get(from.owner) ?? []).find((t) => t.file === from.file) ?? index.types.get(from.owner)?.[0] : undefined;
  if (!recv.length) {
    if (owner) {
      const own = methodsOn(index, owner, method);
      if (own.length) return own;
    }
    // A top-level function: in the same file, then the same package or folder.
    const fns = index.functions.get(method) ?? [];
    const dir = from.file.slice(0, from.file.lastIndexOf('/') + 1);
    return fns.filter((f) => f.file === from.file).concat(fns.filter((f) => f.file !== from.file && f.file.startsWith(dir) && !f.file.slice(dir.length).includes('/')));
  }
  const first = recv[0]!;
  let types: TypeModel[];
  if (SELF.has(first) || first === from.receiver) types = owner ? [owner] : [];
  else if (from.params.has(first)) types = typesNamed(index, from.params.get(first));
  else if (owner && fieldType(index, owner, first)) types = typesNamed(index, fieldType(index, owner, first));
  else types = index.types.get(first) ?? [];
  for (const seg of recv.slice(1)) types = types.flatMap((t) => typesNamed(index, fieldType(index, t, seg)));
  return types.flatMap((t) => methodsOn(index, t, method));
}

const MAX_DEPTH = 5;
const MAX_METHODS = 80;

/**
 * The text of every method a method calls, directly or through others, in any file of the project: where a rate
 * limiter, lockout or expiry check two calls away shows up. `onlyLines` keeps to the calls made on those lines (a
 * closure inside a larger function).
 */
export function reachableText(project: Project | undefined, from: Method, onlyLines?: [number, number]): string {
  if (!project) return '';
  const lang = otherLangOf(from.file);
  if (!lang) return '';
  const index = indexFor(project, lang);
  const seen = new Set<string>([`${from.file}:${from.line}:${from.name}`]);
  const texts: string[] = [];
  const visit = (m: Method, depth: number, lines?: [number, number]) => {
    if (depth >= MAX_DEPTH) return;
    for (const call of m.calls) {
      if (lines && (call.line < lines[0] || call.line > lines[1])) continue;
      for (const target of resolve(index, m, call)) {
        const key = `${target.file}:${target.line}:${target.name}`;
        if (seen.has(key) || seen.size > MAX_METHODS) continue;
        seen.add(key);
        texts.push(target.text);
        visit(target, depth + 1);
      }
    }
  };
  visit(from, 0, onlyLines);
  return texts.join('\n');
}

/** The method in a file that spans a line, by name when one is given. */
export function methodAt(project: Project | undefined, file: SourceFile, line: number, name?: string): Method | null {
  const lang = otherLangOf(file.path);
  if (!lang) return null;
  const model = (project && indexFor(project, lang).files.get(file.path)) ?? modelOf(file);
  if (!model) return null;
  const all = [...model.types.flatMap((t) => t.methods), ...model.functions];
  return all.filter((m) => line >= m.line && line <= m.endLine && (!name || m.name === name)).sort((a, b) => (a.endLine - a.line) - (b.endLine - b.line))[0] ?? null;
}

/**
 * The methods a handler reference names (`h.Login` in `r.POST("/login", h.Login)`), resolved from the function the
 * reference sits in, the way a call there would be.
 */
export function methodsReferenced(project: Project | undefined, file: SourceFile, line: number, ref: string): Method[] {
  const lang = otherLangOf(file.path);
  if (!project || !lang) return [];
  const from = methodAt(project, file, line);
  const chain = ref.split('.').filter(Boolean);
  return from && chain.length ? resolve(indexFor(project, lang), from, { chain, line }) : [];
}

/** The one method with this name in the project's files of this language, when there's exactly one. */
export function onlyMethodNamed(project: Project | undefined, lang: OtherLang, name: string): Method | null {
  if (!project) return null;
  const index = indexFor(project, lang);
  const found = [...index.types.values()].flat().flatMap((t) => t.methods.filter((m) => m.name === name)).concat(index.functions.get(name) ?? []);
  return found.length === 1 ? found[0]! : null;
}
