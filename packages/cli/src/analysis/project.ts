import type { SourceFile } from '../rules/types';

import { factsFor, type CallFact, type FileFacts, type FnFact } from './facts';

/*
 * Following calls between functions and files. Deliberately simple: a call is resolved through the
 * file's imports and what its names hold, and anything cleverer counts as not resolved.
 */

export type Project = {
  /** Every source file, by path. */
  paths: Set<string>;
  read: (path: string) => SourceFile | null;
  /** Worked out as needed, then kept for the rest of the scan. */
  files: Map<string, SourceFile | null>;
  summaries: Map<string, FnSummary>;
  /** Paths by their last segment, for imports that aren't relative (`@/services/loan`). */
  byName: Map<string, string[]>;
};

export type FnSummary = {
  /** Parameters (by index) that end up as the ID of a record it loads, with no owner check on the way. */
  readsById: Set<number>;
  /** It, or something it calls, ties its work to the signed-in user. */
  ownerCheck: boolean;
  /** Names it or anything it calls uses, and its text, to look for words such as an idempotency key. */
  sources: string[];
  names: Set<string>;
};

export type Located = { file: SourceFile; facts: FileFacts; fn: FnFact };

const MAX_DEPTH = 5;
const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts', '/index.ts', '/index.tsx', '/index.js', '/index.jsx', '/index.mjs'];

export function createProject(paths: Iterable<string>, read: Project['read']): Project {
  const all = new Set(paths);
  const byName = new Map<string, string[]>();
  for (const p of all) {
    const name = p.slice(p.lastIndexOf('/') + 1);
    const list = byName.get(name);
    if (list) list.push(p);
    else byName.set(name, [p]);
  }
  return { paths: all, read, files: new Map(), summaries: new Map(), byName };
}

const fileIn = (project: Project, path: string): SourceFile | null => {
  if (!project.files.has(path)) {
    // Files are small once parsed into facts, but a repository can have many: keep this from growing without limit.
    if (project.files.size > 20_000) project.files.clear();
    project.files.set(path, project.read(path));
  }
  return project.files.get(path) ?? null;
};

const dirOf = (path: string) => (path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');

function normalizePath(path: string): string {
  const out: string[] = [];
  for (const part of path.split('/')) {
    if (part === '..') out.pop();
    else if (part && part !== '.') out.push(part);
  }
  return out.join('/');
}

/** A path ending in these segments, for `@/services/loan` or `app.services.loan`. */
function bySuffix(project: Project, tail: string): string | null {
  const name = tail.slice(tail.lastIndexOf('/') + 1);
  const found = project.byName.get(name)?.filter((p) => p === tail || p.endsWith(`/${tail}`)) ?? [];
  return found.length === 1 ? found[0]! : null;
}

function resolveJs(project: Project, from: string, spec: string): string | null {
  const base = spec.startsWith('.') ? normalizePath(`${dirOf(from)}/${spec}`) : spec.replace(/^(?:@|~|#)\/?/, '').replace(/^src\//, '');
  const noJs = base.replace(/\.[cm]?js$/, '');
  for (const candidate of [base, ...EXTENSIONS.map((e) => noJs + e)]) {
    if (spec.startsWith('.')) {
      if (project.paths.has(candidate)) return candidate;
    } else if (/[/]/.test(spec) || spec.startsWith('.')) {
      const hit = bySuffix(project, candidate);
      if (hit) return hit;
    }
  }
  return null;
}

/** `.services.loan` from `app/views.py`, or `app.services.loan`. */
function resolvePy(project: Project, from: string, spec: string): string | null {
  const dots = /^\.*/.exec(spec)![0].length;
  const rest = spec.slice(dots).replace(/\./g, '/');
  if (dots) {
    let dir = dirOf(from);
    for (let i = 1; i < dots; i++) dir = dirOf(dir);
    const base = normalizePath(`${dir}/${rest}`);
    return [`${base}.py`, `${base}/__init__.py`].find((c) => project.paths.has(c)) ?? null;
  }
  return bySuffix(project, `${rest}.py`) ?? bySuffix(project, `${rest}/__init__.py`);
}

const stripCall = (name: string) => name.replace(/\(\)$/, '');

function memberOf(facts: FileFacts, owner: string, name: string): FnFact | undefined {
  return facts.fns.find((f) => f.name === name && f.owner === owner);
}

function topLevel(facts: FileFacts, name: string): FnFact | undefined {
  return facts.fns.find((f) => f.name === name && !f.owner);
}

/** The module an import points at. `from .services import loans` may name a file or something in one. */
function moduleOf(project: Project, file: SourceFile, spec: string, imported: string): { file: SourceFile; viaName: boolean } | null {
  if (/\.py$/i.test(file.path)) {
    if (imported) {
      const asFile = resolvePy(project, file.path, `${spec}${spec.endsWith('.') ? '' : '.'}${imported}`);
      const target = asFile && fileIn(project, asFile);
      if (target) return { file: target, viaName: false };
    }
    const path = resolvePy(project, file.path, spec);
    const target = path && fileIn(project, path);
    return target ? { file: target, viaName: Boolean(imported) } : null;
  }
  const path = resolveJs(project, file.path, spec);
  const target = path && fileIn(project, path);
  return target ? { file: target, viaName: Boolean(imported) } : null;
}

/** Finds what `chain` calls, in this file or through its imports. */
export function resolveCall(project: Project | undefined, file: SourceFile, facts: FileFacts, caller: FnFact, chain: string[]): Located | null {
  const method = chain[chain.length - 1]!;
  const inThisFile = (fn: FnFact | undefined): Located | null => (fn ? { file, facts, fn } : null);

  const inModule = (name: string, member?: string): Located | null => {
    const imp = facts.imports.find((i) => i.local === name);
    if (!imp || !project) return null;
    const target = moduleOf(project, file, imp.module, imp.imported);
    if (!target) return null;
    const theirs = factsFor(target.file);
    const declared = target.viaName && imp.imported !== 'default' ? imp.imported : name;
    let fn: FnFact | undefined;
    if (!member) fn = topLevel(theirs, declared) ?? (imp.imported === 'default' ? theirs.fns.find((f) => f.id > 0 && !f.owner) : undefined);
    else {
      // The name is an object, a class, an instance, or the whole module.
      const type = theirs.instances.get(declared);
      fn = memberOf(theirs, declared, member) ?? (type ? memberOf(theirs, stripCall(type), member) : undefined);
      if (!fn && imp.imported === 'default') fn = theirs.fns.find((f) => f.name === member);
      if (!fn && !target.viaName) fn = topLevel(theirs, member);
    }
    return fn ? { file: target.file, facts: theirs, fn } : null;
  };

  if (chain.length === 1) return inThisFile(topLevel(facts, method)) ?? inModule(method);

  const objectName = stripCall(chain[chain.length - 2]!);
  const isSelf = objectName === 'this' || objectName === 'self';
  if (isSelf) return caller.owner ? inThisFile(memberOf(facts, caller.owner, method)) : null;

  // loans.get(id), or this.loans.get(id) with `loans` injected
  const type = facts.instances.get(objectName);
  if (type) {
    const className = stripCall(type);
    return inThisFile(memberOf(facts, className, method)) ?? inModule(className, method);
  }
  return inThisFile(memberOf(facts, objectName, method)) ?? inModule(objectName, method);
}

const keyOf = (located: Located) => `${located.file.path}#${located.fn.id}`;

/** What a function does, including what it calls. */
export function summarize(project: Project | undefined, located: Located, depth = 0, seen = new Set<string>()): FnSummary {
  const key = keyOf(located);
  const cached = project?.summaries.get(key);
  if (cached) return cached;
  const { file, facts, fn } = located;
  const summary: FnSummary = { readsById: new Set(), ownerCheck: fn.ownerCheck, sources: [fn.source], names: new Set(fn.names) };
  if (seen.has(key) || depth > MAX_DEPTH) return summary;
  seen.add(key);

  for (const read of facts.reads) {
    if (read.fn !== fn.id) continue;
    if (read.scoped) summary.ownerCheck = true;
    else for (const o of read.origins) if (typeof o === 'number') summary.readsById.add(o);
  }
  for (const call of callsIn(facts, fn)) {
    const target = resolveCall(project, file, facts, fn, call.chain);
    if (!target) continue;
    const theirs = summarize(project, target, depth + 1, seen);
    if (theirs.ownerCheck) summary.ownerCheck = true;
    summary.sources.push(...theirs.sources);
    for (const name of theirs.names) summary.names.add(name);
    call.args.forEach((origins, i) => {
      if (!theirs.readsById.has(i)) return;
      for (const o of origins) if (typeof o === 'number') summary.readsById.add(o);
    });
  }
  // Worked out at the top of the call tree only: partway round a cycle, it isn't complete.
  if (depth === 0) project?.summaries.set(key, summary);
  return summary;
}

export const callsIn = (facts: FileFacts, fn: FnFact): CallFact[] => facts.calls.filter((c) => c.fn === fn.id);
