import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/*
 * Lockfile readers for the dependency check: npm (package-lock.json / npm-shrinkwrap.json),
 * pnpm (pnpm-lock.yaml v5, v6 and v9) and yarn (yarn.lock v1 and berry). No YAML library:
 * these files are machine-written with a fixed, indentation-based layout, so a line reader is
 * enough and keeps the CLI dependency-free.
 *
 * Every reader returns the installed packages and whether each is only needed for development.
 * When a lockfile doesn't say (pnpm v9, yarn), dev-only is worked out by walking the dependency
 * graph from package.json's production dependencies; if that walk finds nothing (an unusual
 * workspace layout), every package is treated as production so nothing is hidden.
 */

export type LockedPackage = { name: string; version: string; dev: boolean; line: number };
export type Lockfile = { file: string; packages: LockedPackage[] };

/** Lockfiles we read, in the order we prefer them when a repo has more than one. */
export const SUPPORTED_LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;

export function readLockfile(root: string): Lockfile | null {
  for (const file of SUPPORTED_LOCKFILES) {
    const p = join(root, file);
    if (!existsSync(p)) continue;
    const text = readFileSync(p, 'utf8');
    const manifest = readManifest(root);
    if (file === 'pnpm-lock.yaml') return { file, packages: parsePnpmLock(text) };
    if (file === 'yarn.lock') return { file, packages: parseYarnLock(text, manifest) };
    return { file, packages: parseNpmLock(text) };
  }
  return null;
}

type Manifest = { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string>; devDependencies?: Record<string, string> };

function readManifest(root: string): Manifest {
  try {
    return JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Manifest;
  } catch {
    return {};
  }
}

function dedupe(list: LockedPackage[]): LockedPackage[] {
  const out = new Map<string, LockedPackage>();
  for (const p of list) {
    if (!p.name || !SEMVER.test(p.version)) continue;
    const key = `${p.name}@${p.version}`;
    const prev = out.get(key);
    // Needed in production anywhere → production.
    if (!prev) out.set(key, p);
    else if (prev.dev && !p.dev) out.set(key, { ...prev, dev: false });
  }
  return [...out.values()];
}

/** Marks as dev everything not reachable from the production roots. */
function classify<T extends { name: string; version: string; line: number; deps: string[] }>(
  nodes: Map<string, T>,
  prodRoots: string[],
): LockedPackage[] {
  const prod = new Set<string>();
  const stack = prodRoots.filter((k) => nodes.has(k));
  while (stack.length) {
    const k = stack.pop()!;
    if (prod.has(k)) continue;
    prod.add(k);
    for (const d of nodes.get(k)!.deps) if (nodes.has(d) && !prod.has(d)) stack.push(d);
  }
  const walked = prod.size > 0;
  return dedupe([...nodes.entries()].map(([k, n]) => ({ name: n.name, version: n.version, line: n.line, dev: walked ? !prod.has(k) : false })));
}

// ---------------------------------------------------------------- npm

export function parseNpmLock(text: string): LockedPackage[] {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; dev?: boolean; link?: boolean; name?: string }>;
    dependencies?: Record<string, { version: string; dev?: boolean }>;
  };
  const out: LockedPackage[] = [];
  if (lock.packages) {
    for (const [path, meta] of Object.entries(lock.packages)) {
      if (!path || !meta.version || meta.link) continue;
      if (!path.includes('node_modules/')) continue; // workspace folders, not installed packages
      const name = meta.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.push({ name, version: meta.version, dev: Boolean(meta.dev), line: 0 });
    }
  } else if (lock.dependencies) {
    for (const [name, meta] of Object.entries(lock.dependencies)) out.push({ name, version: meta.version, dev: Boolean(meta.dev), line: 0 });
  }
  return dedupe(out);
}

// ---------------------------------------------------------------- shared line reader

type Line = { indent: number; text: string; no: number };

function lines(text: string): Line[] {
  const out: Line[] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    if (!raw.trim() || raw.trimStart().startsWith('#')) return;
    out.push({ indent: raw.length - raw.trimStart().length, text: raw.trim(), no: i + 1 });
  });
  return out;
}

function unquote(s: string): string {
  const t = s.trim();
  return (t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")) ? t.slice(1, -1) : t;
}

/** `key: value` / `key value` (yarn v1) → [key, value]. Key may be quoted and contain ':' or '@'. */
function keyValue(text: string, yarnV1 = false): [string, string] {
  if (text.startsWith('"') || text.startsWith("'")) {
    const q = text[0]!;
    const end = text.indexOf(q, 1);
    const key = text.slice(1, end);
    const rest = text.slice(end + 1).replace(/^:/, '').trim();
    return [key, unquote(rest)];
  }
  if (yarnV1) {
    const sp = text.search(/[\s:]/);
    if (sp === -1) return [text, ''];
    return [text.slice(0, sp), unquote(text.slice(sp + 1).replace(/^:/, ''))];
  }
  const c = text.indexOf(': ');
  if (c === -1) return [text.replace(/:$/, ''), ''];
  return [text.slice(0, c), unquote(text.slice(c + 2))];
}

/** Top-level sections of a pnpm lockfile, each as its child lines. */
function sections(all: Line[]): Map<string, Line[]> {
  const out = new Map<string, Line[]>();
  let current: Line[] | null = null;
  for (const l of all) {
    if (l.indent === 0) {
      current = [];
      out.set(keyValue(l.text)[0], current);
    } else current?.push(l);
  }
  return out;
}

/** Splits a section into its entries (lines at the section's first indent) with their bodies. */
function entries(section: Line[]): { head: Line; body: Line[] }[] {
  if (!section.length) return [];
  const level = section[0]!.indent;
  const out: { head: Line; body: Line[] }[] = [];
  for (const l of section) {
    if (l.indent === level) out.push({ head: l, body: [] });
    else out[out.length - 1]?.body.push(l);
  }
  return out;
}

/** Child map under `field:` inside an entry body (e.g. dependencies). */
function childMap(body: Line[], field: string): [string, string][] {
  const start = body.findIndex((l) => keyValue(l.text)[0] === field && !keyValue(l.text)[1]);
  if (start === -1) return [];
  const level = body[start]!.indent;
  const out: [string, string][] = [];
  for (let i = start + 1; i < body.length && body[i]!.indent > level; i++) {
    if (body[i]!.indent === body[start + 1]!.indent) out.push(keyValue(body[i]!.text));
  }
  return out;
}

function scalar(body: Line[], field: string, yarnV1 = false): string | undefined {
  const top = body[0]?.indent;
  const l = body.find((x) => x.indent === top && keyValue(x.text, yarnV1)[0] === field);
  return l ? keyValue(l.text, yarnV1)[1] : undefined;
}

// ---------------------------------------------------------------- pnpm

const stripPeers = (v: string) => v.replace(/\(.*$/, '').replace(/_.*$/, '');

/** `@scope/name@1.2.3(peer@1)` → [name, version]; v5 `/@scope/name/1.2.3_peer` too. */
export function splitPnpmKey(key: string, v5: boolean): [string, string] | null {
  let k = key.replace(/^\//, '');
  if (v5) {
    const parts = k.split('/');
    const version = stripPeers(parts.pop() ?? '');
    return [parts.join('/'), version];
  }
  k = k.replace(/\(.*$/, '');
  const at = k.lastIndexOf('@');
  if (at <= 0) return null;
  return [k.slice(0, at), k.slice(at + 1)];
}

export function parsePnpmLock(text: string): LockedPackage[] {
  const all = lines(text);
  const secs = sections(all);
  const version = parseFloat(unquote(all.find((l) => l.indent === 0 && l.text.startsWith('lockfileVersion'))?.text.split(':')[1] ?? '0'));
  const v5 = version > 0 && version < 6;
  const packages = entries(secs.get('packages') ?? []);

  // v5/v6: each package says whether it's dev-only.
  if (version < 9) {
    return dedupe(
      packages.flatMap(({ head, body }) => {
        const kv = splitPnpmKey(keyValue(head.text)[0], v5);
        if (!kv) return [];
        const devFlag = scalar(body, 'dev');
        return [{ name: scalar(body, 'name') ?? kv[0], version: scalar(body, 'version') ?? kv[1], dev: devFlag === 'true', line: head.no }];
      }),
    );
  }

  // v9: graph lives in `snapshots`; roots in `importers`.
  const nodes = new Map<string, { name: string; version: string; line: number; deps: string[] }>();
  const lineOf = new Map(packages.map(({ head }) => [keyValue(head.text)[0], head.no]));
  for (const { head, body } of entries(secs.get('snapshots') ?? [])) {
    const key = keyValue(head.text)[0];
    const kv = splitPnpmKey(key, false);
    if (!kv) continue;
    const deps = [...childMap(body, 'dependencies'), ...childMap(body, 'optionalDependencies')].map(([n, v]) => `${n}@${v}`);
    nodes.set(key, { name: kv[0], version: kv[1], line: lineOf.get(key.replace(/\(.*$/, '')) ?? head.no, deps });
  }
  if (!nodes.size) {
    for (const { head } of packages) {
      const kv = splitPnpmKey(keyValue(head.text)[0], false);
      if (kv) nodes.set(keyValue(head.text)[0], { name: kv[0], version: kv[1], line: head.no, deps: [] });
    }
  }
  const prodRoots: string[] = [];
  for (const { body } of entries(secs.get('importers') ?? [])) {
    for (const field of ['dependencies', 'optionalDependencies']) {
      const start = body.findIndex((l) => keyValue(l.text)[0] === field);
      if (start === -1) continue;
      const level = body[start]!.indent;
      let name: string | null = null;
      for (let i = start + 1; i < body.length && body[i]!.indent > level; i++) {
        const [k, v] = keyValue(body[i]!.text);
        if (body[i]!.indent === level + 2) name = k;
        else if (k === 'version' && name && !v.startsWith('link:')) prodRoots.push(`${name}@${v}`);
      }
    }
  }
  return classify(nodes, prodRoots);
}

// ---------------------------------------------------------------- yarn

/** `@scope/name@^1` → name; an alias `foo@npm:bar@^1` → bar. */
function descriptorName(descriptor: string): string {
  const at = descriptor.indexOf('@', descriptor.startsWith('@') ? 1 : 0);
  const name = at === -1 ? descriptor : descriptor.slice(0, at);
  const range = at === -1 ? '' : descriptor.slice(at + 1);
  const alias = /^npm:(@?[^@]+)@/.exec(range);
  return alias ? alias[1]! : name;
}

export function parseYarnLock(text: string, manifest: Manifest = {}): LockedPackage[] {
  const all = lines(text);
  const berry = all.some((l) => l.indent === 0 && l.text.startsWith('__metadata'));
  const nodes = new Map<string, { name: string; version: string; line: number; deps: string[] }>();
  const byDescriptor = new Map<string, string>();

  for (const { head, body } of entries(all)) {
    // `"a@^1, a@^2":` (berry quotes the whole list) or `"a@^1", "a@^2":` (v1 quotes each).
    const header = head.text.replace(/:$/, '');
    if (header === '__metadata') continue;
    const descriptors = header.split(/,\s*/).map((d) => d.replace(/^["']|["']$/g, ''));
    const version = scalar(body, 'version', !berry);
    const resolution = scalar(body, 'resolution', !berry) ?? '';
    if (!version || /@(workspace|link|portal|file):/.test(resolution)) continue;
    const name = descriptorName(berry && resolution ? resolution : descriptors[0]!);
    const id = `${name}@${version}#${head.no}`;
    const depLines = [...yarnChildren(body, 'dependencies', berry), ...yarnChildren(body, 'optionalDependencies', berry)];
    nodes.set(id, { name, version, line: head.no, deps: depLines.map(([n, r]) => `${n}@${r}`) });
    for (const d of descriptors) byDescriptor.set(d, id);
  }

  // Edges and roots are descriptors (name@range); point them at the entries that satisfy them.
  const resolve = (d: string) => {
    const at = d.indexOf('@', d.startsWith('@') ? 1 : 0);
    return byDescriptor.get(d) ?? (at > 0 ? byDescriptor.get(`${d.slice(0, at)}@npm:${d.slice(at + 1)}`) : undefined);
  };
  for (const n of nodes.values()) n.deps = n.deps.map((d) => resolve(d) ?? '').filter(Boolean);
  const prodRoots = Object.entries({ ...manifest.dependencies, ...manifest.optionalDependencies, ...manifest.peerDependencies })
    .map(([n, r]) => resolve(`${n}@${r}`) ?? '')
    .filter(Boolean);
  return classify(nodes, prodRoots);
}

function yarnChildren(body: Line[], field: string, berry: boolean): [string, string][] {
  const start = body.findIndex((l) => l.text === `${field}:`);
  if (start === -1) return [];
  const level = body[start]!.indent;
  const out: [string, string][] = [];
  for (let i = start + 1; i < body.length && body[i]!.indent > level; i++) {
    const [n, r] = keyValue(body[i]!.text, !berry);
    out.push([n, r]);
  }
  return out;
}
