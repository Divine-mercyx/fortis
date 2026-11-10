import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/*
 * Lockfile readers for the dependency check: npm (package-lock.json / npm-shrinkwrap.json),
 * pnpm (pnpm-lock.yaml v5, v6 and v9), yarn (yarn.lock v1 and berry) and Bun (bun.lock). No YAML library:
 * these files are machine-written with a fixed, indentation-based layout, so a line reader is
 * enough and keeps the CLI dependency-free.
 *
 * Every reader returns the installed packages and whether each is only needed for development.
 * When a lockfile doesn't say (pnpm v9, yarn, Bun), dev-only is worked out by walking the dependency
 * graph from package.json's production dependencies (every workspace's, for Yarn workspaces);
 * if that walk finds nothing, every package is treated as production so nothing is hidden.
 *
 * Packages from git, a tarball or a local folder are kept with their `source`, because OSV only
 * knows registry releases: the dependency check names them instead of checking them.
 */

/**
 * `direct`: listed in package.json. `via`: for an indirect package, the direct dependency that pulls
 * it in (the first one found). Both are left out when the lockfile doesn't show the graph.
 */
export type LockedPackage = { name: string; version: string; dev: boolean; line: number; direct?: boolean; via?: string; source?: PackageSource };

/** Where a package came from when it isn't the npm registry. OSV knows registry releases only, so these aren't checked. */
export type PackageSource = 'git' | 'tarball' | 'local';

/**
 * The source a lockfile's reference points at: `git+ssh://…`, `github:user/repo#sha`, a tarball URL,
 * `file:../lib`. Undefined for the registry, including its own tarball URLs (`…/-/name-1.0.0.tgz`),
 * and for workspace links, which are the project's own code.
 */
export function sourceOf(ref: string): PackageSource | undefined {
  const r = ref.replace(/^npm:/, '');
  if (/^(?:workspace|link):/.test(r)) return undefined;
  if (/^(?:file|portal):/.test(r) || /^\.{0,2}\//.test(r)) return 'local';
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|git@)|\.git(?:#|$)|^[\w.-]+\/[\w.-]+(?:#.*)?$|codeload\.github\.com\/[^/]+\/[^/]+\/tar\.gz\/[0-9a-f]{40}$/.test(r)) return 'git';
  if (!/^https?:\/\//.test(r) || /\/-\/[^/]+\.tgz(?:[#?].*)?$/.test(r)) return undefined;
  // A tarball file, or an archive from a code host. Other URLs are private registries (GitHub
  // Packages downloads have no .tgz), whose packages are still registry releases worth checking.
  return /\.(?:tgz|tar\.gz)(?:[#?].*)?$|^https?:\/\/(?:codeload\.github\.com|github\.com|gitlab\.com|bitbucket\.org)\//.test(r) ? 'tarball' : undefined;
}

export type Lockfile = { file: string; packages: LockedPackage[] };

/** Lockfiles we read, in the order we prefer them when a repo has more than one. */
export const SUPPORTED_LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'] as const;

const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;

export function readLockfile(root: string): Lockfile | null {
  for (const file of SUPPORTED_LOCKFILES) {
    const p = join(root, file);
    if (!existsSync(p)) continue;
    const text = readFileSync(p, 'utf8');
    const manifest = readManifest(root);
    if (file === 'pnpm-lock.yaml') return { file, packages: parsePnpmLock(text) };
    if (file === 'yarn.lock') return { file, packages: parseYarnLock(text, manifest) };
    if (file === 'bun.lock') return { file, packages: parseBunLock(text) };
    return { file, packages: parseNpmLock(text) };
  }
  return null;
}

export type Manifest = { name?: string; packageManager?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string>; devDependencies?: Record<string, string>; resolutions?: Record<string, string>; workspaces?: unknown };

/** Whether a folder matches a workspace pattern such as `packages/*` or `apps/**`. */
export function globMatch(pattern: string, folder: string): boolean {
  const p = pattern.replace(/^\.\//, '').replace(/\/+$/, '');
  const re = p
    .split('/')
    .map((part) => (part === '**' ? '.*' : part.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*')))
    .join('/');
  return new RegExp(`^${re}$`).test(folder.replace(/^\.\//, '').replace(/\/+$/, ''));
}

function readManifest(root: string): Manifest {
  try {
    return JSON.parse(readFileSync(join(root, 'package.json'), 'utf8').replace(/^\uFEFF/, '')) as Manifest;
  } catch {
    return {};
  }
}

function dedupe(list: LockedPackage[]): LockedPackage[] {
  const out = new Map<string, LockedPackage>();
  for (const p of list) {
    if (!p.name || (!p.source && !SEMVER.test(p.version))) continue;
    const key = p.source ? `${p.name}@${p.source}:${p.version}` : `${p.name}@${p.version}`;
    const prev = out.get(key);
    // Needed in production anywhere → production.
    if (!prev) out.set(key, p);
    else {
      const merged = { ...prev, dev: prev.dev && p.dev, direct: prev.direct || p.direct || undefined, via: prev.via ?? p.via };
      if (merged.direct) delete merged.via;
      out.set(key, merged);
    }
  }
  return [...out.values()];
}

/** Marks as dev everything not reachable from the production roots. */
function classify<T extends { name: string; version: string; line: number; deps: string[]; source?: PackageSource }>(
  nodes: Map<string, T>,
  prodRoots: string[],
  devRoots: string[] = [],
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
  const via = viaRoots(nodes, [...prodRoots, ...devRoots]);
  const roots = new Set([...prodRoots, ...devRoots]);
  return dedupe(
    [...nodes.entries()].map(([k, n]) => ({
      name: n.name,
      version: n.version,
      line: n.line,
      dev: walked ? !prod.has(k) : false,
      ...(n.source ? { source: n.source } : {}),
      ...(roots.has(k) ? { direct: true } : via.has(k) ? { direct: false, via: via.get(k) } : {}),
    })),
  );
}

/** For each node reachable from a root, the name of the first root (in order) that reaches it. */
function viaRoots(nodes: Map<string, { name: string; deps: string[] }>, roots: string[]): Map<string, string> {
  const via = new Map<string, string>();
  const isRoot = new Set(roots);
  for (const r of roots) {
    if (!nodes.has(r)) continue;
    const rootName = nodes.get(r)!.name;
    const queue = [...nodes.get(r)!.deps];
    while (queue.length) {
      const k = queue.shift()!;
      if (via.has(k) || isRoot.has(k) || !nodes.has(k)) continue;
      via.set(k, rootName);
      queue.push(...nodes.get(k)!.deps);
    }
  }
  return via;
}

// ---------------------------------------------------------------- npm

export function parseNpmLock(text: string): LockedPackage[] {
  type Deps = Record<string, string>;
  type Entry = { version?: string; resolved?: string; dev?: boolean; link?: boolean; name?: string; workspaces?: string[] | { packages?: string[] }; dependencies?: Deps; optionalDependencies?: Deps; devDependencies?: Deps; peerDependencies?: Deps };
  const lock = JSON.parse(text) as {
    packages?: Record<string, Entry>;
    dependencies?: Record<string, { version: string; dev?: boolean }>;
  };
  const out: LockedPackage[] = [];
  if (lock.packages) {
    const pkgs = lock.packages;
    // Node's lookup: from a package's folder, the nearest node_modules/<name> going up.
    const resolveFrom = (from: string, name: string): string | undefined => {
      for (let dir = from; ; ) {
        const candidate = `${dir ? `${dir}/` : ''}node_modules/${name}`;
        if (pkgs[candidate]) return candidate;
        if (!dir) return undefined;
        const cut = dir.lastIndexOf('/node_modules/');
        dir = cut === -1 ? '' : dir.slice(0, cut);
      }
    };
    const nodes = new Map<string, { name: string; deps: string[] }>();
    for (const [path, meta] of Object.entries(pkgs)) {
      if (!path.includes('node_modules/') || meta.link) continue;
      const deps = Object.keys({ ...meta.dependencies, ...meta.optionalDependencies, ...meta.peerDependencies })
        .map((d) => resolveFrom(path, d))
        .filter((d): d is string => Boolean(d));
      nodes.set(path, { name: meta.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length), deps });
    }
    const root = pkgs[''] ?? {};
    const rootNames = [root.dependencies, root.optionalDependencies, root.peerDependencies, root.devDependencies].flatMap((d) => Object.keys(d ?? {}));
    const roots = [...new Set(rootNames.map((n) => resolveFrom('', n)).filter((d): d is string => Boolean(d)))];
    const isRoot = new Set(roots);
    const via = roots.length ? viaRoots(nodes, roots) : new Map<string, string>();
    const workspaces = Array.isArray(root.workspaces) ? root.workspaces : (root.workspaces?.packages ?? []);
    const isWorkspace = (folder: string) => workspaces.some((w) => globMatch(w, folder));
    for (const [path, meta] of Object.entries(pkgs)) {
      if (!path || !path.includes('node_modules/')) continue; // workspace folders, not installed packages
      const name = meta.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      if (meta.link) {
        // A link to a workspace is the project's own code. Any other is a local folder: `file:../lib`.
        if (meta.resolved && !isWorkspace(meta.resolved)) out.push({ name, version: '', dev: Boolean(meta.dev), line: 0, source: 'local' });
        continue;
      }
      if (!meta.version) continue;
      const source = meta.resolved ? sourceOf(meta.resolved) : undefined;
      const graph = isRoot.has(path) ? { direct: true } : via.has(path) ? { direct: false, via: via.get(path) } : {};
      out.push({ name, version: meta.version, dev: Boolean(meta.dev), line: 0, ...graph, ...(source ? { source } : {}) });
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
  const k = key.replace(/^\//, '').replace(/\(.*$/, '');
  // A package from git, a tarball or a folder: the reference stays whole.
  const other = /^(@?[^@/]+(?:\/[^@/]+)?)@((?:https?|file|git(?:\+[a-z]+)?|github|link):.*)$/.exec(k);
  if (other) return [other[1]!, other[2]!];
  // `name@1.2.3` / `@scope/name@1.2.3` (v6+), told apart from `/name/1.2.3_peer@1` (v5) by the key
  // itself, since an old lockfile may not say which version it is.
  const modern = /^(@?[^@/]+(?:\/[^@/]+)?)@([^/@]+)$/.exec(k);
  if (modern && !v5) return [modern[1]!, modern[2]!];
  const parts = k.split('/');
  if (parts.length < 2) return null;
  const version = stripPeers(parts.pop() ?? '');
  return [parts.join('/'), version];
}

/** A dependency's snapshot key. An aliased dependency's version is already the real `name@version`. */
const pnpmRef = (name: string, version: string) => (/^@?[^@(]+@/.test(version) ? version : `${name}@${version}`);

/** A package's name and version, or where it came from when that isn't the registry. */
function pnpmNode([name, ref]: [string, string], specifiers: Map<string, string>): { name: string; version: string; source?: PackageSource } {
  if (SEMVER.test(ref)) return { name, version: ref };
  const spec = specifiers.get(name);
  const source = (spec && sourceOf(spec)) ?? sourceOf(ref);
  return source ? { name, version: '', source } : { name, version: ref };
}

export function parsePnpmLock(text: string): LockedPackage[] {
  const all = lines(text);
  const secs = sections(all);
  const version = parseFloat(unquote(all.find((l) => l.indent === 0 && l.text.startsWith('lockfileVersion'))?.text.split(':')[1] ?? '0'));
  const v5 = version > 0 && version < 6;
  // No version line: an old lockfile; keys are recognised by their shape.
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

  // v9: `packages` lists what is installed; `snapshots` holds the graph (one entry per peer
  // variant); `importers` holds the roots. A snapshot whose package isn't listed is ignored.
  const nodes = new Map<string, { name: string; version: string; line: number; deps: string[]; source?: PackageSource }>();
  // What package.json asked for (`github:…`, a URL), which tells git from a tarball when both are codeload URLs.
  const specifiers = new Map<string, string>();
  for (const { body } of entries(secs.get('importers') ?? [])) {
    let name: string | null = null;
    for (const l of body) {
      const [k, v] = keyValue(l.text);
      if (k === 'specifier' && name) specifiers.set(name, v);
      else if (v === '' && !/^(?:dependencies|optionalDependencies|devDependencies)$/.test(k)) name = k;
    }
  }
  const listed = new Map(packages.map(({ head }) => [keyValue(head.text)[0], head.no]));
  for (const { head, body } of entries(secs.get('snapshots') ?? [])) {
    const key = keyValue(head.text)[0];
    const line = listed.get(key.replace(/\(.*$/, ''));
    const kv = splitPnpmKey(key, false);
    if (!kv || line === undefined) continue;
    const deps = [...childMap(body, 'dependencies'), ...childMap(body, 'optionalDependencies')].map(([n, v]) => pnpmRef(n, v));
    nodes.set(key, { ...pnpmNode(kv, specifiers), line, deps });
  }
  // Packages with no snapshot entry (or a lockfile without snapshots) still count.
  const covered = new Set([...nodes.keys()].map((k) => k.replace(/\(.*$/, '')));
  for (const [key, line] of listed) {
    const kv = splitPnpmKey(key, false);
    if (kv && !covered.has(key)) nodes.set(key, { ...pnpmNode(kv, specifiers), line, deps: [] });
  }
  const prodRoots: string[] = [];
  const devRoots: string[] = [];
  for (const { body } of entries(secs.get('importers') ?? [])) {
    for (const field of ['dependencies', 'optionalDependencies', 'devDependencies']) {
      const into = field === 'devDependencies' ? devRoots : prodRoots;
      const start = body.findIndex((l) => keyValue(l.text)[0] === field);
      if (start === -1) continue;
      const level = body[start]!.indent;
      let name: string | null = null;
      for (let i = start + 1; i < body.length && body[i]!.indent > level; i++) {
        const [k, v] = keyValue(body[i]!.text);
        if (body[i]!.indent === level + 2) name = k;
        else if (k === 'version' && name && !v.startsWith('link:')) into.push(pnpmRef(name, v));
      }
    }
  }
  return classify(nodes, prodRoots, devRoots);
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

/**
 * `workspaces`: each workspace's package.json. Without them, a workspace root lists none of its
 * packages' dependencies, so every package counts as production rather than hide real ones.
 */
export function parseYarnLock(text: string, manifest: Manifest = {}, workspaces: Manifest[] = []): LockedPackage[] {
  const all = lines(text);
  const berry = all.some((l) => l.indent === 0 && l.text.startsWith('__metadata'));
  const nodes = new Map<string, { name: string; version: string; line: number; deps: string[]; source?: PackageSource }>();
  const byDescriptor = new Map<string, string>();

  for (const { head, body } of entries(all)) {
    // `"a@^1, a@^2":` (berry quotes the whole list) or `"a@^1", "a@^2":` (v1 quotes each).
    const header = head.text.replace(/:$/, '');
    if (header === '__metadata') continue;
    const descriptors = header.split(/,\s*/).map((d) => d.replace(/^["']|["']$/g, ''));
    const version = scalar(body, 'version', !berry);
    const resolution = scalar(body, 'resolution', !berry) ?? '';
    // Workspaces are the project itself, not installed packages.
    if (!version || /@workspace:/.test(resolution) || descriptors.some((d) => /@workspace:/.test(d))) continue;
    const name = descriptorName(berry && resolution ? resolution : descriptors[0]!);
    const rangeOf = (d: string) => d.slice(d.indexOf('@', d.startsWith('@') ? 1 : 0) + 1);
    // Local folders, git and tarballs: from what package.json asked for, or what it resolved to.
    const source = sourceOf(rangeOf(descriptors[0]!)) ?? (resolution ? sourceOf(rangeOf(resolution)) : undefined) ?? sourceOf(scalar(body, 'resolved', !berry) ?? '');
    const id = `${name}@${version}#${head.no}`;
    const depLines = [...yarnChildren(body, 'dependencies', berry), ...yarnChildren(body, 'optionalDependencies', berry)];
    nodes.set(id, { name, version: source ? '' : version, line: head.no, deps: depLines.map(([n, r]) => `${n}@${r}`), ...(source ? { source } : {}) });
    for (const d of descriptors) byDescriptor.set(d, id);
  }

  // Edges and roots are descriptors (name@range); point them at the entries that satisfy them.
  // `resolutions` in package.json replace a range everywhere. Berry keeps the original range on the
  // dependent (`minimist: npm:^1.2.5`) but lists only the replacement, so look that up too.
  const replaced = new Map<string, string>();
  for (const [key, range] of Object.entries(manifest.resolutions ?? {})) replaced.set(key.replace(/^(?:\*\*\/)?(?:.*\/)?((?:@[^/]+\/)?[^/]+)$/, '$1'), range);
  const byName = new Map<string, string[]>();
  for (const [id, n] of nodes) byName.set(n.name, [...(byName.get(n.name) ?? []), id]);
  const resolve = (d: string) => {
    const at = d.indexOf('@', d.startsWith('@') ? 1 : 0);
    const name = at > 0 ? d.slice(0, at) : d;
    const lookup = (range: string) => byDescriptor.get(`${name}@${range}`) ?? byDescriptor.get(`${name}@npm:${range.replace(/^npm:/, '')}`);
    const forced = replaced.get(name);
    const only = byName.get(name);
    return byDescriptor.get(d) ?? (at > 0 ? lookup(d.slice(at + 1)) : undefined) ?? (forced ? lookup(forced) : undefined) ?? (only?.length === 1 ? only[0] : undefined);
  };
  for (const n of nodes.values()) n.deps = n.deps.map((d) => resolve(d) ?? '').filter(Boolean);
  // A workspace root doesn't list its packages' dependencies: the roots are those of every workspace.
  // Without their package.json files, walking from the root alone would mark everything dev.
  const owners = manifest.workspaces ? (workspaces.length ? [manifest, ...workspaces] : []) : [manifest];
  const own = new Set(workspaces.map((w) => w.name).filter(Boolean));
  const rootsOf = (pick: (m: Manifest) => Record<string, string>[]) =>
    owners
      .flatMap((m) => pick(m).flatMap((deps) => Object.entries(deps ?? {})))
      .filter(([n, r]) => !own.has(n) && !r.startsWith('workspace:'))
      .map(([n, r]) => resolve(`${n}@${r}`) ?? '')
      .filter(Boolean);
  const prodRoots = rootsOf((m) => [m.dependencies ?? {}, m.optionalDependencies ?? {}, m.peerDependencies ?? {}]);
  const devRoots = rootsOf((m) => [m.devDependencies ?? {}]);
  return classify(nodes, prodRoots, devRoots);
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

// ---------------------------------------------------------------- bun

/** bun.lock is JSON with trailing commas (JSONC). Drops those and any comments, leaving strings alone. */
export function parseJsonc(text: string): unknown {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? text.length : end + 1;
    } else if (c === ',') {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (text[j] !== '}' && text[j] !== ']') out += c;
    } else out += c;
  }
  return JSON.parse(out.charCodeAt(0) === 0xfeff ? out.slice(1) : out);
}

/** `name@spec` → [name, spec], for scoped names too. */
function splitAt(ident: string): [string, string] {
  const at = ident.indexOf('@', ident.startsWith('@') ? 1 : 0);
  return at === -1 ? [ident, ''] : [ident.slice(0, at), ident.slice(at + 1)];
}

/** A package key's path of names: `@babel/highlight/chalk` → ['@babel/highlight', 'chalk']. */
function keyNames(key: string): string[] {
  const parts = key.split('/');
  const out: string[] = [];
  for (let i = 0; i < parts.length; i++) out.push(parts[i]!.startsWith('@') && i + 1 < parts.length ? `${parts[i]}/${parts[++i]}` : parts[i]!);
  return out;
}

type BunDeps = { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string>; devDependencies?: Record<string, string> };

/**
 * Bun's text lockfile (Bun 1.2 and later). `packages` maps a key to
 * `["name@version", registry, { dependencies… }, integrity]`; the key is the name the package is
 * installed under (an alias's own name), and nested copies are keyed by path, `parent/name`, which
 * is how a dependency is found: the nearest key going up, as in node_modules. `workspaces` lists
 * each workspace's dependencies and devDependencies, so dev-only packages come from the lockfile
 * itself, by walking from the production ones.
 */
export function parseBunLock(text: string): LockedPackage[] {
  const lock = parseJsonc(text) as { workspaces?: Record<string, BunDeps & { name?: string }>; packages?: Record<string, unknown[]> };
  const pkgs = lock.packages ?? {};

  // Each package is on its own line: `    "key": ["name@version", …],` inside "packages".
  const lineOfKey = new Map<string, number>();
  const all = text.split(/\r?\n/);
  const start = all.findIndex((l) => /^\s*"packages"\s*:\s*\{/.test(l));
  for (let i = start + 1; start !== -1 && i < all.length; i++) {
    const m = /^\s*("(?:[^"\\]|\\.)*")\s*:\s*\[/.exec(all[i]!);
    if (m) lineOfKey.set(JSON.parse(m[1]!) as string, i + 1);
  }

  const resolve = (from: string[], dep: string): string | undefined => {
    for (let n = from.length; n >= 0; n--) {
      const key = [...from.slice(0, n), dep].join('/');
      if (pkgs[key]) return key;
    }
    return undefined;
  };
  const depNames = (d: BunDeps | undefined) => Object.keys({ ...d?.dependencies, ...d?.optionalDependencies, ...d?.peerDependencies });

  const nodes = new Map<string, { name: string; version: string; line: number; deps: string[]; source?: PackageSource }>();
  for (const [key, entry] of Object.entries(pkgs)) {
    if (!Array.isArray(entry) || typeof entry[0] !== 'string') continue;
    const [name, spec] = splitAt(entry[0]);
    // The project's own code: workspaces and the root.
    if (/^(?:workspace|root):/.test(spec)) continue;
    const info = (entry.find((e, i) => i > 0 && e && typeof e === 'object' && !Array.isArray(e)) ?? {}) as BunDeps;
    const source = /^(?:file|link):/.test(spec) ? 'local' : /^https?:\/\//.test(spec) ? (sourceOf(spec) ?? 'tarball') : sourceOf(spec);
    const from = keyNames(key);
    const deps = depNames(info)
      .map((d) => resolve(from, d))
      .filter((d): d is string => Boolean(d));
    nodes.set(key, { name, version: source ? '' : spec, line: lineOfKey.get(key) ?? 0, deps, ...(source ? { source } : {}) });
  }

  // Roots: every workspace's dependencies, looked up from the workspace (a member's own copies are
  // keyed under its name). Other workspaces are the project's own code, not roots.
  const prodRoots: string[] = [];
  const devRoots: string[] = [];
  for (const [path, ws] of Object.entries(lock.workspaces ?? {})) {
    const from = path && ws.name ? [ws.name] : [];
    const roots = (names: string[]) => names.map((d) => resolve(from, d)).filter((d): d is string => Boolean(d) && nodes.has(d!));
    prodRoots.push(...roots(depNames(ws)));
    devRoots.push(...roots(Object.keys(ws.devDependencies ?? {})));
  }
  return classify(nodes, [...new Set(prodRoots)], [...new Set(devRoots)]);
}
