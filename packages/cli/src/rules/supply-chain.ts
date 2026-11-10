import { EOL, EOL_IMAGES } from './eol-data';
import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored } from './types';

/*
 * Supply-chain checks on the files that build and ship the code: Dockerfiles and GitHub Actions
 * workflows. Line-based on purpose: both formats are line-oriented, and neither needs a parser.
 * Silence a reviewed line with `# fortis-ignore: <why>`.
 */

export const DOCKERFILE = /(?:^|\/)(?:Dockerfile|Containerfile)(?:\.[\w.-]+)?$|\.dockerfile$/i;
export const WORKFLOW = /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(?:^|\/)action\.ya?ml$/i;

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string, fix?: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
  ...(fix ? { fix } : {}),
});

/* ---------------------------------------------------------------- Dockerfiles */

export type BaseImage = { line: number; image: string; registry: string; name: string; tag: string | null; digest: string | null };

/** Dev, test and example images aren't what customers' data runs on. */
const NOT_PRODUCTION = /(?:^|[/.\-_])(?:dev|devel|development|test|tests|testing|local|debug|ci|e2e|example|examples|sample|samples|demo|devcontainer)(?:[/.\-_]|$)/i;
export const isProductionDockerfile = (path: string) => !NOT_PRODUCTION.test(path.replace(/(?:Dockerfile|Containerfile)$/i, ''));

/** Every `FROM` in a Dockerfile, with build arguments filled in where their default is known. Stages and scratch are left out. */
export function baseImages(file: SourceFile): BaseImage[] {
  const args = new Map<string, string>();
  const stages = new Set<string>();
  const out: BaseImage[] = [];
  for (let i = 0; i < file.lines.length; i++) {
    const start = i;
    let text = file.lines[i]!.replace(/\s+#.*$/, '');
    // Continuation lines: `FROM \` then the image on the next line.
    while (/\\\s*$/.test(text) && i + 1 < file.lines.length) text = text.replace(/\\\s*$/, ' ') + file.lines[++i]!;
    const arg = /^\s*ARG\s+(\w+)(?:=("?)([^"\s]*)\2)?/i.exec(text);
    if (arg) {
      if (arg[3] !== undefined && !args.has(arg[1]!)) args.set(arg[1]!, arg[3]);
      continue;
    }
    const from = /^\s*FROM\s+(?:--\w+(?:=\S+)?\s+)*(\S+)(?:\s+AS\s+(\S+))?/i.exec(text);
    if (!from) continue;
    if (from[2]) stages.add(from[2].toLowerCase());
    let ref = from[1]!;
    let unknown = false;
    ref = ref.replace(/\$\{(\w+)(?::?-([^}]*))?\}|\$(\w+)/g, (_, braced: string | undefined, fallback: string | undefined, bare: string | undefined) => {
      const value = args.get((braced ?? bare)!) ?? fallback;
      if (value === undefined || value === '') unknown = true;
      return value ?? '';
    });
    // An image named by a build argument with no default can't be judged from the file.
    if (unknown || stages.has(ref.toLowerCase()) || ref.toLowerCase() === 'scratch') continue;
    const at = ref.indexOf('@');
    const digest = at === -1 ? null : ref.slice(at + 1);
    const withoutDigest = at === -1 ? ref : ref.slice(0, at);
    const slash = withoutDigest.indexOf('/');
    const first = slash === -1 ? '' : withoutDigest.slice(0, slash);
    const hasRegistry = /[.:]/.test(first) || first === 'localhost';
    const registry = hasRegistry ? first : '';
    const path = hasRegistry ? withoutDigest.slice(slash + 1) : withoutDigest;
    const colon = path.lastIndexOf(':');
    const name = (colon === -1 ? path : path.slice(0, colon)).replace(/^library\//, '');
    const tag = colon === -1 ? null : path.slice(colon + 1);
    out.push({ line: start + 1, image: ref, registry: registry === 'docker.io' || registry === 'index.docker.io' ? '' : registry, name, tag, digest });
  }
  return out;
}

/** SUP-IMG-001: a base image with no tag, or `latest`, changes underneath the build. */
export const imageTagRule: FileRule = {
  id: 'SUP-IMG-001',
  pack: 'dependencies',
  appliesTo: DOCKERFILE,
  skipTests: true,
  run(file) {
    return baseImages(file)
      .filter((b) => (b.tag === null || b.tag === 'latest') && !b.digest && !isIgnored(file, b.line))
      .map((b) => hit(file, b.line, 'SUP-IMG-001', 'low', `Base image ${b.tag ? 'uses latest' : 'has no tag'}`, `Pin ${b.name} to a release, for example ${b.name}:<version>, and better still to its digest (${b.name}:<version>@sha256:...).`));
  },
};

/** SUP-IMG-002: a production image pinned by tag only. Tags can be moved to point at other images. */
export const imageDigestRule: FileRule = {
  id: 'SUP-IMG-002',
  pack: 'dependencies',
  appliesTo: DOCKERFILE,
  skipTests: true,
  run(file) {
    if (!isProductionDockerfile(file.path)) return [];
    return baseImages(file)
      .filter((b) => b.tag !== null && b.tag !== 'latest' && !b.digest && !isIgnored(file, b.line))
      .map((b) => hit(file, b.line, 'SUP-IMG-002', 'info', 'Base image not pinned by digest', `Add the digest you've tested: FROM ${b.image}@sha256:<digest> (docker buildx imagetools inspect ${b.image} shows it). Dependabot and Renovate can keep it current.`));
  },
};

/** The release cycle and product an image tag names, such as node:16-alpine → nodejs 16. */
export function releaseOf(b: BaseImage): { product: string; cycle: string }[] {
  const fullName = b.registry ? `${b.registry}/${b.name}` : b.name;
  const product = Object.entries(EOL_IMAGES).find(([, images]) => images.includes(fullName))?.[0];
  const tag = (b.tag ?? '').toLowerCase();
  const out: { product: string; cycle: string }[] = [];
  if (product && tag) {
    const version = /^v?(\d+)(?:\.(\d+))?/.exec(tag);
    if (version) {
      // Node, .NET and Debian releases are numbered by major version; the rest by major.minor.
      const byMajor = product === 'nodejs' || product === 'dotnet' || product === 'debian';
      const cycle = byMajor ? version[1]! : version[2] !== undefined ? `${version[1]}.${version[2]}` : version[1]!;
      out.push({ product, cycle });
    } else if (product === 'debian' || product === 'ubuntu') {
      out.push({ product, cycle: tag.split(/[-.]/)[0]! });
    }
  }
  // The OS under a language image: node:18-bullseye, python:3.11-alpine3.17
  for (const part of tag.split('-')) {
    if (product !== 'debian' && EOL.debian?.some((r) => r[2] === part)) out.push({ product: 'debian', cycle: part });
    if (product !== 'ubuntu' && EOL.ubuntu?.some((r) => r[2] === part)) out.push({ product: 'ubuntu', cycle: part });
    const alpine = /^alpine(\d+\.\d+)$/.exec(part);
    if (alpine && product !== 'alpine-linux') out.push({ product: 'alpine-linux', cycle: alpine[1]! });
  }
  return out;
}

const PRODUCT_NAMES: Record<string, string> = {
  nodejs: 'Node.js',
  python: 'Python',
  debian: 'Debian',
  ubuntu: 'Ubuntu',
  'alpine-linux': 'Alpine',
  go: 'Go',
  php: 'PHP',
  ruby: 'Ruby',
  dotnet: '.NET',
};

/** The date a release stopped getting security fixes, if it has. */
export function endOfLife(product: string, cycle: string, now = new Date()): string | null {
  const row = EOL[product]?.find((r) => r[0] === cycle || r[2] === cycle);
  if (!row?.[1]) return null;
  return new Date(`${row[1]}T00:00:00Z`) <= now ? row[1] : null;
}

/** SUP-IMG-003: a base image whose OS or runtime no longer gets security fixes. */
export const imageEolRule: FileRule = {
  id: 'SUP-IMG-003',
  pack: 'dependencies',
  appliesTo: DOCKERFILE,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    for (const b of baseImages(file)) {
      if (isIgnored(file, b.line)) continue;
      for (const { product, cycle } of releaseOf(b)) {
        const date = endOfLife(product, cycle);
        if (!date) continue;
        const name = `${PRODUCT_NAMES[product] ?? product} ${cycle}`;
        out.push(hit(file, b.line, 'SUP-IMG-003', 'medium', `Base image is end-of-life: ${name} (since ${date})`, `${name} no longer gets security fixes. Move ${b.name} to a supported release (see https://endoflife.date/${product}).`));
        break;
      }
    }
    return out;
  },
};

/* ---------------------------------------------------------------- GitHub Actions */

/** Actions from GitHub itself, which the issue leaves out: pinning them is good practice but they aren't third parties. */
const GITHUB_OWNED = /^(?:actions|github)\//i;
const USES = /^(\s*(?:-\s*)?uses:\s*)(["']?)([^"'\s#]+)\2\s*(?:#\s*(.*))?$/;

export type ActionUse = { line: number; action: string; ref: string; comment: string };

/** Every `uses:` in a workflow or composite action that names another repository's action. */
export function actionUses(file: SourceFile): ActionUse[] {
  const out: ActionUse[] = [];
  file.lines.forEach((text, i) => {
    const m = USES.exec(text);
    if (!m) return;
    const target = m[3]!;
    if (target.startsWith('./') || target.startsWith('docker://')) return;
    const at = target.lastIndexOf('@');
    if (at === -1) return;
    out.push({ line: i + 1, action: target.slice(0, at), ref: target.slice(at + 1), comment: (m[4] ?? '').trim() });
  });
  return out;
}

const isCommit = (ref: string) => /^[0-9a-f]{40}$/i.test(ref);

/** SUP-GHA-001: a third-party action pinned to a tag or branch, which its owner (or a thief) can move. */
export const actionPinRule: FileRule = {
  id: 'SUP-GHA-001',
  pack: 'dependencies',
  appliesTo: WORKFLOW,
  skipTests: true,
  run(file) {
    return actionUses(file)
      .filter((u) => !GITHUB_OWNED.test(u.action) && !isCommit(u.ref) && !isIgnored(file, u.line))
      .map((u) => hit(file, u.line, 'SUP-GHA-001', 'medium', 'Third-party action not pinned to a commit', `Pin ${u.action} to the commit SHA of ${u.ref}, keeping the tag as a comment: uses: ${u.action}@<40-character SHA> # ${u.ref}`));
  },
};

/** Ways a job gets the pull request's own code. */
const PR_CODE = /github\.event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|github\.head_ref|refs\/pull\/|\bpull\/\$\{\{|github\.event\.(?:pull_request\.)?number/;

/** SUP-GHA-002: `pull_request_target` runs with secrets and a write token, so it must never run the pull request's code. */
export const pullRequestTargetRule: FileRule = {
  id: 'SUP-GHA-002',
  pack: 'dependencies',
  appliesTo: WORKFLOW,
  skipTests: true,
  run(file) {
    if (!/^\s*(?:on:\s*)?(?:-\s*)?\[?[^#\n]*\bpull_request_target\b/m.test(file.text)) return [];
    const out: Detection[] = [];
    file.lines.forEach((text, i) => {
      if (/^\s*#/.test(text) || isIgnored(file, i + 1)) return;
      const code = text.replace(/\s+#.*$/, '');
      const key = /^\s*(?:-\s*)?([\w-]+):/.exec(code)?.[1];
      // A checkout's `ref:` or `repository:` pointing at the pull request. An `if:` that only compares it is fine.
      const checkout = (key === 'ref' || key === 'repository') && PR_CODE.test(code);
      // A command in a `run:` step that fetches the pull request's code.
      const command = (!key || key === 'run') && (/\bgh\s+pr\s+checkout\b/.test(code) || (/\bgit\s+(?:fetch|checkout|pull|switch)\b/.test(code) && PR_CODE.test(code)));
      if (checkout || command) out.push(hit(file, i + 1, 'SUP-GHA-002', 'high', "pull_request_target workflow checks out the pull request's code"));
    });
    return out;
  },
};

export const SUPPLY_CHAIN_RULES: FileRule[] = [imageTagRule, imageDigestRule, imageEolRule, actionPinRule, pullRequestTargetRule];
