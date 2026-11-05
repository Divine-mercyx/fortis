import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type { SourceFile } from './rules/types';

const DEFAULT_IGNORES = [
  'node_modules/**', '**/node_modules/**', 'dist/**', 'build/**', 'out/**', '.next/**', 'coverage/**', 'vendor/**', '**/vendor/**',
  '**/target/**', '**/.gradle/**', '**/__pycache__/**', '**/.venv/**', '**/venv/**', '**/site-packages/**', '**/obj/**',
  '**/*.min.js', '**/*.map', '**/*.lock', 'package-lock.json', '**/package-lock.json', 'pnpm-lock.yaml', '**/pnpm-lock.yaml', 'yarn.lock', '**/packages.lock.json', '**/gradle.lockfile',
];
const BINARY = /\.(png|jpe?g|gif|webp|ico|svg|pdf|zip|gz|tgz|jar|war|ear|class|pyc|phar|nupkg|woff2?|ttf|otf|eot|mp4|mp3|mov|wasm|exe|dll|so|dylib|bin|sqlite|db)$/i;
const MAX_BYTES = 1024 * 1024;

/** Tiny glob: `**` matches across folders, `*` within one. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === '*' && glob[i + 1] === '*') {
      re += '.*';
      i++;
      if (glob[i + 1] === '/') i++;
    } else if (ch === '*') re += '[^/]*';
    else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

export function makeFilter(extra: string[] = []) {
  // Globs and paths written on Windows (src\\legacy\\**) mean the same as with forward slashes.
  const patterns = [...DEFAULT_IGNORES, ...extra].map((g) => globToRegExp(g.replace(/\\/g, '/')));
  return (path: string) => {
    const p = path.replace(/\\/g, '/');
    return !BINARY.test(p) && !patterns.some((re) => re.test(p));
  };
}

/** One file, ready for the rules; null when it is missing, a folder, too big (over 1 MB) or binary. */
export function readSource(root: string, path: string): SourceFile | null {
  try {
    const abs = join(root, path);
    const st = statSync(abs);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    const text = readFileSync(abs, 'utf8');
    if (text.includes('\u0000')) return null;
    return { path, text, lines: text.split(/\r?\n/) };
  } catch {
    return null; // deleted or unreadable
  }
}

export function loadFiles(root: string, paths: string[], ignore: string[] = []): SourceFile[] {
  const keep = makeFilter(ignore);
  return paths.filter(keep).map((p) => readSource(root, p)).filter((f): f is SourceFile => f !== null);
}
