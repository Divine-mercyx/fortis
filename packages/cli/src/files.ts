import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type { SourceFile } from './rules/types';

const DEFAULT_IGNORES = [
  'node_modules/**', '**/node_modules/**', 'dist/**', 'build/**', 'out/**', '.next/**', 'coverage/**', 'vendor/**',
  '**/*.min.js', '**/*.map', '**/*.lock', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
];
const BINARY = /\.(png|jpe?g|gif|webp|ico|svg|pdf|zip|gz|tgz|jar|woff2?|ttf|otf|eot|mp4|mp3|mov|wasm|exe|dll|so|dylib|bin|sqlite|db)$/i;
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
  const patterns = [...DEFAULT_IGNORES, ...extra].map(globToRegExp);
  return (path: string) => !BINARY.test(path) && !patterns.some((p) => p.test(path));
}

export function loadFiles(root: string, paths: string[], ignore: string[] = []): SourceFile[] {
  const keep = makeFilter(ignore);
  const out: SourceFile[] = [];
  for (const path of paths) {
    if (!keep(path)) continue;
    const abs = join(root, path);
    try {
      const st = statSync(abs);
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      const text = readFileSync(abs, 'utf8');
      if (text.includes('\u0000')) continue;
      out.push({ path, text, lines: text.split(/\r?\n/) });
    } catch {
      /* deleted or unreadable */
    }
  }
  return out;
}
