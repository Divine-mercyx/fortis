import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

import { INSTALL_URL } from './env';

const MARKER = '# fortis-pre-push';
/** Finds the CLI wherever it was installed: in this project (npm, pnpm, yarn), or globally (any language). */
const RUN = `if [ -x ./node_modules/.bin/fortis ]; then ./node_modules/.bin/fortis scan --pre-push
elif command -v fortis >/dev/null 2>&1; then fortis scan --pre-push
else npx --no-install fortis scan --pre-push; fi`;

const HOOK = `#!/bin/sh
${MARKER}
# Installed by Fortis. Checks the files you are about to push. Skip once with: git push --no-verify
${RUN}
`;
/** What earlier versions wrote. It needs Node, so `fortis init` replaces it. */
const OLD_RUN = /^npx --no-install fortis scan --pre-push(?: \|\| exit 1)?$/m;

function hooksDir(root: string): string {
  try {
    const custom = execFileSync('git', ['config', '--get', 'core.hooksPath'], { cwd: root, encoding: 'utf8' }).trim();
    if (custom) return join(root, custom);
  } catch {
    /* not set */
  }
  return join(root, '.git', 'hooks');
}

export function installHook(root: string): { path: string; status: 'installed' | 'already' | 'appended' | 'upgraded' } {
  const dir = hooksDir(root);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, 'pre-push');
  if (existsSync(path)) {
    const current = readFileSync(path, 'utf8');
    if (OLD_RUN.test(current)) {
      writeFileSync(path, current.replace(OLD_RUN, RUN));
      chmodSync(path, 0o755);
      return { path, status: 'upgraded' };
    }
    if (current.includes(MARKER)) return { path, status: 'already' };
    writeFileSync(path, `${current.trimEnd()}\n\n${MARKER}\n( ${RUN.replace(/\n/g, '\n  ')} ) || exit 1\n`);
    chmodSync(path, 0o755);
    return { path, status: 'appended' };
  }
  writeFileSync(path, HOOK);
  chmodSync(path, 0o755);
  return { path, status: 'installed' };
}
