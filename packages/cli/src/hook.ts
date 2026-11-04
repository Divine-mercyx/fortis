import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

import { INSTALL_URL } from './env';

const MARKER = '# fortis-pre-push';
/** Finds the CLI wherever it was installed: in this project (npm, pnpm, yarn, Yarn Plug'n'Play), or globally (any language). */
// --stdin: git writes the refs being pushed to the hook's stdin; the CLI reads them so a first
// push (new branch, empty remote) checks every new commit, not just the last one.
const RUN = `if [ -x ./node_modules/.bin/fortis ]; then ./node_modules/.bin/fortis scan --pre-push --stdin
elif [ -f ./.pnp.cjs ] && command -v yarn >/dev/null 2>&1; then yarn fortis scan --pre-push --stdin
elif command -v fortis >/dev/null 2>&1; then fortis scan --pre-push --stdin
elif npx --no-install fortis --version >/dev/null 2>&1; then npx --no-install fortis scan --pre-push --stdin
else echo "Fortis: the CLI isn't installed in this repo. Run: npm i -D fortis-watchdog (or skip once: git push --no-verify)" >&2; exit 1; fi`;

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

export function installHook(root: string): { path: string; status: 'installed' | 'already' | 'appended' | 'updated' } {
  const dir = hooksDir(root);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, 'pre-push');
  if (existsSync(path)) {
    const current = readFileSync(path, 'utf8');
    if (current.includes(MARKER)) {
      if (current.includes(RUN) || current.includes(RUN.replace(/\n/g, '\n  '))) return { path, status: 'already' };
      // A hook from an earlier version: swap in the current Fortis lines, keep everything else.
      const ours = current.startsWith(`#!/bin/sh\n${MARKER}`);
      const start = current.indexOf(MARKER);
      const endTok = 'fi ) || exit 1';
      const end = current.indexOf(endTok, start);
      const block = `${MARKER}\n( ${RUN.replace(/\n/g, '\n  ')} ) || exit 1`;
      const updated = ours ? HOOK : end === -1 ? `${current.trimEnd()}\n\n${block}\n` : `${current.slice(0, start)}${block}${current.slice(end + endTok.length)}`;
      writeFileSync(path, updated);
      chmodSync(path, 0o755);
      return { path, status: 'updated' };
    }
    writeFileSync(path, `${current.trimEnd()}\n\n${MARKER}\n( ${RUN.replace(/\n/g, '\n  ')} ) || exit 1\n`);
    chmodSync(path, 0o755);
    return { path, status: 'appended' };
  }
  writeFileSync(path, HOOK);
  chmodSync(path, 0o755);
  return { path, status: 'installed' };
}
