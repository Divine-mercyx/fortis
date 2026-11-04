import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

import { INSTALL_URL } from './env';

const MARKER = '# fortis-pre-push';
/** Finds the CLI wherever it was installed: in this project (npm, pnpm, yarn), or globally (any language, no Node needed). */
// --stdin: git writes the refs being pushed to the hook's stdin; the CLI reads them so a first
// push (new branch, empty remote) checks every new commit, not just the last one.
const RUN = `if [ -x ./node_modules/.bin/fortis ]; then ./node_modules/.bin/fortis scan --pre-push --stdin
elif command -v fortis >/dev/null 2>&1; then fortis scan --pre-push --stdin
else
  echo "Fortis isn't installed on this machine, so this push wasn't checked and has been stopped." >&2
  echo "Install it: curl -fsSL ${INSTALL_URL}/install.sh | sh" >&2
  echo "On Windows: irm ${INSTALL_URL}/install.ps1 | iex" >&2
  echo "Or skip once: git push --no-verify" >&2
  exit 1
fi`;
/** RUN inside a hook that has other commands: a failure must still stop the push. */
const RUN_WITH_OTHERS = `( ${RUN.replace(/\n/g, '\n  ')} ) || exit 1`;

const HOOK = `#!/bin/sh
${MARKER}
# Installed by Fortis. Checks the files you are about to push. Skip once with: git push --no-verify
${RUN}
`;
/** What earlier versions wrote. They fall back on npx, which needs Node, or miss --stdin. */
const OLD_RUN = /^npx --no-install fortis scan --pre-push(?: --stdin)?(?: \|\| exit 1)?$|^(?:\( )?if \[ -x \.\/node_modules\/\.bin\/fortis \];[\s\S]*?\bfi(?: \) \|\| exit 1)?$/m;

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
      if (current.includes('scan --pre-push --stdin') && !current.includes('npx --no-install')) return { path, status: 'already' };
      // A hook from an earlier version: swap in the current Fortis lines, keep everything else.
      const updated = OLD_RUN.test(current) ? current.replace(OLD_RUN, () => RUN_WITH_OTHERS) : `${current.trimEnd()}\n\n${RUN_WITH_OTHERS}\n`;
      writeFileSync(path, updated);
      chmodSync(path, 0o755);
      return { path, status: 'updated' };
    }
    writeFileSync(path, `${current.trimEnd()}\n\n${MARKER}\n${RUN_WITH_OTHERS}\n`);
    chmodSync(path, 0o755);
    return { path, status: 'appended' };
  }
  writeFileSync(path, HOOK);
  chmodSync(path, 0o755);
  return { path, status: 'installed' };
}
