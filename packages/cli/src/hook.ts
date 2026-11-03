import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

const MARKER = '# fortis-pre-push';
const HOOK = `#!/bin/sh
${MARKER}
# Installed by Fortis. Checks the files you are about to push. Skip once with: git push --no-verify
npx --no-install fortis scan --pre-push
`;

function hooksDir(root: string): string {
  try {
    const custom = execFileSync('git', ['config', '--get', 'core.hooksPath'], { cwd: root, encoding: 'utf8' }).trim();
    if (custom) return join(root, custom);
  } catch {
    /* not set */
  }
  return join(root, '.git', 'hooks');
}

export function installHook(root: string): { path: string; status: 'installed' | 'already' | 'appended' } {
  const dir = hooksDir(root);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, 'pre-push');
  if (existsSync(path)) {
    const current = readFileSync(path, 'utf8');
    if (current.includes(MARKER)) return { path, status: 'already' };
    writeFileSync(path, `${current.trimEnd()}\n\n${MARKER}\nnpx --no-install fortis scan --pre-push || exit 1\n`);
    chmodSync(path, 0o755);
    return { path, status: 'appended' };
  }
  writeFileSync(path, HOOK);
  chmodSync(path, 0o755);
  return { path, status: 'installed' };
}
