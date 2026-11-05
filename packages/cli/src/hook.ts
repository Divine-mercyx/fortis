import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

import { INSTALL_URL } from './env';

const MARKER = '# fortis-pre-push';
/**
 * Finds the CLI wherever it was installed: in this project (npm, pnpm, yarn, Yarn Plug'n'Play, a Python
 * virtual environment, uv or Poetry), or globally (any language, no Node needed). A virtual environment
 * usually isn't active when git runs the hook, so being on PATH isn't enough.
 */
// --stdin: git writes the refs being pushed to the hook's stdin; the CLI reads them so a first
// push (new branch, empty remote) checks every new commit, not just the last one.
// Windows: Git runs hooks with its own sh. npm, pnpm and Yarn put a sh shim at .bin/fortis; Bun
// puts fortis.exe there. GUI clients (GitHub Desktop, VS Code) often lack ~/.fortis/bin on PATH, so
// the standalone install is also looked up directly.
const RUN = `if [ -x ./node_modules/.bin/fortis ]; then ./node_modules/.bin/fortis scan --pre-push --stdin
elif [ -f ./node_modules/.bin/fortis.exe ]; then ./node_modules/.bin/fortis.exe scan --pre-push --stdin
elif [ -f ./.pnp.cjs ] && command -v yarn >/dev/null 2>&1; then yarn fortis scan --pre-push --stdin
elif [ -x ./.venv/bin/fortis ]; then ./.venv/bin/fortis scan --pre-push --stdin
elif [ -x ./venv/bin/fortis ]; then ./venv/bin/fortis scan --pre-push --stdin
elif [ -x ./.venv/Scripts/fortis.exe ]; then ./.venv/Scripts/fortis.exe scan --pre-push --stdin
elif [ -x ./venv/Scripts/fortis.exe ]; then ./venv/Scripts/fortis.exe scan --pre-push --stdin
elif command -v fortis >/dev/null 2>&1; then fortis scan --pre-push --stdin
elif [ -x "$HOME/.fortis/bin/fortis" ]; then "$HOME/.fortis/bin/fortis" scan --pre-push --stdin
elif [ -f "$HOME/.fortis/bin/fortis.exe" ]; then "$HOME/.fortis/bin/fortis.exe" scan --pre-push --stdin
elif [ -f ./uv.lock ] && command -v uv >/dev/null 2>&1 && uv run --no-sync fortis --version >/dev/null 2>&1; then uv run --no-sync fortis scan --pre-push --stdin
elif [ -f ./poetry.lock ] && command -v poetry >/dev/null 2>&1 && poetry run fortis --version >/dev/null 2>&1; then poetry run fortis scan --pre-push --stdin
elif npx --no-install fortis --version >/dev/null 2>&1; then npx --no-install fortis scan --pre-push --stdin
else
  echo "Fortis: the CLI isn't installed in this repo, so this push wasn't checked and has been stopped." >&2
  echo "Install it: pip install fortis-watchdog, or npm i -D fortis-watchdog" >&2
  echo "Without Node: curl -fsSL ${INSTALL_URL}/install.sh | sh" >&2
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
  // Git's own answer covers core.hooksPath and worktrees, where .git is a file pointing at the
  // main repository and hooks live in the shared folder. Needs git 2.31+ for --path-format.
  try {
    const p = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-path', 'hooks'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (p) return p;
  } catch {
    /* older git: work it out below */
  }
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
