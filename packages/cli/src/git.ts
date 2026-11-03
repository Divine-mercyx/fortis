import { execFileSync } from 'node:child_process';

function git(cwd: string, args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 }).trim();
  } catch {
    return null;
  }
}

export const repoRoot = (cwd: string) => git(cwd, ['rev-parse', '--show-toplevel']);
export const currentBranch = (cwd: string) => git(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']) ?? undefined;
export const currentCommit = (cwd: string) => git(cwd, ['rev-parse', 'HEAD']) ?? undefined;

const lines = (out: string | null) => (out ? out.split('\n').map((l) => l.trim()).filter(Boolean) : []);

/** Every tracked and untracked-but-not-ignored file. */
export function allFiles(root: string): string[] {
  return lines(git(root, ['ls-files', '--cached', '--others', '--exclude-standard']));
}

/**
 * Files changed by the commits about to be pushed, plus anything uncommitted.
 * Compares with the upstream branch, falling back to the default branch, then the last commit.
 */
export function changedFiles(root: string): string[] {
  const bases = ['@{upstream}', 'origin/HEAD', 'origin/main', 'origin/master', 'HEAD~1'];
  let committed: string[] = [];
  for (const base of bases) {
    const mergeBase = git(root, ['merge-base', 'HEAD', base]);
    if (mergeBase) {
      committed = lines(git(root, ['diff', '--name-only', '--diff-filter=ACMR', mergeBase, 'HEAD']));
      break;
    }
  }
  const working = lines(git(root, ['diff', '--name-only', '--diff-filter=ACMR', 'HEAD']));
  const untracked = lines(git(root, ['ls-files', '--others', '--exclude-standard']));
  return [...new Set([...committed, ...working, ...untracked])];
}
