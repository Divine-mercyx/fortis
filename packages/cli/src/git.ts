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

/** One line of what git gives a pre-push hook on stdin: `<local ref> <local sha> <remote ref> <remote sha>`. */
export type PushedRef = { localRef: string; localSha: string; remoteRef: string; remoteSha: string };

const ZERO_SHA = /^0+$/;

export function parsePushRefs(input: string): PushedRef[] {
  return lines(input)
    .map((l) => l.split(/\s+/))
    .filter((p) => p.length >= 4 && !ZERO_SHA.test(p[1]!)) // deleting a branch pushes nothing
    .map(([localRef, localSha, remoteRef, remoteSha]) => ({ localRef: localRef!, localSha: localSha!, remoteRef: remoteRef!, remoteSha: remoteSha! }));
}

/** Files added or changed by the commits git rev-list would list for these arguments. */
function filesInCommits(root: string, revArgs: string[]): string[] {
  return lines(git(root, ['log', '--name-only', '--format=', '--diff-filter=ACMR', ...revArgs]));
}

/**
 * Files changed by the commits about to be pushed, plus anything uncommitted.
 *
 * From the git hook (`pushed` given): exactly the commits in the push. A new branch, or a
 * first push to an empty remote, covers every commit the remote doesn't have yet, not just the
 * last one. Run by hand: compares with the upstream or default branch, else every commit not
 * on any remote.
 */
export function changedFiles(root: string, pushed?: PushedRef[]): string[] {
  let committed: string[] = [];
  if (pushed?.length) {
    for (const r of pushed) {
      const known = !ZERO_SHA.test(r.remoteSha) && git(root, ['cat-file', '-e', `${r.remoteSha}^{commit}`]) !== null;
      committed.push(...filesInCommits(root, known ? [`${r.remoteSha}..${r.localSha}`] : [r.localSha, '--not', '--remotes']));
    }
  } else {
    const base = ['@{upstream}', 'origin/HEAD', 'origin/main', 'origin/master']
      .map((b) => git(root, ['merge-base', 'HEAD', b]))
      .find(Boolean);
    committed = base
      ? lines(git(root, ['diff', '--name-only', '--diff-filter=ACMR', base, 'HEAD']))
      : filesInCommits(root, ['HEAD', '--not', '--remotes']);
  }
  const working = lines(git(root, ['diff', '--name-only', '--diff-filter=ACMR', 'HEAD']));
  const untracked = lines(git(root, ['ls-files', '--others', '--exclude-standard']));
  return [...new Set([...committed, ...working, ...untracked])];
}
