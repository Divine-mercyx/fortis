import { execFileSync } from 'node:child_process';

function git(cwd: string, args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 }).trim();
  } catch {
    return null;
  }
}

export const repoRoot = (cwd: string) => git(cwd, ['rev-parse', '--show-toplevel']);
/** The branch name, or undefined on a detached HEAD (CI checkouts of a tag or a pull-request merge commit). */
export const currentBranch = (cwd: string) => {
  const b = git(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']);
  return b && b !== 'HEAD' ? b : undefined;
};
export const currentCommit = (cwd: string) => git(cwd, ['rev-parse', 'HEAD']) ?? undefined;

const lines = (out: string | null) => (out ? out.split('\n').map((l) => l.trim()).filter(Boolean) : []);

/** How the checkout is laid out: what a scan can't see, and why. */
export type Checkout = {
  /** A shallow clone (CI's default fetch-depth: 1): history and branch comparisons see only part of it. */
  shallow: boolean;
  /** Paths of submodules (separate repositories inside this one). */
  submodules: string[];
  /** Tracked files a sparse checkout left off disk. */
  notCheckedOut: number;
};

export function checkoutInfo(root: string): Checkout {
  const staged = lines(git(root, ['ls-files', '--stage']));
  return {
    shallow: git(root, ['rev-parse', '--is-shallow-repository']) === 'true',
    // Mode 160000 is a gitlink: the folder belongs to another repository.
    submodules: staged.filter((l) => l.startsWith('160000 ')).map((l) => l.slice(l.indexOf('\t') + 1)),
    // `ls-files -t` marks skip-worktree entries (sparse checkout) with S.
    notCheckedOut: lines(git(root, ['ls-files', '-t'])).filter((l) => l.startsWith('S ')).length,
  };
}

/**
 * Every tracked and untracked-but-not-ignored file that is on disk. Submodules are left out unless
 * asked for (they are other repositories, usually scanned on their own); sparse-checkout entries
 * that aren't on disk are left out.
 */
export function allFiles(root: string, opts: { submodules?: boolean } = {}): string[] {
  const skipped = new Set(lines(git(root, ['ls-files', '-t'])).filter((l) => l.startsWith('S ')).map((l) => l.slice(2)));
  const tracked = lines(git(root, ['ls-files', '--cached', ...(opts.submodules ? ['--recurse-submodules'] : [])]));
  const untracked = lines(git(root, ['ls-files', '--others', '--exclude-standard']));
  const gitlinks = opts.submodules ? new Set<string>() : new Set(checkoutInfo(root).submodules);
  return [...new Set([...tracked, ...untracked])].filter((p) => !skipped.has(p) && !gitlinks.has(p));
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
