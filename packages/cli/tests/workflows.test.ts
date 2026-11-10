import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const dir = join(__dirname, '..', '..', '..', '.github', 'workflows');
const workflows = readdirSync(dir)
  .filter((f) => f.endsWith('.yml'))
  .map((name) => ({ name, text: readFileSync(join(dir, name), 'utf8') }));
const release = workflows.find((w) => w.name === 'release-cli.yml')!.text;

describe('GitHub workflows', () => {
  it('finds the workflows', () => {
    expect(workflows.length).toBeGreaterThan(2);
  });

  it('pins every action to a full commit SHA, with its version beside it', () => {
    const bad = workflows.flatMap(({ name, text }) =>
      [...text.matchAll(/^\s*(?:- )?uses:\s*(\S+)(.*)$/gm)]
        .filter(([, action]) => !action!.startsWith('./'))
        .filter(([, action, rest]) => !/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/.test(action!) || !/#\s*v\d/.test(rest!))
        .map(([line]) => `${name}: ${line!.trim()}`),
    );
    expect(bad).toEqual([]);
  });

  it('pins every runner to an image version', () => {
    const bad = workflows.flatMap(({ name, text }) => (/\b(ubuntu|macos|windows)-latest\b/.test(text) ? [name] : []));
    expect(bad).toEqual([]);
  });
});

describe('the release workflow', () => {
  const NOTES = /awk -v v="\*\*\$VERSION\*\*" '([^']+)'/;

  it('uses trusted publishing with provenance, and stores no npm token', () => {
    expect(release).toContain('npm publish --provenance');
    expect(release).toContain('id-token: write');
    expect(release).not.toMatch(/NPM_TOKEN|NODE_AUTH_TOKEN/);
  });

  it('skips the npm step cleanly when the version is already published', () => {
    const check = release.indexOf('npm view "fortis-watchdog@$VERSION" version');
    const skip = release.indexOf('exit 0', check);
    const publish = release.indexOf('npm publish --provenance');
    expect(check).toBeGreaterThan(-1);
    expect(check).toBeLessThan(skip);
    expect(skip).toBeLessThan(publish);
  });

  it('takes release notes from the changelog', () => {
    expect(release).toMatch(NOTES);
    expect(release).toContain('--notes-file notes.md');
  });

  it('keeps every install method ahead of anything being published', () => {
    expect(release).toMatch(/binaries:\n\s+needs: \[check, e2e\]/);
    expect(release).toMatch(/npm:\n\s+needs: \[github-release, docker\]/);
  });
});
