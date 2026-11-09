// Runs the extension in a real VS Code against a small project with a leaked key.
// Build first: pnpm --filter fortis-security package
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runTests } from '@vscode/test-electron';

const here = dirname(fileURLToPath(import.meta.url));
const workspace = mkdtempSync(join(tmpdir(), 'fortis-editor-'));
const git = (...args) => execFileSync('git', args, { cwd: workspace, stdio: 'ignore' });

// Built at run time, so the repository never holds anything a secret scanner flags.
const key = ['sk', 'live', 'abcdef0123456789abcdef0123456789abcdef01'].join('_');
git('init', '-q');
writeFileSync(join(workspace, 'pay.js'), `const PAYSTACK = "${key}";\n`);
writeFileSync(join(workspace, 'clean.js'), 'const ok = 1;\n');

try {
  await runTests({
    extensionDevelopmentPath: join(here, '..'),
    extensionTestsPath: join(here, 'suite.cjs'),
    extensionTestsEnv: { FORTIS_TEST_KEY: key, FORTIS_KEY: '' },
    launchArgs: [workspace, '--disable-workspace-trust', '--disable-extensions'],
  });
} finally {
  rmSync(workspace, { recursive: true, force: true, maxRetries: 3 });
}
