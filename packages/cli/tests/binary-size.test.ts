import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// @ts-expect-error a plain script with no type declarations
import { checkSizes, MAX_BINARY, MAX_DOWNLOAD } from '../scripts/check-binary-size.mjs';

const scripts = join(__dirname, '..', 'scripts');

describe('the binary size limit', () => {
  it('passes at the limit and fails over it, for each size', () => {
    expect(checkSizes(MAX_BINARY, MAX_DOWNLOAD)).toEqual([]);
    expect(checkSizes(MAX_BINARY + 1, MAX_DOWNLOAD)[0]).toMatch(/The binary is 60.0 MB/);
    expect(checkSizes(MAX_BINARY, MAX_DOWNLOAD + 1)[0]).toMatch(/The download is 25.0 MB/);
    expect(checkSizes(MAX_BINARY + 1, MAX_DOWNLOAD + 1)).toHaveLength(2);
  });
});

describe('the small Node build', () => {
  const script = readFileSync(join(scripts, 'build-node-runtime.sh'), 'utf8');

  it('removes what the CLI never uses', () => {
    for (const flag of ['--with-intl=small-icu', '--without-npm', '--without-corepack', '--without-inspector', '--without-amaro', '--without-sqlite']) expect(script).toContain(flag);
  });

  it('keeps what the CLI needs: the JIT for scan speed, TLS, and process.report', () => {
    const configure = script.slice(script.indexOf('./configure'), script.indexOf('if [ "$(uname -s)" = Darwin ]'));
    for (const flag of ['--v8-lite-mode', '--without-ssl', '--without-report', '--disable-single-executable-application']) expect(configure).not.toContain(flag);
  });

  it('checks the source it downloads', () => {
    expect(script).toMatch(/NODE_SHA256=[0-9a-f]{64}/);
    expect(script).toContain('FAILED: the Node source checksum');
  });
});

describe('building the binary', () => {
  const build = readFileSync(join(scripts, 'build-binary.mjs'), 'utf8');

  it('makes the blob with the same Node it injects into', () => {
    expect(build).toContain('process.env.FORTIS_NODE_RUNTIME');
    expect(build).toContain("run(runtime, ['--experimental-sea-config', config])");
    expect(build).toContain('copyFileSync(runtime, binary)');
  });
});
