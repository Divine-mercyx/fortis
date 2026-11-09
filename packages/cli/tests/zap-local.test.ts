import { describe, expect, it } from 'vitest';

import { chooseZapEngine, findLocalZap, localZapCommand, zapPlan } from '../src/dast';

const has = (...paths: string[]) => (p: string) => paths.includes(p);

describe('finding a local ZAP', () => {
  it('finds the usual install folder on each system', () => {
    expect(findLocalZap({}, 'darwin', has('/Applications/ZAP.app/Contents/Java/zap.sh'), '/Users/a')).toBe('/Applications/ZAP.app/Contents/Java/zap.sh');
    expect(findLocalZap({}, 'darwin', has('/Users/a/Applications/ZAP.app/Contents/Java/zap.sh'), '/Users/a')).toBe('/Users/a/Applications/ZAP.app/Contents/Java/zap.sh');
    expect(findLocalZap({}, 'linux', has('/usr/share/zaproxy/zap.sh'))).toBe('/usr/share/zaproxy/zap.sh');
    expect(findLocalZap({}, 'linux', has('/snap/bin/zaproxy'))).toBe('/snap/bin/zaproxy');
    const bat = 'C:\\Program Files\\ZAP\\Zed Attack Proxy\\zap.bat';
    expect(findLocalZap({ ProgramFiles: 'C:\\Program Files' }, 'win32', has(bat))).toBe(bat);
  });

  it('prefers PATH, and FORTIS_ZAP_PATH over everything', () => {
    expect(findLocalZap({ PATH: '/opt/bin:/usr/bin' }, 'linux', has('/usr/bin/zap.sh', '/usr/share/zaproxy/zap.sh'))).toBe('/usr/bin/zap.sh');
    expect(findLocalZap({ Path: 'D:\\tools;C:\\x' }, 'win32', has('D:\\tools\\zap.bat'))).toBe('D:\\tools\\zap.bat');
    expect(findLocalZap({ FORTIS_ZAP_PATH: '/custom/zap.sh', PATH: '/usr/bin' }, 'linux', has('/custom/zap.sh', '/usr/bin/zap.sh'))).toBe('/custom/zap.sh');
    expect(findLocalZap({ FORTIS_ZAP_PATH: '/missing/zap.sh' }, 'linux', has('/usr/share/zaproxy/zap.sh'))).toBeNull();
  });

  it('returns null when ZAP is not installed', () => {
    expect(findLocalZap({ PATH: '/usr/bin' }, 'linux', () => false)).toBeNull();
  });
});

describe('choosing how to run ZAP', () => {
  const up = () => ({ ok: true as const });
  const down = () => ({ ok: false as const, reason: 'Docker is not installed.' });

  it('uses Docker when it is available, even with a local ZAP installed', () => {
    expect(chooseZapEngine({}, up, () => '/usr/bin/zap.sh')).toEqual({ kind: 'docker' });
  });

  it('falls back to a local ZAP when Docker is not available', () => {
    expect(chooseZapEngine({}, down, () => '/usr/bin/zap.sh')).toEqual({ kind: 'local', path: '/usr/bin/zap.sh' });
  });

  it('gives the Docker reason when neither is available', () => {
    expect(chooseZapEngine({}, down, () => null)).toEqual({ kind: 'none', reason: 'Docker is not installed.' });
  });

  it('honours FORTIS_ZAP_PATH over Docker, and reports a wrong path', () => {
    expect(chooseZapEngine({ FORTIS_ZAP_PATH: '/z/zap.sh' }, up, () => '/z/zap.sh')).toEqual({ kind: 'local', path: '/z/zap.sh' });
    expect(chooseZapEngine({ FORTIS_ZAP_PATH: '/z/zap.sh' }, up, () => null)).toMatchObject({ kind: 'none', reason: expect.stringContaining('/z/zap.sh') });
  });
});

describe('the local ZAP plan', () => {
  const types = (p: ReturnType<typeof zapPlan>) => p.jobs.map((j) => j.type);
  const base = { target: 'https://staging.x.ng', minutes: 2, reportDir: '/tmp/w' };

  it('sends no attacks in baseline mode', () => {
    expect(types(zapPlan({ ...base, mode: 'baseline' }))).toEqual(['spider', 'passiveScan-wait', 'report']);
  });

  it('adds the active scan only in full mode and for OpenAPI', () => {
    expect(types(zapPlan({ ...base, mode: 'full' }))).toEqual(['spider', 'passiveScan-wait', 'activeScan', 'passiveScan-wait', 'report']);
    const api = zapPlan({ ...base, mode: 'full', openapi: 'https://staging.x.ng/openapi.json' });
    expect(types(api)).toEqual(['openapi', 'passiveScan-wait', 'activeScan', 'passiveScan-wait', 'report']);
    expect(api.jobs[0]!.parameters).toEqual({ apiUrl: 'https://staging.x.ng/openapi.json', targetUrl: 'https://staging.x.ng' });
  });

  it('stays on the target, and writes the report format the parser reads', () => {
    const plan = zapPlan({ ...base, mode: 'baseline' });
    expect(plan.env.contexts[0]!.includePaths).toEqual(['https://staging\\.x\\.ng.*']);
    expect(plan.jobs.at(-1)!.parameters).toMatchObject({ template: 'traditional-json', reportDir: '/tmp/w', reportFile: 'report.json' });
    expect(plan.jobs[0]!.parameters).toEqual({ maxDuration: 2 });
  });
});

describe('the local ZAP command', () => {
  it('runs zap.sh directly on macOS and Linux', () => {
    expect(localZapCommand('/opt/zap/zap.sh', '/tmp/w/plan.yaml', '/tmp/w/home', 'linux')).toEqual({
      command: '/opt/zap/zap.sh',
      args: ['-cmd', '-autorun', '/tmp/w/plan.yaml', '-dir', '/tmp/w/home', '-silent'],
      windowsVerbatimArguments: false,
    });
  });

  it('runs zap.bat through cmd.exe on Windows, quoting paths with spaces', () => {
    const { command, args, windowsVerbatimArguments } = localZapCommand('C:\\Program Files\\ZAP\\zap.bat', 'C:\\Temp\\w\\plan.yaml', 'C:\\Temp\\w\\home', 'win32');
    expect(command).toBe('cmd.exe');
    expect(windowsVerbatimArguments).toBe(true);
    expect(args.at(-1)).toBe('""C:\\Program Files\\ZAP\\zap.bat" -cmd -autorun "C:\\Temp\\w\\plan.yaml" -dir "C:\\Temp\\w\\home" -silent"');
  });
});
