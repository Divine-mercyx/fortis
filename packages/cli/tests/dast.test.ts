import { describe, expect, it } from 'vitest';

import { isLocalHost, parseZapReport, reportOrigins, stripHtml, zapCommand, type ZapReport } from '../src/dast';

const FAKE_KEY = ['sk', 'live', 'abcdefghijklmnop1234'].join('_');

const report: ZapReport = {
  site: [
    {
      '@name': 'https://staging.paywave.ng',
      alerts: [
        {
          pluginid: '10038',
          alertRef: '10038-1',
          alert: 'Content Security Policy (CSP) Header Not Set',
          riskcode: '2',
          confidence: '3',
          cweid: '693',
          desc: '<p>Content Security Policy (CSP) is an added layer of security.</p><p>It helps detect XSS.</p>',
          solution: '<p>Set the Content-Security-Policy header on every response.</p>',
          instances: [
            { uri: 'https://staging.paywave.ng/login?next=%2Fwallet', method: 'GET' },
            { uri: 'https://staging.paywave.ng/', method: 'GET' },
            { uri: 'https://staging.paywave.ng/login', method: 'GET' },
          ],
        },
        {
          pluginid: '40018',
          alertRef: '40018',
          alert: 'SQL Injection',
          riskcode: '3',
          confidence: '2',
          desc: '<p>SQL injection may be possible.</p>',
          solution: '<p>Use parameterised queries &amp; never build SQL from input.</p>',
          instances: [{ uri: 'https://staging.paywave.ng/api/search?q=1', method: 'GET', param: 'q', evidence: `token=${FAKE_KEY}` }],
        },
        { pluginid: '10096', alertRef: '10096', alert: 'Timestamp Disclosure', riskcode: '0', confidence: '1', instances: [{ uri: 'https://staging.paywave.ng/' }] },
        { pluginid: '10202', alertRef: '10202', alert: 'Absence of Anti-CSRF Tokens', riskcode: '2', confidence: '0', instances: [{ uri: 'https://staging.paywave.ng/' }] },
      ],
    },
  ],
};

describe('ZAP report parsing', () => {
  const findings = parseZapReport(report, 'https://staging.paywave.ng');

  it('maps ZAP risk to severity, sorts by severity and drops alerts ZAP marks false positive', () => {
    expect(findings.map((f) => [f.ruleId, f.severity])).toEqual([
      ['ZAP-40018', 'high'],
      ['ZAP-10038-1', 'medium'],
      ['ZAP-10096', 'info'],
    ]);
  });

  it('groups instances into one finding with paths only, no query strings', () => {
    const csp = findings.find((f) => f.ruleId === 'ZAP-10038-1')!;
    expect(csp.urls).toEqual(['/', '/login']);
    expect(csp.file).toBe('/');
    expect(csp.detail).toContain('Fix: Set the Content-Security-Policy header');
    expect(csp.detail).toContain('Seen on 2 URLs');
    expect(csp.detail).toContain('CWE-693');
    expect(csp.detail).not.toContain('<p>');
  });

  it('keeps a stable fingerprint per alert type and masks secrets in evidence', () => {
    const sqli = findings.find((f) => f.ruleId === 'ZAP-40018')!;
    expect(sqli.fingerprint).toBe('zap:40018');
    expect(sqli.snippet).not.toContain('abcdefghijklmnop1234');
    expect(sqli.detail).toContain('parameterised queries & never');
  });

  it('reads the origins a report covers', () => {
    expect(reportOrigins(report)).toEqual(['https://staging.paywave.ng']);
  });

  it('strips HTML entities and tags', () => {
    expect(stripHtml('<p>a &lt;b&gt;</p><p>c</p>')).toBe('a <b>\nc');
  });
});

describe('ZAP command', () => {
  const base = { target: 'https://staging.paywave.ng', minutes: 2, name: 'n', local: false, platform: 'linux' };

  it('uses the passive baseline script by default and the full scan only when asked', () => {
    expect(zapCommand({ ...base, mode: 'baseline' })).toContain('zap-baseline.py');
    expect(zapCommand({ ...base, mode: 'full' })).toContain('zap-full-scan.py');
    const apiScan = zapCommand({ ...base, mode: 'full', openapi: 'https://staging.paywave.ng/openapi.json' });
    expect(apiScan).toContain('zap-api-scan.py');
    expect(apiScan.join(' ')).toContain('-f openapi');
  });

  it('reaches the host for local runs', () => {
    expect(zapCommand({ ...base, target: 'http://localhost:3000', mode: 'baseline', local: true })).toEqual(
      expect.arrayContaining(['--network', 'host']),
    );
    const mac = zapCommand({ ...base, target: 'http://localhost:3000', mode: 'baseline', local: true, platform: 'darwin' });
    expect(mac).toContain('http://host.docker.internal:3000');
  });

  it('recognises local hosts only', () => {
    expect(['localhost', '127.0.0.1', 'app.localhost'].every(isLocalHost)).toBe(true);
    expect(['staging.paywave.ng', '10.0.0.1', 'localhost.evil.com'].some(isLocalHost)).toBe(false);
  });
});
