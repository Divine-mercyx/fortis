import { describe, expect, it } from 'vitest';

import { decodeBase64, genericSecretRule, notebookView, paymentKeyRule } from '../src/rules/secrets';
import { emptyContext, type Detection, type SourceFile } from '../src/rules/types';

/*
 * Secrets that line-by-line matching can't read: notebooks (JSON-escaped cells), PEM blocks on one
 * line inside JSON, base64 values and Kubernetes Secret manifests. Key-shaped values are built at
 * runtime so this file doesn't trip secret scanners.
 */
const j = (...parts: string[]) => parts.join('');
const PAYSTACK = j('sk_live_', '0123456789abcdef'.repeat(3).slice(0, 40));
const GITHUB = j('ghp_', 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU1vW0xYz1234');
const BEGIN = ['-----BEGIN', 'PRIVATE KEY-----'].join(' ');
const PEM = [BEGIN, 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7', '-----END PRIVATE KEY-----', ''].join('\n');
const b64 = (s: string) => Buffer.from(s).toString('base64');

const file = (path: string, text: string): SourceFile => ({ path, text, lines: text.split(/\r?\n/) });
const findings = (path: string, text: string): Detection[] => {
  const f = file(path, text);
  return [...paymentKeyRule.run(f, emptyContext()), ...genericSecretRule.run(f, emptyContext())];
};
const summary = (list: Detection[]) => list.map((d) => `${d.ruleId}@${d.line} ${d.title}`);

describe('notebooks', () => {
  const nb = (cells: unknown[], indent?: number) => JSON.stringify({ cells, metadata: {}, nbformat: 4, nbformat_minor: 5 }, null, indent);

  it('reads cells as code, so an escaped assignment is named properly', () => {
    const text = nb([{ cell_type: 'code', source: 'import os\npassword = "Zx9qLm2Vb7Rt4Wk8Np3Hs6Jd"\n', outputs: [] }]); // fortis-ignore: test input
    expect(summary(findings('analysis.ipynb', text))).toEqual(['SEC-GEN-001@1 Hard-coded password']);
  });

  it('points at the notebook line, with outputs written before the source as Jupyter does', () => {
    const text = nb([
      { cell_type: 'code', outputs: [{ output_type: 'stream', name: 'stdout', text: ['ok\n'] }], source: ['x = 1\n'] },
      { cell_type: 'code', outputs: [{ output_type: 'stream', name: 'stdout', text: [`token is ${GITHUB}\n`] }], source: ['print(token)\n'] },
    ], 1);
    const lines = text.split('\n');
    const at = lines.findIndex((l) => l.includes(GITHUB)) + 1;
    expect(summary(findings('analysis.ipynb', text))).toEqual([`SEC-GEN-001@${at} GitHub token in code`]);
  });

  it('reads text outputs and tracebacks, and skips images', () => {
    const png = Buffer.alloc(3000, 7).toString('base64');
    const view = notebookView(file('a.ipynb', nb([{ cell_type: 'code', source: [], outputs: [{ output_type: 'error', traceback: ['Error: bad key'] }, { output_type: 'display_data', data: { 'image/png': png, 'text/plain': ['<Figure>'] } }] }])))!;
    expect(view.file.lines).toContain('Error: bad key');
    expect(view.file.lines).toContain('<Figure>');
    expect(view.file.text).not.toContain(png.slice(0, 50));
  });

  it('honours fortis-ignore written in a cell', () => {
    const text = nb([{ cell_type: 'code', source: [`KEY = "${GITHUB}"  # fortis-ignore\n`], outputs: [] }], 1);
    expect(findings('a.ipynb', text)).toEqual([]);
  });

  it('falls back to the raw text when a notebook is not valid JSON', () => {
    const text = `{"cells": [{"source": ["API_KEY = \\"Zx9qLm2Vb7Rt4Wk8Np3Hs6Jd\\"\\n"]`;
    expect(summary(findings('broken.ipynb', text))).toEqual(['SEC-GEN-001@1 Hard-coded API_KEY']);
  });
});

describe('PEM blocks on one line in JSON', () => {
  const json = (pem: string) => `{"private_key": ${JSON.stringify(pem)}}`;

  it('reports a key with key material in it', () => {
    expect(summary(findings('deploy.json', json(PEM)))).toEqual(['SEC-GEN-001@1 Private key in code']);
    expect(summary(findings('deploy.json', json(PEM.replace(/PRIVATE KEY/g, 'ENCRYPTED PRIVATE KEY'))))).toEqual(['SEC-GEN-001@1 Encrypted private key in code']);
  });

  it('leaves documentation placeholders alone', () => {
    for (const body of ['...', '<your private key>', 'YOUR_KEY_HERE', '']) {
      expect(findings('README.json', json(`-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`)), body).toEqual([]);
    }
  });

  it('still reports a key file, and a key built up over several string lines', () => {
    expect(summary(findings('server.key.txt', PEM))).toEqual(['SEC-GEN-001@1 Private key in code']);
    const concat = `const key =\n  "${BEGIN}\\n" +\n  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\\n" +\n  "-----END PRIVATE KEY-----";`;
    expect(summary(findings('key.ts', concat))).toEqual(['SEC-GEN-001@2 Private key in code']);
  });
});

describe('base64 values', () => {
  it('decodes text and refuses bytes, short values and oversized ones', () => {
    expect(decodeBase64(b64(GITHUB))).toBe(GITHUB);
    expect(decodeBase64(Buffer.from(GITHUB).toString('base64url'))).toBe(GITHUB);
    expect(decodeBase64(Buffer.alloc(48, 200).toString('base64'))).toBeNull();
    expect(decodeBase64(b64('short'))).toBeNull();
    expect(decodeBase64(b64('a'.repeat(4000)))).toBeNull();
  });

  it('finds a named key inside, and gives it to the rule for that key', () => {
    expect(summary(findings('config.ts', `const k = "${b64(PAYSTACK)}";`))).toEqual(['FX-SEC-001@1 Live Paystack secret key (base64-encoded)']);
    expect(summary(findings('app.env', `GH=${b64(GITHUB)}`))).toEqual(['SEC-GEN-001@1 GitHub token (base64-encoded)']);
    expect(summary(findings('config.ts', `const pem = atob("${b64(PEM)}");`))).toEqual(['SEC-GEN-001@1 Private key (base64-encoded)']);
    expect(summary(findings('config.ts', `const url = "${b64('postgres://app:Sup3rS3cr3tPw@db.prod.example.com/app')}";`))).toEqual(['SEC-GEN-001@1 Database password in a connection URL (base64-encoded)']); // fortis-ignore: test input
  });

  it("doesn't report base64 that holds no key", () => {
    const text = [
      `const banner = "${b64('Plain words that are base64 encoded for transport, nothing more.')}";`,
      `const sri = "sha512-${Buffer.alloc(64, 9).toString('base64')}";`,
      `const img = "data:image/png;base64,${b64(`not a png but ${GITHUB}`)}";`,
    ].join('\n');
    expect(findings('page.ts', text)).toEqual([]);
  });

  it('stops decoding after 200 values in one file', () => {
    const filler = Array.from({ length: 250 }, (_, i) => `const v${i} = "${b64(`ordinary text value number ${i} padded out`)}";`);
    const text = [...filler, `const k = "${b64(GITHUB)}";`].join('\n');
    expect(findings('big.ts', text)).toEqual([]);
    expect(findings('small.ts', `const k = "${b64(GITHUB)}";`)).toHaveLength(1);
  });
});

describe('Kubernetes Secret manifests', () => {
  const secret = (data: string, extra = '') => `apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ntype: Opaque\n${extra}data:\n${data}`;

  it('reports credential values, decoded, and leaves names, hosts and placeholders alone', () => {
    const text = secret([`  username: ${b64('admin')}`, `  host: ${b64('db.internal')}`, `  password: ${b64('Zx9qLm2Vb7Rt4Wk8')}`, `  api-key: ""`, `  token: ${b64('changeme')}`].join('\n'));
    expect(summary(findings('k8s/secret.yaml', text))).toEqual(['SEC-GEN-001@9 Kubernetes Secret value for password committed to the repository']);
  });

  it('names the key when it recognises it, and reads stringData as plain text', () => {
    const text = secret(`  PAYSTACK_SECRET_KEY: ${b64(PAYSTACK)}\n  tls.key: ${b64(PEM)}\n`, `stringData:\n  GITHUB_TOKEN: ${GITHUB}\n`);
    expect(summary(findings('k8s/secret.yaml', text)).sort()).toEqual([
      'FX-SEC-001@9 Live Paystack secret key in a Kubernetes Secret (base64)',
      'SEC-GEN-001@10 Private key in a Kubernetes Secret (base64)',
      'SEC-GEN-001@7 GitHub token in a Kubernetes Secret',
    ]);
  });

  it('only reads Secrets: a ConfigMap in the same file, and Helm templates, are left alone', () => {
    const text = [`apiVersion: v1\nkind: ConfigMap\ndata:\n  signing.key: ${b64('Zx9qLm2Vb7Rt4Wk8')}`, '---', secret('  password: {{ .Values.password | b64enc }}\n')].join('\n');
    expect(findings('chart/templates/all.yaml', text)).toEqual([]);
  });
});
