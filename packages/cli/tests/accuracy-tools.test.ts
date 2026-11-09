import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { falsePositiveShapes, lineShape, maskSnippet } from '@fortis/shared';

import { compare, precisionOf, recallOf, scoreRules, type Corpus, type Expected } from '../bench/corpus';
import { candidates, stillFlagged } from '../bench/feedback';
// @ts-expect-error a plain script with no type declarations
import { ISSUE_LABELS, ISSUE_TITLE, plan } from '../scripts/report-nightly.mjs';

describe('the shape of a line', () => {
  it('keeps structure, and removes every name, string and number', () => {
    expect(lineShape('const acmeLoan = await AcmeLoans.findById(req.params.id, 500);')).toBe('const x = await x.findById(req.params.id, 0);');
    expect(lineShape("logger.info('customer jane@acme.ng paid', customer_name);")).toBe('logger.info("…", x);');
    expect(lineShape('total = compute_acme_total(1_000.50)')).toBe('x = x(0)');
  });

  it('drops comments, whatever they say', () => {
    expect(lineShape('const a = 1; // Jane at Acme said this is fine')).toBe('const x = 0;');
    expect(lineShape('x = 1  # internal ticket ACME-123')).toBe('x = 0');
    expect(lineShape('foo(/* acme */ 1)')).toBe('x( 0)');
  });

  it('handles masked secrets and lines cut off mid-string', () => {
    expect(lineShape(maskSnippet(`const k = "${['sk', 'live', 'abcdef0123456789abcdef0123456789'].join('_')}";`))).toBe('const x = "…";');
    expect(lineShape('const k = sk_live_••••6789;')).toBe('const x = "…"');
    expect(lineShape("send('text that gets cut off")).toBe('send("…"');
  });

  it('never lets a customer identifier through', () => {
    const line = "await PaywaveNigeria.creditCustomer('Adaeze Obi', 'adaeze@paywave.ng', 8031234567, acct_0123456789);";
    const shape = lineShape(line);
    for (const leak of ['Paywave', 'Adaeze', 'Obi', 'paywave.ng', '8031234567', 'acct_0123456789', 'creditCustomer']) expect(shape).not.toContain(leak);
  });
});

describe('false-positive shapes', () => {
  const row = (orgId: string, over = {}) => ({ ruleId: 'FX-OWN-001', file: 'src/AcmeLoans.ts', snippet: 'const a = await Loan.findById(req.params.id);', orgId, ...over });

  it('only includes a shape reported by at least two workspaces, without naming them', () => {
    expect(falsePositiveShapes([row('a'), row('a')])).toEqual([]);
    const out = falsePositiveShapes([row('a'), row('b', { snippet: 'const other = await Payment.findById(req.params.id);' })]);
    expect(out).toEqual([{ rule: 'FX-OWN-001', extension: 'ts', shape: 'const x = await x.findById(req.params.id);', workspaces: 2 }]);
    expect(JSON.stringify(out)).not.toMatch(/AcmeLoans|"a"|"b"|orgId/);
  });

  it('keeps rules and extensions apart, and skips findings with no line', () => {
    expect(falsePositiveShapes([row('a'), row('b', { ruleId: 'FX-TXN-001' })])).toEqual([]);
    expect(falsePositiveShapes([row('a'), row('b', { file: 'x.py' })])).toEqual([]);
    expect(falsePositiveShapes([row('a', { snippet: null }), row('b', { snippet: null })])).toEqual([]);
    expect(falsePositiveShapes([row('a')], 1)).toHaveLength(1);
  });
});

describe('turning shapes into candidate cases', () => {
  const shape = (rule: string, extension: string, text: string) => ({ rule, extension, shape: text, workspaces: 3 });

  it('finds shapes the rule still flags, and writes them as files', () => {
    const flagged = shape('FX-PII-002', 'ts', 'console.log(x.bvn);');
    expect(stillFlagged(flagged)).toBe(true);
    const out = candidates([flagged, shape('FX-PII-002', 'ts', 'console.log("…");')]);
    expect(out.flagged).toEqual([flagged]);
    expect(out.other).toBe(1);
    expect(out.files[0]!.text).toContain('console.log(x.bvn);');
    expect(out.files[0]!.path).toMatch(/FX-PII-002[\\/]shape-[0-9a-f]{10}\.ts$/);
  });

  it('copes with a rule or extension it can not run', () => {
    expect(stillFlagged(shape('NOT-A-RULE', 'ts', 'x'))).toBe(false);
    expect(stillFlagged(shape('FX-PII-002', 'java', 'console.log(x.bvn);'))).toBe(false);
  });

  it('uses the comment style of the language', () => {
    const out = candidates([shape('FX-PII-002', 'py', 'logger.info(x.bvn)')]);
    if (out.files[0]) expect(out.files[0].text.startsWith('# ')).toBe(true);
  });
});

describe('comparing corpus findings', () => {
  const e = (rule: string, line: number, verdict: Expected['verdict']): Expected => ({ rule, file: 'a.js', line, verdict });
  const f = (rule: string, line: number) => ({ rule, file: 'a.js', line });

  it('reports what is new, gone or still unreviewed', () => {
    const out = compare([e('A', 1, 'true'), e('A', 2, 'false'), e('B', 3, 'unreviewed')], [f('A', 1), f('B', 3), f('C', 4)]);
    expect(out.unexpected).toEqual([f('C', 4)]);
    expect(out.missing).toEqual([e('A', 2, 'false')]);
    expect(out.unreviewed).toEqual([e('B', 3, 'unreviewed')]);
  });

  it('scores precision and recall from reviewed findings only', () => {
    const scores = scoreRules([{ expected: [e('A', 1, 'true'), e('A', 2, 'false'), e('A', 3, 'true'), e('A', 4, 'unreviewed')], found: [f('A', 1), f('A', 2)] }]);
    expect(scores.A).toEqual({ correct: 1, wrong: 1, missed: 1 });
    expect(precisionOf(scores.A!)).toBe(0.5);
    expect(recallOf(scores.A!)).toBe(0.5);
  });
});

describe('the recorded corpus', () => {
  const corpus = JSON.parse(readFileSync(join(__dirname, '..', 'bench', 'corpus.json'), 'utf8')) as Corpus;

  it('covers every supported language', () => {
    const languages = new Set(corpus.repos.flatMap((r) => r.languages));
    for (const language of ['JavaScript', 'TypeScript', 'Python', 'Java', 'Go', 'PHP', 'C#', 'Ruby', 'Rust', 'Dart']) expect(languages, language).toContain(language);
  });

  it('pins every repository to a full commit', () => {
    for (const r of corpus.repos) expect(r.commit, r.repo).toMatch(/^[0-9a-f]{40}$/);
  });

  it('has every finding reviewed, and holds no code', () => {
    for (const r of corpus.repos) {
      for (const finding of r.findings) {
        expect(['true', 'false'], `${r.repo} ${finding.file}:${finding.line}`).toContain(finding.verdict);
        expect(Object.keys(finding).every((k) => ['rule', 'file', 'line', 'verdict', 'why'].includes(k))).toBe(true);
      }
    }
  });
});

describe('the nightly issue', () => {
  const URL = 'https://github.com/o/r/actions/runs/1';

  it('opens one issue on the first failure, and comments after that', () => {
    const [create] = plan('failure', URL, undefined) as string[][];
    expect(create!.slice(0, 4)).toEqual(['issue', 'create', '--title', ISSUE_TITLE]);
    expect(create).toContain(ISSUE_LABELS[0]);
    expect(create!.join(' ')).toContain(URL);
    expect(plan('failure', URL, 12)).toEqual([['issue', 'comment', '12', '--body', `It failed again: ${URL}`]]);
  });

  it('closes the issue when a run passes, and otherwise stays quiet', () => {
    expect(plan('success', URL, 12)).toEqual([['issue', 'close', '12', '--comment', `The nightly run passes again: ${URL}`]]);
    expect(plan('success', URL, undefined)).toEqual([]);
  });
});
