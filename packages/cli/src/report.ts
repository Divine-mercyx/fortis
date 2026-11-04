import { findRule, maskSnippet, type Severity } from '@fortis/shared';

import type { Detection } from './rules/types';
import type { ScanResult } from './scan';
import { meetsThreshold } from './scan';
import { c, log, sevColour } from './ui';

const LABEL: Record<Severity, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };

export function printReport(result: ScanResult, opts: { failOn: Severity; prePush: boolean; packs: readonly string[] }) {
  const { detections } = result;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const d of detections) counts[d.severity]++;
  const blocking = detections.filter((d) => meetsThreshold(d.severity, opts.failOn));

  log(c.grey(`fortis ▸ ${opts.packs.join(' · ')} rules · ${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'}${result.packagesChecked ? ` · ${result.packagesChecked} packages` : ''} · ${result.durationMs} ms`));
  log('');

  if (!detections.length) {
    // Don't call it a full pass when a check couldn't run (offline, no lockfile, OSV down).
    const skipped = result.incompleteChecks?.includes('dependencies') ?? false;
    if (skipped) log(c.green(c.bold('✓ Nothing found')), c.yellow('· the dependency check did not run (see below)'));
    else log(c.green(c.bold('✓ All checks passed')), c.grey('· nothing found'));
    return;
  }

  const summary = (Object.keys(counts) as Severity[]).filter((s) => counts[s]).map((s) => sevColour[s]!(`${counts[s]} ${s}`)).join(c.grey(' · '));
  if (blocking.length) log(c.bold(c.red(opts.prePush ? '✖ PUSH BLOCKED' : '✖ CHECK FAILED')), c.grey('·'), summary);
  else log(c.yellow(c.bold('▲ Findings to review')), c.grey('·'), summary, c.grey(`(not blocking: threshold is ${opts.failOn})`));
  log('');

  for (const d of detections.slice(0, 50)) printDetection(d);
  if (detections.length > 50) log(c.grey(`  …and ${detections.length - 50} more. Use --json for the full list.`));

  log('');
  if (blocking.length) {
    log(c.grey('Fix the issues above and push again.'));
    log(c.grey('Reviewed and safe? Add  // fortis-ignore  to the line. Emergency only: git push --no-verify'));
  }
}

function printDetection(d: Detection) {
  const rule = findRule(d.ruleId);
  log(`  ${sevColour[d.severity]!(LABEL[d.severity].padEnd(8))} ${c.white(c.bold(d.ruleId))}  ${d.title}`);
  log(`  ${' '.repeat(8)} ${c.cyan(d.line ? `${d.file}:${d.line}` : d.file)}`);
  log(`  ${' '.repeat(8)} ${c.grey(maskSnippet(d.snippet).slice(0, 140))}`);
  if (rule) log(`  ${' '.repeat(8)} ${c.green('fix')} ${rule.fix}`);
  log('');
}

/** Report for a ZAP run: one line per alert type, with where it was seen and how to fix it. */
export function printDastReport(findings: (Omit<Detection, 'line' | 'snippet'> & { detail?: string; urls: string[] })[], opts: { failOn: Severity; origin: string }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  const blocking = findings.filter((f) => meetsThreshold(f.severity, opts.failOn));
  log('');
  if (!findings.length) {
    log(c.green(c.bold('✓ No alerts')), c.grey(`· ${opts.origin}`));
    return;
  }
  const summary = (Object.keys(counts) as Severity[]).filter((s) => counts[s]).map((s) => sevColour[s]!(`${counts[s]} ${s}`)).join(c.grey(' · '));
  if (blocking.length) log(c.bold(c.red('✖ TEST FAILED')), c.grey('·'), summary);
  else log(c.yellow(c.bold('▲ Alerts to review')), c.grey('·'), summary, c.grey(`(not failing: threshold is ${opts.failOn})`));
  log('');
  for (const f of findings.filter((x) => x.severity !== 'info').slice(0, 40)) {
    log(`  ${sevColour[f.severity]!(LABEL[f.severity].padEnd(8))} ${c.white(c.bold(f.ruleId))}  ${f.title}`);
    const more = f.urls.length > 1 ? c.grey(` (+${f.urls.length - 1} more)`) : '';
    log(`  ${' '.repeat(8)} ${c.cyan(f.file)}${more}`);
    const fix = /\n\nFix: ([^\n]+)/.exec(f.detail ?? '')?.[1];
    if (fix) log(`  ${' '.repeat(8)} ${c.green('fix')} ${fix.slice(0, 220)}`);
    log('');
  }
  if (counts.info) log(c.grey(`  ${counts.info} informational alert(s) not shown. Use --json for all.`));
}

export function explain(ruleId: string): boolean {
  const rule = findRule(ruleId.toUpperCase());
  if (!rule) return false;
  log('');
  log(`${sevColour[rule.severity]!(LABEL[rule.severity])}  ${c.bold(rule.id)}  ${c.bold(rule.title)}`);
  log(c.grey(`pack: ${rule.pack}`));
  log('');
  log(c.bold('Why it matters'));
  log(`  ${rule.summary}`);
  log('');
  log(c.bold('How to fix it'));
  log(`  ${rule.fix}`);
  log('');
  log(c.grey('Silence a reviewed line with  // fortis-ignore'));
  return true;
}
