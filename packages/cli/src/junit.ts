import { findRule, maskSnippet, maskText, type Severity } from '@fortis/shared';

import type { Detection } from './rules/types';
import { meetsThreshold } from './scan';

/** Removes characters XML can't hold at all, then escapes the ones with a meaning. */
const xml = (s: string) =>
  s
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

/**
 * JUnit XML for CI systems that show test reports. A finding that blocks the build is a failed test,
 * and one below the threshold is skipped, so it's visible without turning the report red. A clean
 * scan is one passing test, because some systems treat an empty report as an error.
 */
export function toJunit(detections: Detection[], opts: { failOn: Severity; durationMs: number }): string {
  const cases = detections.map((d) => {
    const where = d.line ? `${d.file}:${d.line}` : d.file;
    const name = `${d.ruleId} ${where}`;
    const title = maskText(d.title);
    const open = `    <testcase classname="${xml(d.file)}" name="${xml(name)}" time="0"`;
    if (!meetsThreshold(d.severity, opts.failOn)) return `${open}>\n      <skipped message="${xml(`${d.severity}: ${title}`)}"/>\n    </testcase>`;
    const fix = d.fix ?? findRule(d.ruleId)?.fix;
    const body = [title, maskSnippet(d.snippet).slice(0, 300), fix ? `Fix: ${maskText(fix)}` : ''].filter(Boolean).join('\n');
    return `${open}>\n      <failure message="${xml(`${d.severity}: ${title}`)}" type="${xml(d.ruleId)}">${xml(body)}</failure>\n    </testcase>`;
  });
  const failures = detections.filter((d) => meetsThreshold(d.severity, opts.failOn)).length;
  const skipped = detections.length - failures;
  const time = (opts.durationMs / 1000).toFixed(3);
  const body = cases.length ? cases.join('\n') : '    <testcase classname="fortis" name="Fortis scan" time="0"/>';
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="Fortis" tests="${cases.length || 1}" failures="${failures}" errors="0" skipped="${skipped}" time="${time}">`,
    `  <testsuite name="Fortis" tests="${cases.length || 1}" failures="${failures}" errors="0" skipped="${skipped}" time="${time}">`,
    body,
    '  </testsuite>',
    '</testsuites>',
    '',
  ].join('\n');
}
