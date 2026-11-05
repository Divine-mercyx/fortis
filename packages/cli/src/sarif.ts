import { findRule, maskSnippet, type Severity } from '@fortis/shared';

import { VERSION } from './env';
import { fingerprintOf } from './baseline';
import type { Detection } from './rules/types';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
/** GitHub code scanning ranks alerts by this CVSS-like score. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };

/** SARIF 2.1.0, the format GitHub code scanning, GitLab and most IDEs read. */
export function toSarif(detections: Detection[]) {
  const ids = [...new Set(detections.map((d) => d.ruleId))];
  const rules = ids.map((id) => {
    const r = findRule(id);
    const sample = detections.find((d) => d.ruleId === id)!;
    return {
      id,
      name: id.replace(/-/g, ''),
      shortDescription: { text: r?.title ?? sample.title },
      fullDescription: { text: r?.summary ?? sample.title },
      help: { text: r ? `${r.summary}\n\nFix: ${r.fix}` : sample.title, markdown: r ? `${r.summary}\n\n**Fix:** ${r.fix}` : sample.title },
      helpUri: `https://fortis.dev/rules/${id}`,
      properties: { tags: ['security', r?.pack ?? 'fortis'], 'security-severity': SECURITY_SEVERITY[r?.severity ?? sample.severity] },
      defaultConfiguration: { level: LEVEL[r?.severity ?? sample.severity] },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'Fortis', semanticVersion: VERSION, informationUri: 'https://fortis.dev', rules } },
        results: detections.map((d) => ({
          ruleId: d.ruleId,
          ruleIndex: ids.indexOf(d.ruleId),
          level: LEVEL[d.severity],
          message: { text: `${d.title}${d.commit ? ` (introduced in commit ${d.commit.slice(0, 7)})` : ''}${d.fix ? `\n\nFix: ${d.fix}` : ''}` },
          ...(d.fixedVersion !== undefined ? { properties: { fixedVersion: d.fixedVersion } } : {}),
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: d.file, uriBaseId: '%SRCROOT%' },
                region: { startLine: Math.max(1, d.line || 1), snippet: { text: maskSnippet(d.snippet).slice(0, 300) } },
              },
            },
          ],
          partialFingerprints: { fortis: fingerprintOf(d) },
          properties: { 'security-severity': SECURITY_SEVERITY[d.severity] },
        })),
      },
    ],
  };
}

const esc = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s: string) => esc(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

/**
 * GitHub Actions workflow commands: findings show as annotations on the pull request's
 * "Files changed" tab. Works on every plan, unlike code scanning on private repositories.
 */
export function githubAnnotations(items: { severity: Severity; ruleId: string; title: string; file?: string; line?: number; message?: string; fix?: string }[], max = 50): string[] {
  return items.slice(0, max).map((d) => {
    const kind = d.severity === 'critical' || d.severity === 'high' ? 'error' : d.severity === 'medium' ? 'warning' : 'notice';
    const props = [d.file ? `file=${escProp(d.file)}` : '', d.file && d.line ? `line=${d.line}` : '', `title=${escProp(`Fortis ${d.ruleId}: ${d.title}`)}`].filter(Boolean).join(',');
    const rule = findRule(d.ruleId);
    return `::${kind} ${props}::${esc(d.message ?? (rule ? `${rule.summary} Fix: ${d.fix ?? rule.fix}` : d.fix ? `Fix: ${d.fix}` : d.title))}`;
  });
}
