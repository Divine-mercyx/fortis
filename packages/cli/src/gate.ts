import { c, sevColour } from './ui';

/** The release gate verdict the API returns with an upload (Plus and Enterprise). */
export type GateVerdict =
  | {
      enforced: true;
      status: 'passed' | 'failed' | 'excepted';
      policy: { minSeverity: string; blockLiveSecrets: boolean };
      blockingCount: number;
      blocking: { findingId: string; ruleId: string; severity: string; title: string; file: string; line: number | null; liveSecret: boolean }[];
      exception?: { reason: string; by: string | null; expiresAt: string; commit: string | null };
      manageUrl: string;
    }
  | { enforced: false; reason: string };

/**
 * The scan's exit code. An enforced gate decides it: the policy set in the dashboard, not --fail-on, says
 * whether this CI run may go out. Otherwise (no gate, Free or Core, upload failed) the local threshold decides.
 */
export function exitCode(gate: GateVerdict | undefined | null, localBlocking: number): number {
  if (gate?.enforced) return gate.status === 'failed' ? 1 : 0;
  return localBlocking ? 1 : 0;
}

/** Lines that explain the verdict in the CI log. */
export function gateLines(gate: GateVerdict): string[] {
  if (!gate.enforced) return [];
  const level = gate.policy.minSeverity === 'medium' ? 'medium or above' : gate.policy.minSeverity === 'high' ? 'high or critical' : 'critical';
  const rule = `${level} findings${gate.policy.blockLiveSecrets ? ' and live leaked keys' : ''}`;
  const where = (b: { file: string; line: number | null }) => (b.line ? `${b.file}:${b.line}` : b.file);
  const list = gate.blocking.slice(0, 10).map((b) => `    ${sevColour[b.severity]?.(b.severity.toUpperCase()) ?? b.severity}  ${b.title}${b.liveSecret ? c.red(' (live key)') : ''}  ${c.grey(where(b))}`);
  const more = gate.blockingCount > 10 ? [c.grey(`    …and ${gate.blockingCount - 10} more`)] : [];
  if (gate.status === 'passed') return [c.green(`✔ Release gate passed`) + c.grey(` (blocks ${rule})`)];
  if (gate.status === 'excepted') {
    const e = gate.exception!;
    return [
      c.yellow(`! Release gate: ${gate.blockingCount} open finding${gate.blockingCount === 1 ? '' : 's'} would block this release, but ${e.by ?? 'an admin'} approved it.`),
      c.grey(`  Reason: ${e.reason}`),
      c.grey(`  Approval ends ${new Date(e.expiresAt).toUTCString()}${e.commit ? ` and covers commit ${e.commit} only` : ''}.`),
      ...list,
      ...more,
    ];
  }
  return [
    c.red(c.bold(`✖ Release gate failed: ${gate.blockingCount} open finding${gate.blockingCount === 1 ? '' : 's'} at the level this project blocks (${rule}).`)),
    ...list,
    ...more,
    c.grey(`  Fix them, mark them as accepted with a reason, or ask an admin to approve this release: ${gate.manageUrl}`),
  ];
}
