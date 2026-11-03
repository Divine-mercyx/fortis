/**
 * Operator report: false-positive rate per rule across every workspace, worst first.
 * Rules with a high rate and enough triaged findings are the ones to tune next.
 *
 *   DATABASE_URL=... pnpm --filter @fortis/api rule-health
 */
import { sql } from 'drizzle-orm';

import { db, pool } from '../src/db/client';
import { presentHealth, ruleHealthSql, type RuleHealthRow } from '../src/modules/findings.routes';

const rows = await db.execute(sql`${ruleHealthSql} group by rule_id`);
const orgs = await db.execute(sql`select rule_id as "ruleId", count(distinct org_id)::int as n from findings group by rule_id`);
const orgCount = new Map((orgs.rows as { ruleId: string; n: number }[]).map((r) => [r.ruleId, r.n]));
const health = (rows.rows as RuleHealthRow[]).map(presentHealth).sort((a, b) => (b.falsePositiveRate ?? -1) - (a.falsePositiveRate ?? -1));

console.log(`${'rule'.padEnd(14)}${'orgs'.padStart(5)}${'total'.padStart(7)}${'triaged'.padStart(9)}${'false+'.padStart(8)}${'rate'.padStart(7)}`);
for (const r of health) {
  const rate = r.falsePositiveRate === null ? '–' : `${Math.round(r.falsePositiveRate * 100)}%`;
  const flag = r.falsePositiveRate !== null && r.falsePositiveRate >= 0.2 && r.triaged >= 10 ? '  ← tune' : '';
  console.log(`${r.ruleId.padEnd(14)}${String(orgCount.get(r.ruleId) ?? 0).padStart(5)}${String(r.total).padStart(7)}${String(r.triaged).padStart(9)}${String(r.falsePositive).padStart(8)}${rate.padStart(7)}${flag}`);
}
await pool.end();
