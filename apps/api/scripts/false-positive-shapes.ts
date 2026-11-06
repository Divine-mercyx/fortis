/**
 * Operator export: code findings marked as false positives across every workspace, as anonymous line
 * shapes for the benchmark. Rule, file extension and shape only, and only shapes that at least two
 * workspaces reported. Feed the result to `pnpm --filter fortis-watchdog feedback`.
 *
 *   DATABASE_URL=... pnpm --filter @fortis/api false-positive-shapes > shapes.json
 */
import { falsePositiveShapes, type FalsePositive } from '@fortis/shared';

import { db, pool } from '../src/db/client';
import { falsePositiveSql } from '../src/modules/findings.routes';

const minArg = process.argv.find((a) => a.startsWith('--min-workspaces='))?.split('=')[1];
const rows = await db.execute(falsePositiveSql);
console.log(JSON.stringify(falsePositiveShapes(rows.rows as FalsePositive[], minArg ? Number(minArg) : undefined), null, 2));
await pool.end();
