// Sets an organisation's plan (e.g. for design partners before billing exists).
// Usage: pnpm --filter @fortis/api exec tsx scripts/set-plan.ts <org-slug> <free|core|plus|enterprise>
import { eq } from 'drizzle-orm';

import { isPlanId } from '@fortis/shared';

import { db, pool } from '../src/db/client';
import { auditLog, organizations } from '../src/db/schema';

const [slug, plan] = process.argv.slice(2);
if (!slug || !plan || !isPlanId(plan)) {
  console.error('Usage: tsx scripts/set-plan.ts <org-slug> <free|core|plus|enterprise>');
  process.exit(1);
}
const [org] = await db.update(organizations).set({ plan }).where(eq(organizations.slug, slug)).returning();
if (!org) {
  console.error(`No organisation with slug "${slug}"`);
  process.exit(1);
}
await db.insert(auditLog).values({ orgId: org.id, action: 'plan.changed', targetType: 'organization', targetId: org.id, meta: { plan, by: 'script' } });
console.log(`${org.name} (${org.slug}) is now on ${plan}`);
await pool.end();
