import type { z } from 'zod';

import { badRequest } from './errors';

export function parse<S extends z.ZodType>(schema: S, value: unknown): z.infer<S> {
  const result = schema.safeParse(value);
  if (!result.success) {
    const issues = result.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message }));
    throw badRequest(issues[0]?.message ?? 'Invalid request', 'VALIDATION_FAILED', issues);
  }
  return result.data;
}
