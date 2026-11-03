import { randomBase62 } from './crypto';

export function slugify(value: string): string {
  const base = value
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return base || 'org';
}

export const slugWithSuffix = (value: string) => `${slugify(value)}-${randomBase62(5).toLowerCase()}`;
