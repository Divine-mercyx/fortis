declare const __FORTIS_VERSION__: string | undefined;
declare const __FORTIS_API_URL__: string | undefined;

export const VERSION = typeof __FORTIS_VERSION__ === 'string' ? __FORTIS_VERSION__ : '0.0.0-dev';
const DEFAULT_API = typeof __FORTIS_API_URL__ === 'string' ? __FORTIS_API_URL__ : 'http://localhost:4000';

/** API base URL: FORTIS_API_URL, then the project config, then the built-in default. */
export function apiUrl(configured?: string): string {
  return (process.env.FORTIS_API_URL ?? configured ?? DEFAULT_API).replace(/\/+$/, '');
}
