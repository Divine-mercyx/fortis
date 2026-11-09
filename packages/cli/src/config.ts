import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import type { Severity } from '@fortis/shared';

import { SCHEMA_URL, validateProjectConfig } from './config-schema';

/** Per-repository settings, committed as .fortis.json. Never holds the key. */
export type ProjectConfig = {
  /** Where editors find the schema that autocompletes this file. */
  $schema?: string;
  apiUrl?: string;
  projectId?: string;
  failOn?: Severity;
  ignore?: string[];
  /** Default staging URL for `fortis test`. */
  target?: string;
};

export const PROJECT_CONFIG = '.fortis.json';

const warned = new Set<string>();

/** A typo in the settings used to do nothing, silently. This goes to stderr, so --json stays clean. */
function warnOnce(path: string, config: unknown) {
  if (warned.has(path)) return;
  warned.add(path);
  for (const issue of validateProjectConfig(config)) console.error(`! ${PROJECT_CONFIG}: ${issue.message}`);
}

export function readProjectConfig(root: string): ProjectConfig {
  const p = join(root, PROJECT_CONFIG);
  if (!existsSync(p)) return {};
  try {
    // Windows editors often save JSON with a byte-order mark, which JSON.parse rejects.
    const config = JSON.parse(readFileSync(p, 'utf8').replace(/^\uFEFF/, '')) as ProjectConfig;
    warnOnce(p, config);
    // A wrong type here can't be used, and would otherwise be read one character at a time.
    if (config.ignore !== undefined && !Array.isArray(config.ignore)) delete config.ignore;
    // `src\\legacy\\**` written on Windows means the same as `src/legacy/**`.
    if (Array.isArray(config.ignore)) config.ignore = config.ignore.map((g) => String(g).replace(/\\/g, '/'));
    return config;
  } catch {
    throw new Error(`${PROJECT_CONFIG} is not valid JSON`);
  }
}

export function writeProjectConfig(root: string, config: ProjectConfig) {
  // $schema first, so editors offer autocomplete on the rest.
  writeFileSync(join(root, PROJECT_CONFIG), `${JSON.stringify({ $schema: SCHEMA_URL, ...config }, null, 2)}\n`);
}

/* ---------- User credentials (~/.config/fortis/credentials.json, mode 0600) ---------- */

type Credentials = { keys: Record<string, string> };

export function credentialsPath() {
  const base = process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config');
  return join(base, 'fortis', 'credentials.json');
}

function readCredentials(): Credentials {
  try {
    return JSON.parse(readFileSync(credentialsPath(), 'utf8')) as Credentials;
  } catch {
    return { keys: {} };
  }
}

/** The key for an API: FORTIS_KEY wins (CI), then the saved key from `fortis login`. */
export function resolveKey(api: string): string | undefined {
  return process.env.FORTIS_KEY?.trim() || readCredentials().keys[api];
}

export function saveKey(api: string, key: string) {
  const p = credentialsPath();
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  const creds = readCredentials();
  creds.keys[api] = key;
  writeFileSync(p, `${JSON.stringify(creds, null, 2)}\n`, { mode: 0o600 });
  chmodSync(p, 0o600);
}

export function removeKey(api: string) {
  const creds = readCredentials();
  if (!(api in creds.keys)) return false;
  delete creds.keys[api];
  writeFileSync(credentialsPath(), `${JSON.stringify(creds, null, 2)}\n`, { mode: 0o600 });
  return true;
}
