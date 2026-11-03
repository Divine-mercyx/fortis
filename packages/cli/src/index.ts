import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { MAX_FINDINGS_PER_SCAN, RULE_CATALOG, SEVERITIES, type RulePack, type Severity } from '@fortis/shared';

import { ApiError, client, toUpload, type WhoAmI } from './api';
import { PROJECT_CONFIG, readProjectConfig, removeKey, resolveKey, saveKey, writeProjectConfig } from './config';
import { apiUrl, VERSION } from './env';
import { currentBranch, currentCommit, repoRoot } from './git';
import { installHook } from './hook';
import { explain, printReport } from './report';
import { meetsThreshold, runScan } from './scan';
import { c, err, log } from './ui';

const FREE_PACKS: RulePack[] = ['secrets', 'dependencies'];

const HELP = `
${c.bold('fortis')} ${c.grey(`v${VERSION}`)}  security checks on every push, for fintech teams

${c.bold('Usage')}
  fortis init [--key fts_…] [--api URL] [--no-hook]   set up this repo and the pre-push hook
  fortis scan [options]                              scan and report (and upload, if your plan syncs)
  fortis login <key> [--api URL]                     save a CLI key on this machine
  fortis logout [--api URL]                          remove the saved key
  fortis whoami                                      show the project and plan for your key
  fortis explain <RULE-ID>                           why a rule matters and how to fix it
  fortis rules                                       list every rule

${c.bold('Scan options')}
  --pre-push       only files in the commits being pushed (used by the git hook)
  --ci             full scan for CI: closes findings that are fixed
  --fail-on <sev>  block at this severity or above (default: critical)
  --json           print machine-readable results
  --no-upload      keep results on this machine
  --offline        skip the network (no dependency check, no upload)

${c.bold('Environment')}
  FORTIS_KEY       CLI key (preferred in CI)
  FORTIS_API_URL   API address (default: ${apiUrl()})
`;

type Flags = Record<string, string | boolean>;

function parseArgs(argv: string[]): { cmd: string; args: string[]; flags: Flags } {
  const [cmd = 'help', ...rest] = argv;
  const args: string[] = [];
  const flags: Flags = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2) as [string, string | undefined];
      if (v !== undefined) flags[k] = v;
      else if (['key', 'api', 'fail-on'].includes(k) && rest[i + 1] && !rest[i + 1]!.startsWith('--')) flags[k] = rest[++i]!;
      else flags[k] = true;
    } else args.push(a);
  }
  return { cmd, args, flags };
}

const str = (v: string | boolean | undefined) => (typeof v === 'string' ? v : undefined);

async function cmdScan(flags: Flags): Promise<number> {
  const root = repoRoot(process.cwd()) ?? process.cwd();
  const config = readProjectConfig(root);
  const api = apiUrl(str(flags.api) ?? config.apiUrl);
  const offline = Boolean(flags.offline);
  const key = offline ? undefined : resolveKey(api);
  const prePush = Boolean(flags['pre-push'] || flags.changed);
  const ci = Boolean(flags.ci || process.env.CI);
  const json = Boolean(flags.json);
  const failOn = (str(flags['fail-on']) ?? config.failOn ?? 'critical') as Severity;
  if (!SEVERITIES.includes(failOn)) {
    err(c.red(`--fail-on must be one of: ${SEVERITIES.join(', ')}`));
    return 2;
  }

  const notes: string[] = [];
  let packs: RulePack[] = FREE_PACKS;
  let who: WhoAmI | null = null;
  if (key) {
    const api$ = client(api, key);
    try {
      [who, packs] = await Promise.all([api$.whoami(), api$.rulePacks()]);
    } catch (e) {
      const ae = e as ApiError;
      if (ae.status === 401) {
        err(c.red(`✖ ${ae.message}`), c.grey('Create a new key in the dashboard, then run: fortis login <key>'));
        return 2;
      }
      notes.push(`Could not load your plan (${ae.message}). Running the free rule packs only.`);
    }
  } else if (!offline) {
    notes.push('No Fortis key found, so only the free secrets and dependency checks ran. Add a key for the fintech rule pack.');
  }

  const result = await runScan({ root, scope: prePush ? 'changed' : 'full', packs, ignore: config.ignore, offline });
  result.notes.unshift(...notes);

  let uploaded: Awaited<ReturnType<ReturnType<typeof client>['upload']>> | null = null;
  const canUpload = Boolean(key && who?.entitlements.uploadFindings && !flags['no-upload'] && !offline);
  if (canUpload) {
    try {
      uploaded = await client(api, key!).upload({
        scanId: randomUUID(),
        trigger: prePush ? 'pre-push' : ci ? 'ci' : 'manual',
        scope: prePush ? 'changed' : 'full',
        commit: currentCommit(root),
        branch: currentBranch(root),
        cliVersion: VERSION,
        rulesVersion: who?.rulesVersion,
        durationMs: result.durationMs,
        filesScanned: result.filesScanned,
        findings: result.detections.slice(0, MAX_FINDINGS_PER_SCAN).map(toUpload),
      });
    } catch (e) {
      result.notes.push(`Upload failed: ${(e as Error).message}`);
    }
  } else if (key && who && !who.entitlements.uploadFindings && !flags['no-upload']) {
    result.notes.push(`${who.plan.name} keeps results on this machine. Upgrade to sync findings to the dashboard.`);
  }

  const blocking = result.detections.filter((d) => meetsThreshold(d.severity, failOn));
  if (json) {
    log(JSON.stringify({ ...result, packs, failOn, blocking: blocking.length, upload: uploaded }, null, 2));
  } else {
    printReport(result, { failOn, prePush, packs });
    if (uploaded) {
      log(c.grey(`Synced to ${who?.project.name}: ${uploaded.newCount} new · ${uploaded.fixedCount} fixed · ${uploaded.reopenedCount} reopened`));
      log(c.grey(`→ ${uploaded.dashboardUrl}`));
    }
    for (const n of result.notes) log(c.yellow(`! ${n}`));
  }
  return blocking.length ? 1 : 0;
}

async function cmdInit(flags: Flags): Promise<number> {
  const root = repoRoot(process.cwd());
  if (!root) {
    err(c.red('✖ Run fortis init inside a git repository.'));
    return 2;
  }
  const existing = readProjectConfig(root);
  const api = apiUrl(str(flags.api) ?? existing.apiUrl);
  const key = str(flags.key) ?? resolveKey(api);
  const config = { ...existing, apiUrl: str(flags.api) ?? existing.apiUrl, failOn: existing.failOn ?? 'critical' };

  if (key) {
    try {
      const who = await client(api, key).whoami();
      if (str(flags.key)) saveKey(api, key);
      config.projectId = who.project.id;
      log(c.green('✓'), `Connected to ${c.bold(who.project.name)} in ${who.org.name} (${who.plan.name})`);
    } catch (e) {
      err(c.red(`✖ ${(e as Error).message}`));
      return 2;
    }
  } else {
    log(c.yellow('!'), 'No key yet. Free checks will run locally. Create a key in the dashboard, then run: fortis login <key>');
  }

  writeProjectConfig(root, Object.fromEntries(Object.entries(config).filter(([, v]) => v !== undefined)));
  log(c.green('✓'), `Wrote ${PROJECT_CONFIG}`);

  if (!flags['no-hook']) {
    const hook = installHook(root);
    log(c.green('✓'), hook.status === 'already' ? 'Pre-push hook already installed' : `Pre-push hook ${hook.status} (${hook.path.replace(root + '/', '')})`);
  }

  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { scripts?: Record<string, string> };
    if (!pkg.scripts?.['security:scan']) {
      pkg.scripts = { ...pkg.scripts, 'security:scan': 'fortis scan --ci' };
      writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
      log(c.green('✓'), 'Added npm script "security:scan" for CI');
    }
  }
  log('');
  log(c.grey('Next: push as usual. In CI, set FORTIS_KEY and run: npm run security:scan'));
  return 0;
}

async function main(): Promise<number> {
  const { cmd, args, flags } = parseArgs(process.argv.slice(2));
  if (flags.version || cmd === '--version' || cmd === '-v') {
    log(VERSION);
    return 0;
  }
  switch (cmd) {
    case 'scan':
      return cmdScan(flags);
    case 'init':
      return cmdInit(flags);
    case 'login': {
      const key = args[0];
      if (!key?.startsWith('fts_')) {
        err(c.red('Usage: fortis login fts_…'));
        return 2;
      }
      const api = apiUrl(str(flags.api) ?? readProjectConfig(repoRoot(process.cwd()) ?? process.cwd()).apiUrl);
      try {
        const who = await client(api, key).whoami();
        saveKey(api, key);
        log(c.green('✓'), `Saved. This key is for ${c.bold(who.project.name)} in ${who.org.name}.`);
        return 0;
      } catch (e) {
        err(c.red(`✖ ${(e as Error).message}`));
        return 2;
      }
    }
    case 'logout': {
      const api = apiUrl(str(flags.api));
      log(removeKey(api) ? `${c.green('✓')} Removed the saved key for ${api}` : `No saved key for ${api}`);
      return 0;
    }
    case 'whoami': {
      const root = repoRoot(process.cwd()) ?? process.cwd();
      const api = apiUrl(readProjectConfig(root).apiUrl);
      const key = resolveKey(api);
      if (!key) {
        err('No key found. Run: fortis login <key>');
        return 2;
      }
      try {
        const who = await client(api, key).whoami();
        log(`${c.bold(who.project.name)} · ${who.org.name} · ${who.plan.name}`);
        log(c.grey(`rule packs: ${who.entitlements.rulePacks.join(', ')} · uploads: ${who.entitlements.uploadFindings ? 'on' : 'off'} · api: ${api}`));
        return 0;
      } catch (e) {
        err(c.red(`✖ ${(e as Error).message}`));
        return 2;
      }
    }
    case 'explain':
      if (!args[0] || !explain(args[0])) {
        err(`Unknown rule. Run ${c.bold('fortis rules')} to list them.`);
        return 2;
      }
      return 0;
    case 'rules':
      for (const r of RULE_CATALOG) log(`${c.bold(r.id.padEnd(12))} ${r.severity.padEnd(9)} ${c.grey(r.pack.padEnd(13))} ${r.title}`);
      return 0;
    case 'help':
    case '--help':
    case '-h':
      log(HELP);
      return 0;
    default:
      err(`Unknown command "${cmd}".`);
      log(HELP);
      return 2;
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    err(c.red(`✖ ${(e as Error).message}`));
    process.exit(2);
  },
);
