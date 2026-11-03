import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { MAX_FINDINGS_PER_SCAN, RULE_CATALOG, SEVERITIES, type RulePack, type Severity } from '@fortis/shared';

import { ApiError, client, toUpload, type CliTarget, type WhoAmI } from './api';
import { BASELINE_FILE, readBaseline, splitByBaseline, writeBaseline } from './baseline';
import { detectProvider, writeCi, type CiProvider } from './ci';
import { scanHistory } from './history';
import { githubAnnotations, toSarif } from './sarif';
import { dockerAvailable, isLocalHost, parseZapReport, reportOrigins, runZap, waitForTarget, ZAP_IMAGE, type DastFinding, type ZapAuth, type ZapReport } from './dast';
import { PROJECT_CONFIG, readProjectConfig, removeKey, resolveKey, saveKey, writeProjectConfig } from './config';
import { apiUrl, VERSION } from './env';
import { currentBranch, currentCommit, repoRoot } from './git';
import { installHook } from './hook';
import { explain, printDastReport, printReport } from './report';
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
  fortis test --target <url> [options]               ZAP test of a running staging app
  fortis baseline                                    accept today's findings so only new ones block
  fortis ci init [--provider github|gitlab]          write a CI workflow (scan on PRs, test staging)
  fortis explain <RULE-ID>                           why a rule matters and how to fix it
  fortis rules                                       list every rule

${c.bold('Scan options')}
  --pre-push       only files in the commits being pushed (used by the git hook)
  --ci             full scan for CI: closes findings that are fixed
  --fail-on <sev>  block at this severity or above (default: critical)
  --json           print machine-readable results
  --no-upload      keep results on this machine
  --offline        skip the network (no dependency check, no upload)
  --history        also search all git history for secrets (deleted keys still need rotating)
  --sarif <file>   write SARIF for GitHub code scanning, GitLab and IDEs
  --no-baseline    block on every finding, ignoring ${BASELINE_FILE}

${c.bold('Test options')}  ${c.grey('(needs Docker; the target must be verified and authorised in the dashboard)')}
  --target <url>   staging URL to test (or set it once as "target" in .fortis.json)
  --mode <m>       baseline: passive checks, no attacks (default) · full: active scan (Fortis Plus)
  --openapi <url>  scan every operation in an OpenAPI spec (active, counts as full)
  --minutes <n>    how long to crawl (default 2)
  --local          test localhost on this machine; results stay local
  --zap-report <f> import a ZAP JSON report you ran yourself instead of running Docker
  --fail-on <sev>  fail at this severity or above (default: high)
  --wait <s>       wait up to s seconds for the target to come up (after a deploy)
  logged in        set FORTIS_ZAP_AUTH to a test user's token ("Bearer …" is added if missing);
                   FORTIS_ZAP_AUTH_HEADER changes the header (e.g. Cookie). Sent to the target host only.

${c.bold('Environment')}
  FORTIS_KEY       CLI key (preferred in CI)
  FORTIS_API_URL   API address (default: ${apiUrl()})
  FORTIS_ZAP_DOCKER_ARGS  extra docker flags for fortis test (e.g. --add-host for private staging)
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
      else if (['key', 'api', 'fail-on', 'target', 'mode', 'openapi', 'minutes', 'zap-report', 'sarif', 'since', 'provider', 'staging-branch', 'wait'].includes(k) && rest[i + 1] && !rest[i + 1]!.startsWith('--')) flags[k] = rest[++i]!;
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

  if (flags.history) {
    const h = await scanHistory(root, { since: str(flags.since), ignore: config.ignore });
    result.detections.push(...h.detections);
    result.notes.push(`Searched ${h.commitsScanned} commits that added code: ${h.detections.length} found in history. Rotate every one, even if the file was deleted.`);
  }

  const baseline = flags['no-baseline'] ? null : readBaseline(root);
  const { fresh, known } = splitByBaseline(result.detections, baseline);
  if (known.length) result.notes.push(`${known.length} known finding(s) in ${BASELINE_FILE} are not shown and don't block. Fix them over time.`);

  const sarifPath = str(flags.sarif);
  if (sarifPath) writeFileSync(sarifPath, `${JSON.stringify(toSarif(result.detections), null, 2)}\n`);
  if (process.env.GITHUB_ACTIONS === 'true' && !json) {
    for (const line of githubAnnotations(fresh)) log(line);
  }

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
        findings: result.detections.filter((d) => !d.commit).slice(0, MAX_FINDINGS_PER_SCAN).map(toUpload),
      });
      // History findings never auto-close (history doesn't change), so they go up as their own partial scan.
      const historic = result.detections.filter((d) => d.commit);
      if (historic.length) {
        await client(api, key!).upload({
          scanId: randomUUID(),
          trigger: ci ? 'ci' : 'manual',
          scope: 'changed',
          cliVersion: VERSION,
          rulesVersion: who?.rulesVersion,
          findings: historic.slice(0, MAX_FINDINGS_PER_SCAN).map((d) => ({ ...toUpload(d), file: `${d.file} @ ${d.commit!.slice(0, 7)}` })),
        });
      }
    } catch (e) {
      result.notes.push(`Upload failed: ${(e as Error).message}`);
    }
  } else if (key && who && !who.entitlements.uploadFindings && !flags['no-upload']) {
    result.notes.push(`${who.plan.name} keeps results on this machine. Upgrade to sync findings to the dashboard.`);
  }

  const blocking = fresh.filter((d) => meetsThreshold(d.severity, failOn));
  if (json) {
    log(JSON.stringify({ ...result, packs, failOn, blocking: blocking.length, baselined: known.length, upload: uploaded }, null, 2));
  } else {
    printReport({ ...result, detections: fresh }, { failOn, prePush, packs });
    if (uploaded) {
      log(c.grey(`Synced to ${who?.project.name}: ${uploaded.newCount} new · ${uploaded.fixedCount} fixed · ${uploaded.reopenedCount} reopened`));
      log(c.grey(`→ ${uploaded.dashboardUrl}`));
    }
    for (const n of result.notes) log(c.yellow(`! ${n}`));
  }
  return blocking.length ? 1 : 0;
}

async function cmdTest(flags: Flags): Promise<number> {
  const root = repoRoot(process.cwd()) ?? process.cwd();
  const config = readProjectConfig(root);
  const api = apiUrl(str(flags.api) ?? config.apiUrl);
  const json = Boolean(flags.json);
  const rawTarget = str(flags.target) ?? config.target;
  const openapi = str(flags.openapi);
  const mode = (openapi ? 'full' : (str(flags.mode) ?? 'baseline')) as 'baseline' | 'full';
  const failOn = (str(flags['fail-on']) ?? 'high') as Severity;
  const minutes = Math.min(Math.max(Number(str(flags.minutes) ?? 2) || 2, 1), 60);
  const say = (...p: string[]) => (json ? undefined : log(...p));

  if (!rawTarget) {
    err(c.red('✖ Give a target: fortis test --target https://staging.yourapp.com'));
    return 2;
  }
  if (!['baseline', 'full'].includes(mode)) {
    err(c.red('--mode must be baseline or full'));
    return 2;
  }
  if (!SEVERITIES.includes(failOn)) {
    err(c.red(`--fail-on must be one of: ${SEVERITIES.join(', ')}`));
    return 2;
  }
  let origin: string;
  let hostname: string;
  try {
    const u = new URL(rawTarget);
    if (!/^https?:$/.test(u.protocol)) throw new Error('not http');
    origin = u.origin;
    hostname = u.hostname;
  } catch {
    err(c.red(`✖ "${rawTarget}" is not an http(s) URL.`));
    return 2;
  }

  const local = Boolean(flags.local);
  if (local && !isLocalHost(hostname)) {
    err(c.red('✖ --local only tests this machine (localhost, 127.0.0.1, *.localhost).'), c.grey('Add other hosts as targets in the dashboard and verify them.'));
    return 2;
  }

  // Anything that is not this machine must be a verified, authorised target on the project.
  const key = local ? undefined : resolveKey(api);
  let target: CliTarget | undefined;
  const api$ = key ? client(api, key) : null;
  if (!local) {
    if (!api$) {
      err(c.red('✖ No Fortis key found.'), c.grey('Running-app tests need a key so Fortis can confirm you may test this URL. Run: fortis login <key>'));
      return 2;
    }
    try {
      const res = await api$.targets(origin, mode);
      target = res.targets[0];
      if (!target) {
        err(c.red(`✖ ${origin} is not a target on this project.`), c.grey('Add it under Project → Staging targets, verify the domain and authorise testing.'));
        return 2;
      }
      if (target.blocker) {
        err(c.red(`✖ ${target.blocker}`));
        return 2;
      }
    } catch (e) {
      err(c.red(`✖ ${(e as Error).message}`));
      return 2;
    }
  }

  const waitSeconds = Number(str(flags.wait) ?? 0);
  if (waitSeconds > 0 && !str(flags['zap-report'])) {
    const up = await waitForTarget(origin, Math.min(waitSeconds, 3600), json ? undefined : (m) => log(c.grey(m)));
    if (!up) {
      err(c.red(`✖ ${origin} did not come up within ${waitSeconds}s.`));
      return 2;
    }
  }

  // Logged-in testing: a staging test user's credential from the environment (never a flag, so
  // it stays out of shell history and process lists).
  let auth: ZapAuth | undefined;
  const authValue = process.env.FORTIS_ZAP_AUTH?.trim();
  if (authValue) {
    const header = process.env.FORTIS_ZAP_AUTH_HEADER?.trim() || 'Authorization';
    const value = header.toLowerCase() === 'authorization' && !/^(bearer|basic|token)\s/i.test(authValue) ? `Bearer ${authValue}` : authValue;
    auth = { header, value };
  }

  let report: ZapReport;
  const started = Date.now();
  const importFile = str(flags['zap-report']);
  if (importFile) {
    report = JSON.parse(readFileSync(importFile, 'utf8')) as ZapReport;
    const origins = reportOrigins(report);
    if (origins.length && !origins.includes(origin)) {
      err(c.red(`✖ That report is for ${origins.join(', ')}, not ${origin}.`));
      return 2;
    }
  } else {
    const docker = dockerAvailable();
    if (!docker.ok) {
      err(c.red(`✖ ${docker.reason}`));
      err(c.grey('fortis test runs OWASP ZAP in Docker. Install it from https://docs.docker.com/get-docker/'));
      err(c.grey(`Or run ZAP yourself and import the result: fortis test --target ${origin} --zap-report report.json`));
      return 2;
    }
    const label = openapi ? 'API scan (active)' : mode === 'full' ? 'full scan (active)' : 'baseline (passive, no attacks)';
    say(c.grey(`fortis ▸ OWASP ZAP ${label} · ${origin} · ${ZAP_IMAGE}`));
    say(c.grey(`Crawling for up to ${minutes} min${auth ? `, logged in via the ${auth.header} header` : ' as an anonymous visitor (set FORTIS_ZAP_AUTH to test behind login)'}. Pausing the target in the dashboard stops the run.`));
    try {
      const run = await runZap(
        { target: origin, mode, openapi, minutes, local, auth },
        {
          onLine: (l) => {
            if (!json && /^(PASS|WARN|FAIL|Total of|Stopping)/.test(l)) log(c.grey(`  ${l.slice(0, 160)}`));
          },
          shouldStop: api$
            ? async () => {
                const now = (await api$.targets(origin, mode)).targets[0];
                return now ? now.blocker : 'the target was removed';
              }
            : undefined,
        },
      );
      if (run.stopped) {
        err(c.yellow('! The run was stopped from the dashboard. Nothing was uploaded.'));
        return 2;
      }
      report = run.report;
    } catch (e) {
      err(c.red(`✖ ${(e as Error).message}`));
      return 2;
    }
  }

  const findings: DastFinding[] = parseZapReport(report, origin);
  const durationMs = Date.now() - started;
  const blocking = findings.filter((f) => meetsThreshold(f.severity, failOn));
  if (process.env.GITHUB_ACTIONS === 'true' && !json) {
    for (const line of githubAnnotations(findings.filter((f) => f.severity !== 'info').map((f) => ({ ...f, file: undefined, title: `${f.title} at ${origin}${f.file}` })))) log(line);
  }

  let uploaded: Awaited<ReturnType<ReturnType<typeof client>['upload']>> | null = null;
  const notes: string[] = [];
  if (api$ && target && !flags['no-upload']) {
    try {
      uploaded = await api$.upload({
        scanId: randomUUID(),
        trigger: process.env.CI ? 'ci' : 'manual',
        kind: 'dast',
        targetId: target.id,
        dastMode: mode,
        scope: 'full',
        commit: currentCommit(root),
        branch: currentBranch(root),
        cliVersion: VERSION,
        durationMs,
        findings: findings.slice(0, MAX_FINDINGS_PER_SCAN).map(({ urls: _u, confidence: _c, cwe: _w, ...f }) => f),
      });
    } catch (e) {
      notes.push(`Upload failed: ${(e as Error).message}`);
    }
  } else if (local) {
    notes.push('Local run: results stay on this machine.');
  }

  if (json) {
    log(JSON.stringify({ target: origin, mode, failOn, durationMs, findings, blocking: blocking.length, upload: uploaded, notes }, null, 2));
  } else {
    printDastReport(findings, { failOn, origin });
    if (uploaded) {
      log(c.grey(`Synced: ${uploaded.newCount} new · ${uploaded.fixedCount} fixed · ${uploaded.reopenedCount} reopened`));
      log(c.grey(`→ ${uploaded.dashboardUrl}`));
    }
    for (const n of notes) log(c.yellow(`! ${n}`));
  }
  return blocking.length ? 1 : 0;
}

async function resolvePacks(api: string, key: string | undefined): Promise<RulePack[]> {
  if (!key) return FREE_PACKS;
  try {
    return await client(api, key).rulePacks();
  } catch {
    return FREE_PACKS;
  }
}

async function cmdBaseline(flags: Flags): Promise<number> {
  const root = repoRoot(process.cwd()) ?? process.cwd();
  const config = readProjectConfig(root);
  const api = apiUrl(str(flags.api) ?? config.apiUrl);
  const packs = await resolvePacks(api, resolveKey(api));
  const result = await runScan({ root, scope: 'full', packs, ignore: config.ignore, offline: Boolean(flags.offline) });
  const n = writeBaseline(root, result.detections);
  log(c.green('✓'), `Wrote ${BASELINE_FILE} with ${n} known finding(s) (${packs.join(', ')} rules).`);
  log(c.grey('Commit it. From now on only new findings block pushes and CI; the known ones stay visible in the dashboard.'));
  return 0;
}

async function cmdCi(args: string[], flags: Flags): Promise<number> {
  if (args[0] !== 'init') {
    err('Usage: fortis ci init [--provider github|gitlab] [--staging-branch staging] [--target URL] [--force]');
    return 2;
  }
  const root = repoRoot(process.cwd());
  if (!root) {
    err(c.red('✖ Run fortis ci init inside a git repository.'));
    return 2;
  }
  const provider = (str(flags.provider) ?? detectProvider(root)) as CiProvider;
  if (!['github', 'gitlab'].includes(provider)) {
    err(c.red('--provider must be github or gitlab'));
    return 2;
  }
  const stagingBranch = str(flags['staging-branch']) ?? 'staging';
  const res = writeCi(root, provider, { stagingBranch, target: str(flags.target) ?? readProjectConfig(root).target, force: Boolean(flags.force) });
  if (!res.written) {
    err(c.yellow(`! ${res.path} already exists. Use --force to overwrite it.`));
    return 2;
  }
  log(c.green('✓'), `Wrote ${res.path}`);
  log('');
  if (provider === 'github') {
    log(c.bold('Next, in GitHub → Settings → Secrets and variables → Actions:'));
    log(`  secret   ${c.cyan('FORTIS_KEY')}           a CLI key from the Fortis dashboard`);
    log(`  variable ${c.cyan('FORTIS_STAGING_URL')}   your verified staging URL (for the ZAP job)`);
    log(`  secret   ${c.cyan('FORTIS_TEST_TOKEN')}    optional: a staging test user's token, to test behind login`);
  } else {
    log(c.bold('Next:'), `add ${c.cyan('include: [{ local: fortis.gitlab-ci.yml }]')} to .gitlab-ci.yml and set the CI/CD variables`);
    log('  FORTIS_KEY (masked), FORTIS_STAGING_URL, FORTIS_TEST_TOKEN (optional, masked)');
  }
  log(c.grey(`Pull requests get a code scan; pushes to "${stagingBranch}" also get a ZAP test once the deploy is up.`));
  return 0;
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
    case 'test':
      return cmdTest(flags);
    case 'baseline':
      return cmdBaseline(flags);
    case 'ci':
      return cmdCi(args, flags);
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
