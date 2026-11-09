import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { MAX_FINDINGS_PER_SCAN, RULE_CATALOG, maskSnippet, SEVERITIES, type RulePack, type Severity } from '@fortis/shared';

import { ApiError, client, toUpload, type CliTarget, type WhoAmI } from './api';
import { ACCESS_CONFIG, hasWriteChecks, readAccessConfig, runAccessChecks, writeAccessTemplate, type AccessConfig } from './access';
import { checksFromGraphqlSchema, INTROSPECTION_QUERY, schemaFrom } from './access-graphql';
import { checksFromRoutes, routesFromHar, routesFromOpenApi, routesFromPostman, type Route } from './access-import';
import { BASELINE_FILE, readBaseline, splitByBaseline, writeBaseline } from './baseline';
import { CI_PROVIDERS, detectProvider, NEXT_STEPS, writeCi, type CiProvider } from './ci';
import { runDoctor, type Check } from './doctor';
import { scanHistory } from './history';
import { toJunit } from './junit';
import { postPrComment, prContext } from './pr-comment';
import { githubAnnotations, toSarif } from './sarif';
import { chooseZapEngine, isLocalHost, parseZapReport, reportOrigins, runZap, waitForTarget, ZAP_IMAGE, type DastFinding, type ZapAuth, type ZapReport } from './dast';
import { PROJECT_CONFIG, readProjectConfig, removeKey, resolveKey, saveKey, writeProjectConfig } from './config';
import { apiUrl, VERSION } from './env';
import { checkoutInfo, currentBranch, currentCommit, parsePushRefs, repoRoot, type PushedRef } from './git';
import { installHook } from './hook';
import { explain, printDastReport, printReport } from './report';
import { meetsThreshold, runScan } from './scan';
import { configureNetwork } from './net';
import { osvCacheDir } from './rules/osv-cache';
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
  fortis access --target <url> [--writes]            can test user B read, change or delete test user A's records? (BOLA)
  fortis access init [--openapi|--postman|--har|--graphql <source>]  write ${ACCESS_CONFIG}, from your routes if given
  fortis baseline                                    accept today's findings so only new ones block
  fortis ci init [--provider <name>] [--history]     write a CI pipeline: ${CI_PROVIDERS.join(', ')}
  fortis explain <RULE-ID>                           why a rule matters and how to fix it
  fortis doctor [--strict] [--json] [--offline]      find what isn't working here, and how to fix it
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
  --junit <file>   write JUnit XML for CI systems that show test reports
  --pr-comment     in CI, post one comment on the pull request listing what it adds, updated in place
  --sbom <file>    also check a CycloneDX JSON SBOM (full Maven coverage, including transitive)
  --no-baseline    block on every finding, ignoring ${BASELINE_FILE}
  --submodules     also scan git submodules (skipped by default: they are separate repositories)
  --osv-db <dir>   check dependencies against OSV's downloaded exports (air-gapped networks)
  --no-cache       ask OSV again instead of using answers cached in the last 6 hours

${c.bold('Test options')}  ${c.grey('(needs Docker or a local ZAP; the target must be verified and authorised in the dashboard)')}
  --target <url>   staging URL to test (or set it once as "target" in .fortis.json)
  --mode <m>       baseline: passive checks, no attacks (default) · full: active scan (Fortis Plus)
  --openapi <url>  scan every operation in an OpenAPI spec (active, counts as full)
  --minutes <n>    how long to crawl (default 2)
  --local          test localhost on this machine; results stay local
  --zap-report <f> import a ZAP JSON report you ran yourself instead of running ZAP
  --fail-on <sev>  fail at this severity or above (default: high)
  --wait <s>       wait up to s seconds for the target to come up (after a deploy)
  logged in        set FORTIS_ZAP_AUTH to a test user's token ("Bearer …" is added if missing);
                   FORTIS_ZAP_AUTH_HEADER changes the header (e.g. Cookie). Sent to the target host only.

${c.bold('Access checks')}  ${c.grey('(Fortis Plus; read-only unless you pass --writes)')}
  Create two ordinary customers on staging, give user A a loan/wallet/transfer, then set
  FORTIS_USER_A_TOKEN and FORTIS_USER_B_TOKEN and run fortis access --target <url>.
  --writes         also send updates and deletes as user B, only to throwaway records user A
                   creates first using "writes" in ${ACCESS_CONFIG}

${c.bold('Environment')}
  FORTIS_KEY       CLI key (preferred in CI)
  FORTIS_API_URL   API address (default: ${apiUrl()})
  FORTIS_ZAP_DOCKER_ARGS  extra docker flags for fortis test (e.g. --add-host for private staging)
  FORTIS_ZAP_PATH  use the ZAP at this path (zap.sh or zap.bat) instead of Docker
  HTTPS_PROXY, HTTP_PROXY, NO_PROXY  company proxy (localhost is never proxied)
  NODE_EXTRA_CA_CERTS or --ca <file>  extra CA certificates, for proxies that inspect TLS
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
      else if (['key', 'api', 'fail-on', 'target', 'mode', 'openapi', 'minutes', 'zap-report', 'sarif', 'since', 'provider', 'staging-branch', 'wait', 'config', 'sbom', 'ca', 'osv-db', 'junit', 'postman', 'har', 'graphql'].includes(k) && rest[i + 1] && !rest[i + 1]!.startsWith('--')) flags[k] = rest[++i]!;
      else flags[k] = true;
    } else args.push(a);
  }
  return { cmd, args, flags };
}

const str = (v: string | boolean | undefined) => (typeof v === 'string' ? v : undefined);

/** --osv-db and the OSV answer cache (on unless --no-cache). */
const osvOptions = (flags: Flags) => ({ osvDb: str(flags['osv-db']), osvCacheDir: flags['no-cache'] ? undefined : osvCacheDir() });

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

  const sbom = str(flags.sbom);
  // The hook passes --stdin: git lists the refs being pushed there, so a first push covers every new commit.
  let pushed: PushedRef[] | undefined;
  if (prePush && flags.stdin && !process.stdin.isTTY) {
    try {
      pushed = parsePushRefs(readFileSync(0, 'utf8'));
    } catch {
      /* no stdin: fall back to comparing with the remote branch */
    }
  }
  const result = await runScan({ root, scope: prePush ? 'changed' : 'full', packs, ignore: config.ignore, offline, pushed, sbom, submodules: Boolean(flags.submodules), ...osvOptions(flags) });
  result.notes.unshift(...notes);

  // Git errors look like an empty repository. Passing here would also close every open finding.
  if (!prePush && result.filesScanned === 0 && result.packagesChecked === 0) {
    // Only lockfiles, and the dependency check couldn't run: say why, not "no files".
    const depError = result.notes.find((n) => n.startsWith('Dependency check skipped:'));
    if (depError) {
      err(c.red(`✖ ${depError}`));
      return 2;
    }
    err(c.red('✖ Found no files to scan.'), c.grey('Run this inside a git repository. In a container, the repository may also need: git config --global --add safe.directory <path>'));
    return 2;
  }

  if (flags.history) {
    if (checkoutInfo(root).shallow) {
      result.notes.push(`This is a shallow clone, so --history only saw the commits fetched. In CI, set fetch-depth: 0 on actions/checkout (GitLab: GIT_DEPTH: 0), or run fortis ci init --history.`);
    }
    const h = await scanHistory(root, { since: str(flags.since), ignore: config.ignore });
    result.detections.push(...h.detections);
    result.notes.push(`Searched ${h.commitsScanned} commits that added code: ${h.detections.length} found in history. Rotate every one, even if the file was deleted.`);
  }

  const baseline = flags['no-baseline'] ? null : readBaseline(root);
  const { fresh, known } = splitByBaseline(result.detections, baseline);
  if (known.length) result.notes.push(`${known.length} known finding(s) in ${BASELINE_FILE} are not shown and don't block. Fix them over time.`);

  const sarifPath = str(flags.sarif);
  if (sarifPath) writeFileSync(sarifPath, `${JSON.stringify(toSarif(result.detections), null, 2)}\n`);
  const junitPath = str(flags.junit);
  if (junitPath) writeFileSync(junitPath, toJunit(fresh, { failOn, durationMs: result.durationMs }));
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
        // A full scan that couldn't read every file (sparse checkout, time budget) mustn't close findings.
        scope: prePush || result.partial.length ? 'changed' : 'full',
        incompleteChecks: result.incompleteChecks.length ? result.incompleteChecks : undefined,
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

  let prComment: Awaited<ReturnType<typeof postPrComment>> | null = null;
  if (flags['pr-comment']) {
    const pr = prContext();
    if (pr.reason) result.notes.push(pr.reason);
    if (pr.context) {
      // A comment that can't be posted never fails the build.
      try {
        prComment = await postPrComment(pr.context, fresh);
      } catch (e) {
        result.notes.push(`Pull-request comment failed: ${(e as Error).message.split(pr.context.token).join('••••')}`);
      }
    }
  }

  const blocking = fresh.filter((d) => meetsThreshold(d.severity, failOn));
  if (json) {
    // Masked like every other output: --json usually lands in CI logs.
    const detections = result.detections.map((d) => ({ ...d, snippet: maskSnippet(d.snippet).slice(0, 300) }));
    log(JSON.stringify({ ...result, detections, packs, failOn, blocking: blocking.length, baselined: known.length, upload: uploaded, prComment }, null, 2));
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
    const engine = chooseZapEngine();
    if (engine.kind === 'none') {
      err(c.red(`✖ ${engine.reason}`));
      err(c.grey('fortis test runs OWASP ZAP in Docker (https://docs.docker.com/get-docker/) or from a local install (https://www.zaproxy.org/download/).'));
      err(c.grey(`Or run ZAP yourself and import the result: fortis test --target ${origin} --zap-report report.json`));
      return 2;
    }
    const label = openapi ? 'API scan (active)' : mode === 'full' ? 'full scan (active)' : 'baseline (passive, no attacks)';
    say(c.grey(`fortis ▸ OWASP ZAP ${label} · ${origin} · ${engine.kind === 'docker' ? ZAP_IMAGE : engine.path}`));
    say(c.grey(`Crawling for up to ${minutes} min${auth ? `, logged in via the ${auth.header} header` : ' as an anonymous visitor (set FORTIS_ZAP_AUTH to test behind login)'}. Pausing the target in the dashboard stops the run.`));
    try {
      const run = await runZap(
        { target: origin, mode, openapi, minutes, local, auth, engine },
        {
          onLine: (l) => {
            if (!json && /^(PASS|WARN|FAIL|Total of|Stopping|Job \S+ (started|finished))/.test(l)) log(c.grey(`  ${l.slice(0, 160)}`));
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

async function cmdAccess(args: string[], flags: Flags): Promise<number> {
  const root = repoRoot(process.cwd()) ?? process.cwd();
  const config = readProjectConfig(root);
  const api = apiUrl(str(flags.api) ?? config.apiUrl);
  const json = Boolean(flags.json);

  if (args[0] === 'init') {
    const readSource = async (source: string) => (/^https?:/.test(source) ? await (await fetch(source, { signal: AbortSignal.timeout(20_000) })).text() : readFileSync(source, 'utf8').replace(/^﻿/, ''));
    const spec = str(flags.openapi);
    const postman = str(flags.postman);
    const har = str(flags.har);
    const gql = str(flags.graphql);
    let target = str(flags.target) ?? config.target;
    const routes: Route[] = [];
    let graphql: AccessConfig['graphql'];
    const initNotes: string[] = [];
    const sources: string[] = [];
    let reading = '';
    try {
      if (spec) {
        reading = 'the OpenAPI spec';
        routes.push(...routesFromOpenApi(JSON.parse(await readSource(spec))));
        sources.push('OpenAPI spec');
      }
      if (postman) {
        reading = 'the Postman collection';
        routes.push(...routesFromPostman(JSON.parse(await readSource(postman))));
        sources.push('Postman collection');
      }
      if (har) {
        reading = 'the HAR file';
        const origin = target ? new URL(target).origin : undefined;
        routes.push(...routesFromHar(JSON.parse(await readSource(har)), origin));
        sources.push('HAR file');
      }
      if (gql) {
        reading = 'the GraphQL schema';
        let path = '/graphql';
        let json: unknown;
        if (/^https?:/.test(gql)) {
          const url = new URL(gql);
          path = url.pathname;
          target ??= url.origin;
          const token = process.env.FORTIS_USER_A_TOKEN?.trim();
          const authorization: Record<string, string> = token ? { authorization: /^(bearer|basic|token)\s/i.test(token) ? token : `Bearer ${token}` } : {};
          const res = await fetch(gql, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', ...authorization }, body: JSON.stringify({ query: INTROSPECTION_QUERY }), signal: AbortSignal.timeout(20_000) });
          json = await res.json();
        } else {
          json = JSON.parse(readFileSync(gql, 'utf8').replace(/^﻿/, ''));
        }
        const built = checksFromGraphqlSchema(schemaFrom(json));
        graphql = { path, checks: built.checks };
        initNotes.push(...built.notes);
        sources.push('GraphQL schema');
      }
    } catch (e) {
      err(c.red(`✖ Could not read ${reading}: ${(e as Error).message}`));
      return 2;
    }
    if (existsSync(join(root, ACCESS_CONFIG)) && !flags.force) {
      err(c.yellow(`! ${ACCESS_CONFIG} already exists. Use --force to overwrite it.`));
      return 2;
    }
    const checks = checksFromRoutes(routes);
    writeAccessTemplate(root, target, checks, graphql);
    const count = checks.length + (graphql?.checks.length ?? 0);
    log(c.green('✓'), `Wrote ${ACCESS_CONFIG}${sources.length ? ` with ${count} resource(s) from your ${sources.join(' and ')}` : ' with example loan, wallet and transfer checks'}.`);
    log(c.grey('Edit the paths to match your API. It holds no secrets; tokens come from FORTIS_USER_A_TOKEN and FORTIS_USER_B_TOKEN.'));
    for (const n of initNotes) log(c.yellow(`! ${n}`));
    if (checks.some((check) => check.writes) || graphql?.checks.some((check) => check.writes)) log(c.grey('Fill in the values under "writes" before using --writes. They create and change throwaway records.'));
    return 0;
  }

  let cfg;
  try {
    cfg = readAccessConfig(root, str(flags.config) ?? ACCESS_CONFIG);
  } catch (e) {
    err(c.red(`✖ ${(e as Error).message}`));
    return 2;
  }
  if (!cfg) {
    err(c.red(`✖ No ${ACCESS_CONFIG} yet.`), c.grey('Run: fortis access init  (add --openapi <url> to build it from your spec)'));
    return 2;
  }
  const rawTarget = str(flags.target) ?? cfg.target ?? config.target;
  let origin: string;
  let hostname: string;
  try {
    const u = new URL(rawTarget ?? '');
    origin = u.origin;
    hostname = u.hostname;
  } catch {
    err(c.red('✖ Give a target: fortis access --target https://staging.yourapp.com'));
    return 2;
  }
  const envA = cfg.users?.a?.tokenEnv ?? 'FORTIS_USER_A_TOKEN';
  const envB = cfg.users?.b?.tokenEnv ?? 'FORTIS_USER_B_TOKEN';
  const tokenA = process.env[envA]?.trim();
  const tokenB = process.env[envB]?.trim();
  if (!tokenA || !tokenB) {
    err(c.red(`✖ Set ${envA} and ${envB} to the tokens of two different test customers on staging.`));
    return 2;
  }
  if (tokenA === tokenB) {
    err(c.red('✖ The two tokens are the same. Use two different customers.'));
    return 2;
  }

  const local = Boolean(flags.local);
  if (local && !isLocalHost(hostname)) {
    err(c.red('✖ --local only tests this machine (localhost, 127.0.0.1, *.localhost).'));
    return 2;
  }
  const key = local ? undefined : resolveKey(api);
  const api$ = key ? client(api, key) : null;
  let target: CliTarget | undefined;
  if (!local) {
    if (!api$) {
      err(c.red('✖ No Fortis key found.'), c.grey('Access checks need a key so Fortis can confirm you may test this URL.'));
      return 2;
    }
    try {
      target = (await api$.targets(origin, 'access')).targets[0];
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

  const writes = Boolean(flags.writes);
  if (writes && !hasWriteChecks(cfg)) {
    err(c.red(`✖ --writes needs a "writes" block on at least one check in ${ACCESS_CONFIG}.`), c.grey('It says how user A creates the throwaway record to test with.'));
    return 2;
  }

  const started = Date.now();
  const resourceCount = cfg.checks.length + (cfg.graphql?.checks.length ?? 0);
  if (!json) {
    log(c.grey(`fortis ▸ access checks · ${origin} · ${resourceCount} resource(s) · ${writes ? 'with writes' : 'read-only'}`));
    if (writes) log(c.yellow('! User A creates throwaway records, and user B tries to update and delete them. Existing records are not written to.'));
  }
  let res;
  try {
    res = await runAccessChecks({ origin, config: cfg, tokenA, tokenB, writes });
  } catch (e) {
    err(c.red(`✖ ${(e as Error).message}`));
    return 2;
  }
  // Tokens must never leave this machine in a finding.
  const scrub = (t?: string) => (t ? t.split(tokenA).join('••••').split(tokenB).join('••••') : t);
  const findings = res.findings.map((f) => ({ ...f, snippet: scrub(f.snippet), detail: scrub(f.detail) }));

  let uploaded: Awaited<ReturnType<ReturnType<typeof client>['upload']>> | null = null;
  if (api$ && target && !flags['no-upload']) {
    try {
      uploaded = await api$.upload({
        scanId: randomUUID(), trigger: process.env.CI ? 'ci' : 'manual', kind: 'access', targetId: target.id, scope: 'full',
        // A run that didn't test writes can't say a write problem is fixed.
        incompleteChecks: !writes || res.writesIncomplete ? ['access-writes'] : undefined,
        commit: currentCommit(root), branch: currentBranch(root), cliVersion: VERSION, durationMs: Date.now() - started,
        findings: findings.map(({ evidence: _e, ...f }) => f),
      });
    } catch (e) {
      res.notes.push(`Upload failed: ${(e as Error).message}`);
    }
  }
  const failOn = (str(flags['fail-on']) ?? 'high') as Severity;
  const blocking = findings.filter((f) => meetsThreshold(f.severity, failOn));
  if (json) {
    log(JSON.stringify({ target: origin, writes, checked: res.checked, writesChecked: res.writesChecked, requests: res.requests, findings, notes: res.notes, upload: uploaded }, null, 2));
  } else {
    if (process.env.GITHUB_ACTIONS === 'true') for (const line of githubAnnotations(findings.map((f) => ({ ...f, file: undefined, title: `${f.title} (${f.file})`, message: f.detail })))) log(line);
    log('');
    if (!findings.length) log(c.green(c.bold('✓ No access leaks found')), c.grey(`· ${res.checked} record(s) checked${writes ? `, ${res.writesChecked} throwaway record(s) written to,` : ''} with ${res.requests} requests`));
    else {
      log(c.bold(c.red(`✖ ${findings.length} ACCESS LEAK${findings.length === 1 ? '' : 'S'}`)), c.grey(`· ${res.checked} record(s) checked`));
      log('');
      for (const f of findings) {
        log(`  ${c.bold(c.red('CRITICAL'))} ${c.white(c.bold(f.ruleId))}  ${f.title}`);
        log(`  ${' '.repeat(8)} ${c.cyan(f.file)}  ${c.grey(`A ${f.evidence.status.a} · B ${f.evidence.status.b}${f.evidence.status.anonymous === undefined ? '' : ` · anonymous ${f.evidence.status.anonymous}`}`)}`);
        log('');
      }
    }
    if (uploaded) log(c.grey(`Synced: ${uploaded.newCount} new · ${uploaded.fixedCount} fixed → ${uploaded.dashboardUrl}`));
    for (const n of res.notes) log(c.yellow(`! ${n}`));
  }
  return blocking.length ? 1 : 0;
}

async function cmdDoctor(flags: Flags): Promise<number> {
  const checks = await runDoctor({ cwd: process.cwd(), offline: Boolean(flags.offline), target: str(flags.target) });
  const failed = checks.filter((check) => check.status === 'fail' || (flags.strict && check.status === 'note'));
  if (flags.json) {
    log(JSON.stringify({ problems: failed.length, checks }, null, 2));
    return failed.length ? 1 : 0;
  }
  const mark: Record<Check['status'], string> = { ok: c.green('✓'), note: c.yellow('!'), fail: c.red('✖') };
  log(c.bold('fortis doctor'));
  log('');
  for (const check of checks) {
    log(`  ${mark[check.status]} ${check.message}`);
    if (check.fix) log(c.grey(`    → ${check.fix}`));
  }
  log('');
  if (failed.length) log(c.red(c.bold(`${failed.length} problem${failed.length === 1 ? '' : 's'} to fix.`)));
  else log(c.green(c.bold('No problems found.')));
  return failed.length ? 1 : 0;
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
  const result = await runScan({ root, scope: 'full', packs, ignore: config.ignore, offline: Boolean(flags.offline), sbom: str(flags.sbom), ...osvOptions(flags) });
  const n = writeBaseline(root, result.detections);
  log(c.green('✓'), `Wrote ${BASELINE_FILE} with ${n} known finding(s) (${packs.join(', ')} rules).`);
  log(c.grey('Commit it. From now on only new findings block pushes and CI; the known ones stay visible in the dashboard.'));
  return 0;
}

async function cmdCi(args: string[], flags: Flags): Promise<number> {
  if (args[0] !== 'init') {
    err(`Usage: fortis ci init [--provider ${CI_PROVIDERS.join('|')}] [--staging-branch staging] [--target URL] [--history] [--force]`);
    return 2;
  }
  const root = repoRoot(process.cwd());
  if (!root) {
    err(c.red('✖ Run fortis ci init inside a git repository.'));
    return 2;
  }
  const provider = (str(flags.provider) ?? detectProvider(root)) as CiProvider;
  if (!CI_PROVIDERS.includes(provider)) {
    err(c.red(`--provider must be one of: ${CI_PROVIDERS.join(', ')}`));
    return 2;
  }
  const stagingBranch = str(flags['staging-branch']) ?? 'staging';
  const res = writeCi(root, provider, { stagingBranch, target: str(flags.target) ?? readProjectConfig(root).target, force: Boolean(flags.force), history: Boolean(flags.history) });
  if (!res.written) {
    err(c.yellow(`! ${res.path} already exists. Use --force to overwrite it.`));
    return 2;
  }
  log(c.green('✓'), `Wrote ${res.path}`);
  if (res.mergeInto) log(c.yellow('!'), `${res.mergeInto} is your own pipeline, so it wasn't changed. Copy what you need from ${res.path} into it.`);
  log('');
  if (provider !== 'github' && provider !== 'gitlab') {
    log(c.bold('Next:'));
    for (const line of NEXT_STEPS[provider]) log(`  ${line}`);
    return 0;
  }
  if (provider === 'github') {
    log(c.bold('Next, in GitHub → Settings → Secrets and variables → Actions:'));
    log(`  secret   ${c.cyan('FORTIS_KEY')}           a CLI key from the Fortis dashboard`);
    log(`  variable ${c.cyan('FORTIS_STAGING_URL')}   your verified staging URL (for the ZAP job)`);
    log(`  secret   ${c.cyan('FORTIS_TEST_TOKEN')}    optional: a staging test user's token, to test behind login`);
  } else {
    log(c.bold('Next:'), `add ${c.cyan('include: [{ local: fortis.gitlab-ci.yml }]')} to .gitlab-ci.yml and set the CI/CD variables`);
    log('  FORTIS_KEY (masked), FORTIS_STAGING_URL, FORTIS_TEST_TOKEN (optional, masked),');
    log('  FORTIS_GITLAB_TOKEN (optional, masked: a token with the api scope, for merge-request comments)');
  }
  log(c.grey(`Pull requests get a code scan; pushes to "${stagingBranch}" also get a ZAP test once the deploy is up.`));
  return 0;
}

const PRE_COMMIT_CONFIG = `  - repo: local
    hooks:
      - id: fortis
        name: Fortis security scan
        entry: fortis scan --pre-push
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-push]`;

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

  if (existsSync(join(root, '.pre-commit-config.yaml'))) {
    log(c.yellow('!'), 'This repo uses pre-commit. To run Fortis through it instead, add this to .pre-commit-config.yaml:');
    log(c.grey(PRE_COMMIT_CONFIG));
  }

  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8').replace(/^\uFEFF/, '')) as { scripts?: Record<string, string> };
    if (!pkg.scripts?.['security:scan']) {
      pkg.scripts = { ...pkg.scripts, 'security:scan': 'fortis scan --ci' };
      writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
      log(c.green('✓'), 'Added npm script "security:scan" for CI');
    }
  }
  log('');
  const has = (f: string) => existsSync(join(root, f));
  const runScript = has('pnpm-lock.yaml') ? 'pnpm run security:scan' : has('yarn.lock') ? 'yarn security:scan' : has('bun.lock') || has('bun.lockb') ? 'bun run security:scan' : 'npm run security:scan';
  // A project install isn't on PATH: name the command the way this project runs it.
  const fortis = !existsSync(pkgPath) ? 'fortis' : has('pnpm-lock.yaml') ? 'pnpm exec fortis' : has('yarn.lock') ? 'yarn fortis' : has('bun.lock') || has('bun.lockb') ? 'bunx fortis' : 'npx fortis';
  log(c.grey(`Next: push as usual. For CI, run: ${fortis} ci init${existsSync(pkgPath) ? ` (or set FORTIS_KEY and run: ${runScript})` : ''}`));
  return 0;
}

async function main(): Promise<number> {
  const { cmd, args, flags } = parseArgs(process.argv.slice(2));
  try {
    const net = await configureNetwork(process.env, str(flags.ca));
    if (net && flags.verbose) err(c.grey(net));
  } catch (e) {
    err(c.red(`Could not set up the network: ${(e as Error).message}`));
    return 2;
  }
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
    case 'access':
      return cmdAccess(args, flags);
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
    case 'doctor':
      return cmdDoctor(flags);
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

// `fortis rules | head`, `| grep -q`: the reader can stop early. Stop quietly, like other Unix
// tools, instead of crashing on the broken pipe.
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code === 'EPIPE') process.exit(0);
    throw e;
  });
}

main().then(
  (code) => process.exit(code),
  (e) => {
    err(c.red(`✖ ${(e as Error).message}`));
    process.exit(2);
  },
);
