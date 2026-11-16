import { readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';

import { SEVERITY_RANK, type RulePack, type Severity } from '@fortis/shared';

import { takeAnalysisFailures } from './analysis/facts';
import { callLanguageOf, languageOf, loadGrammars, type Language } from './analysis/parser';
import { createProject } from './analysis/project';
import { scanDependencies } from './rules/dependencies';
import { GLOBAL_LIMIT } from './rules/auth';
import { GLOBAL_LIMIT_OTHER, OTHER_LANGUAGES } from './rules/auth-languages';
import { rulesFor } from './rules/index';
import { CI_FILE, k8sExposedServiceRule, terraformValues, unresolvedNote } from './rules/infrastructure';
import { chartsWithServices, renderCharts, type HelmRunner } from './rules/helm';
import { planFindings } from './rules/terraform-plan';
import { PINNING, PINNING_FILES } from './rules/mobile';
import { findLockfiles } from './rules/lockfiles';
import type { Runner } from './rules/resolve';
import { JS_TS, PYTHON, TEST_PATH, type Detection, type ProjectContext, type SourceFile } from './rules/types';
import { makeFilter, readSource } from './files';
import { allFiles, changedFiles, checkoutInfo, type PushedRef } from './git';

export type ScanOptions = {
  root: string;
  scope: 'changed' | 'full';
  /** Scan exactly these paths (relative to root) instead of working them out from git. */
  only?: string[];
  packs: readonly RulePack[];
  ignore?: string[];
  offline?: boolean;
  /** Read advisories from OSV's downloaded exports instead of the network (works with offline). */
  osvDb?: string;
  /** Where OSV answers are cached between scans; omitted means no cache. */
  osvCacheDir?: string;
  /** From the git hook's stdin: the refs being pushed (pre-push scope only). */
  pushed?: PushedRef[];
  /** A CycloneDX JSON SBOM to check as well as the lockfiles. */
  sbom?: string;
  /** Ask Gradle, Maven, sbt or dotnet for the full dependency tree of build files with no lockfile (--resolve). */
  resolve?: boolean;
  /** Runs the build tools for --resolve. Tests replace it. */
  resolveRunner?: Runner;
  /** `terraform show -json` output to check, where every value is final (--terraform-plan). */
  terraformPlan?: string;
  /** Runs helm to render charts. Tests replace it. */
  helmRunner?: HelmRunner;
  fetchImpl?: typeof fetch;
  /** Also scan submodules (other repositories inside this one). */
  submodules?: boolean;
  /** Stop reading files after this long; the result says so. Default 10 minutes, or FORTIS_SCAN_BUDGET_SECONDS. */
  budgetMs?: number;
};

export type ScanResult = {
  detections: Detection[];
  filesScanned: number;
  packagesChecked: number;
  durationMs: number;
  notes: string[];
  /** Checks that couldn't see everything, so a full scan must not close their findings. */
  incompleteChecks: 'dependencies'[];
  /**
   * Why the file checks didn't see the whole repository (sparse checkout, time budget). A full scan
   * with a reason is uploaded as a partial one, so it can't close findings in files it never read.
   */
  partial: string[];
};

/** Source files the fintech code rules can't read yet. */
const UNCOVERED_LANGUAGES: [RegExp, string][] = [
  [/\.(scala|groovy)$/i, 'Scala/Groovy'],
  [/\.rb$/i, 'Ruby'],
  [/\.rs$/i, 'Rust'],
  [/\.(swift|dart)$/i, 'mobile'],
];

function uncoveredLanguagesNote(paths: string[]): string | null {
  const counts = UNCOVERED_LANGUAGES.map(([re, label]) => ({ label, n: paths.filter((p) => re.test(p) && !TEST_PATH.test(p)).length })).filter((c) => c.n);
  if (!counts.length) return null;
  const list = counts.sort((a, b) => b.n - a.n).map((c) => `${c.n} ${c.label}`).join(', ');
  return `Fintech code rules cover JavaScript, TypeScript, Python, Go, C#, PHP, Java and Kotlin so far: ${list} files had secrets and dependency checks only.`;
}

const DEFAULT_BUDGET_MS = (Number(process.env.FORTIS_SCAN_BUDGET_SECONDS) || 600) * 1000;

export async function runScan(opts: ScanOptions): Promise<ScanResult> {
  const started = Date.now();
  const notes: string[] = [];
  const partial: string[] = [];
  const checkout = checkoutInfo(opts.root);
  const everything = () => allFiles(opts.root, { submodules: opts.submodules });
  const paths = opts.only ?? (opts.scope === 'changed' ? changedFiles(opts.root, opts.pushed) : everything());
  const keep = makeFilter(opts.ignore);
  const candidates = paths.filter(keep);
  let rules = rulesFor(opts.packs);

  if (checkout.submodules.length && !opts.submodules) {
    const list = checkout.submodules.slice(0, 3).join(', ') + (checkout.submodules.length > 3 ? ` and ${checkout.submodules.length - 3} more` : '');
    notes.push(`Skipped ${checkout.submodules.length === 1 ? 'a submodule' : `${checkout.submodules.length} submodules`} (${list}): they are separate repositories. Scan them on their own, or pass --submodules.`);
  }
  if (checkout.notCheckedOut && opts.scope === 'full') {
    notes.push(`Sparse checkout: ${checkout.notCheckedOut} tracked files aren't on disk and weren't scanned. Findings in them stay open.`);
    partial.push('sparse checkout');
  }
  if (checkout.shallow && opts.scope === 'changed' && !opts.pushed?.length) {
    notes.push('This is a shallow clone, so the comparison with the main branch may cover too little. In CI, fetch more history (actions/checkout: fetch-depth: 0) or run a full scan with --ci.');
  }

  // Repository-wide facts (e.g. idempotency middleware defined elsewhere), even for pre-push scans.
  const ctxPaths = (opts.scope === 'full' ? candidates : everything().filter(keep)).filter((p) => (JS_TS.test(p) || PYTHON.test(p)) && !TEST_PATH.test(p));
  const ctx = buildContextFrom(opts.root, ctxPaths);
  // Go, C#, PHP, Java and Kotlin files join the project too, so a route can be followed into its controller.
  const otherPaths = (opts.scope === 'full' ? candidates : everything().filter(keep)).filter((p) => OTHER_LANGUAGES.test(p) && !TEST_PATH.test(p));
  ctx.project = createProject([...ctxPaths, ...otherPaths], (p) => readSource(opts.root, p));
  // Terraform variables and locals, so a rule can judge `cidr_blocks = var.admin_cidrs`, with TF_VAR_ and -var values from CI files.
  const tfPool = (opts.scope === 'full' ? candidates : everything().filter(keep));
  const tfPaths = tfPool.filter((p) => /\.(?:tf|tfvars)$/i.test(p));
  if (tfPaths.length) ctx.terraform = terraformValues([...tfPaths, ...tfPool.filter((p) => CI_FILE.test(p))].map((p) => readSource(opts.root, p)).filter((f): f is SourceFile => f !== null));
  // Settings the infrastructure checks couldn't resolve, so the scan can say they weren't checked.
  ctx.unresolved = [];
  // Go, C#, PHP, Java and Kotlin apps can turn on a rate limit for everything in one file too.
  if (!ctx.rateLimitAll && rules.some((r) => r.id === 'FX-RATE-001')) {
    const pool = (opts.scope === 'full' ? candidates : everything().filter(keep)).filter((p) => OTHER_LANGUAGES.test(p) && !TEST_PATH.test(p));
    ctx.rateLimitAll = pool.some((p) => {
      const f = readSource(opts.root, p);
      return f !== null && GLOBAL_LIMIT_OTHER.test(f.text);
    });
  }
  // Whether the app pins certificates anywhere, so MOB-PIN-001 can judge the app as a whole.
  if (rules.some((r) => r.id === 'MOB-PIN-001')) {
    const pool = (opts.scope === 'full' ? candidates : everything().filter(keep)).filter((p) => PINNING_FILES.test(p) && !/node_modules\//.test(p));
    ctx.pinning = pool.some((p) => {
      const f = readSource(opts.root, p);
      return f !== null && PINNING.test(f.text);
    });
  }

  // Only the grammars this repository needs, and only if the rules that use them are running.
  if (rules.some((r) => r.pack === 'fintech')) {
    const languages = new Set(candidates.map(languageOf).filter((l): l is Language => l !== null));
    // Go, C#, Java and PHP: to follow a login or reset handler into its services (analysis/other.ts).
    for (const l of (opts.scope === 'full' ? candidates : [...candidates, ...otherPaths]).map(callLanguageOf)) if (l) languages.add(l);
    try {
      await loadGrammars(languages);
    } catch (err) {
      notes.push(`Fintech code rules couldn't start: ${(err as Error).message}`);
      partial.push('code analysis unavailable');
      rules = rules.filter((r) => r.pack !== 'fintech');
    }
  }

  // Files are read and checked one at a time, so memory stays flat however big the repository is.
  const budget = opts.budgetMs ?? DEFAULT_BUDGET_MS;
  const seen = new Set<string>();
  const detections: Detection[] = [];
  let filesScanned = 0;
  let read = 0;
  for (const path of candidates) {
    if (Date.now() - started > budget) {
      notes.push(`Stopped after ${Math.round(budget / 1000)} seconds: checked ${read} of ${candidates.length} files. Raise the limit with FORTIS_SCAN_BUDGET_SECONDS, or ignore generated folders in .fortis.json.`);
      partial.push('time budget');
      break;
    }
    read++;
    const file = readSource(opts.root, path);
    if (!file) continue;
    filesScanned++;
    for (const rule of rules) {
      if (!rule.appliesTo.test(file.path)) continue;
      if (rule.skipTests && TEST_PATH.test(file.path)) continue;
      for (const d of rule.run(file, ctx)) {
        const key = `${d.ruleId}|${d.file}|${d.line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        detections.push(d);
      }
    }
  }

  const record = (d: Detection) => {
    const key = `${d.ruleId}|${d.file}|${d.line}`;
    if (seen.has(key)) return;
    seen.add(key);
    detections.push(d);
  };
  // Helm charts, rendered when Helm is installed: Services whose type or ports come from values through a template.
  if (rules.some((r) => r.id === 'INF-K8S-001')) {
    const charts = chartsWithServices(candidates, (p) => readSource(opts.root, p)?.text ?? null);
    if (charts.length) {
      const rendered = await renderCharts(opts.root, charts, opts.helmRunner);
      notes.push(...rendered.notes);
      for (const file of rendered.files) {
        for (const d of k8sExposedServiceRule.run(file, ctx)) {
          // The file check may already have found it in the template itself.
          if (detections.some((x) => x.ruleId === d.ruleId && x.file === d.file)) continue;
          record({ ...d, line: 0, title: `${d.title} (as rendered by helm template)` });
        }
      }
    }
  }
  // A Terraform plan, where every value is final.
  if (opts.terraformPlan && rules.some((r) => r.pack === 'infrastructure')) {
    const rel = relative(opts.root, resolve(opts.root, opts.terraformPlan)).replace(/\\/g, '/');
    try {
      const plan = planFindings(readFileSync(resolve(opts.root, opts.terraformPlan), 'utf8'), rel);
      for (const d of plan.detections) record(d);
      ctx.unresolved.push(...plan.unresolved);
      notes.push(`Terraform plan ${rel}: checked ${plan.resources} planned resource${plan.resources === 1 ? '' : 's'}.`);
    } catch (e) {
      notes.push(`Couldn't read the Terraform plan ${rel}: ${(e as Error).message}. Make it with terraform plan -out=tfplan, then terraform show -json tfplan > plan.json.`);
    }
  }
  const unresolved = unresolvedNote(ctx.unresolved);
  if (unresolved) notes.push(unresolved);

  const unreadable = takeAnalysisFailures();
  if (unreadable) {
    notes.push(`Fintech code rules couldn't read ${unreadable} file${unreadable === 1 ? '' : 's'}, so findings in them stay open.`);
    partial.push('code analysis incomplete');
  }

  let packagesChecked = 0;
  const incompleteChecks: ScanResult['incompleteChecks'] = [];
  const lockTouched = opts.scope === 'full' || Boolean(opts.sbom) || findLockfiles(paths, opts.ignore).length > 0;
  if (opts.packs.includes('dependencies') && lockTouched) {
    if (opts.offline && !opts.osvDb) {
      notes.push('Dependency check skipped (--offline). Use --osv-db <dir> to check against a downloaded OSV database.');
      incompleteChecks.push('dependencies');
    } else {
      const deps = await scanDependencies(opts.root, paths, {
        sbom: opts.sbom,
        ignore: opts.ignore,
        fetchImpl: opts.fetchImpl,
        osvDb: opts.osvDb,
        cacheDir: opts.osvCacheDir,
        resolve: opts.resolve ? { offline: opts.offline, run: opts.resolveRunner } : undefined,
        // Only a full scan can say a lockfile is missing; a push may simply not have touched it.
        allPaths: opts.scope === 'full' ? paths : undefined,
      });
      packagesChecked = deps.checked;
      detections.push(...deps.detections);
      notes.push(...deps.notes);
      if (deps.error) notes.push(`Dependency check skipped: ${deps.error}`);
      if (deps.incomplete) incompleteChecks.push('dependencies');
    }
  }

  if (opts.scope === 'full') {
    const uncovered = uncoveredLanguagesNote(candidates);
    if (uncovered) notes.push(uncovered);
  }

  detections.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return { detections, filesScanned, packagesChecked, durationMs: Date.now() - started, notes, incompleteChecks, partial };
}

/** buildContext over files read one at a time. */
function buildContextFrom(root: string, paths: string[]): ProjectContext {
  const idempotencyHelpers = new Set<string>();
  let rateLimitAll = false;
  for (const p of paths) {
    const f = readSource(root, p);
    if (!f) continue;
    const one = buildContext([f]);
    for (const name of one.idempotencyHelpers) idempotencyHelpers.add(name);
    rateLimitAll ||= Boolean(one.rateLimitAll);
  }
  return { idempotencyHelpers, rateLimitAll };
}

/** Names exported from modules that implement idempotency keys, e.g. withPaymentGuard. */
export function buildContext(files: SourceFile[]): ProjectContext {
  const idempotencyHelpers = new Set<string>();
  let rateLimitAll = false;
  for (const f of files) {
    if (!TEST_PATH.test(f.path) && (GLOBAL_LIMIT.test(f.text) || (OTHER_LANGUAGES.test(f.path) && GLOBAL_LIMIT_OTHER.test(f.text)))) rateLimitAll = true;
    if (TEST_PATH.test(f.path) || !/idempoten/i.test(f.text)) continue;
    if (PYTHON.test(f.path)) {
      for (const m of f.text.matchAll(/^(?:async\s+)?def\s+([A-Za-z_]\w*)/gm)) idempotencyHelpers.add(m[1]!);
    } else if (JS_TS.test(f.path)) {
      for (const m of f.text.matchAll(/\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|\bexport\s+(?:const|let)\s+([A-Za-z_$][\w$]*)/g)) {
        idempotencyHelpers.add((m[1] ?? m[2])!);
      }
    }
  }
  const tf = files.filter((f) => /\.(?:tf|tfvars)$/i.test(f.path));
  const pinning = files.some((f) => PINNING_FILES.test(f.path) && PINNING.test(f.text));
  return { idempotencyHelpers, rateLimitAll, pinning, ...(tf.length ? { terraform: terraformValues(tf) } : {}) };
}

export const meetsThreshold = (sev: Severity, failOn: Severity) => SEVERITY_RANK[sev] >= SEVERITY_RANK[failOn];
