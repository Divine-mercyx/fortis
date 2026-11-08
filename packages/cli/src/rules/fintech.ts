import { callsIn, resolveCall, summarize, type Located } from '../analysis/project';
import { factsFor, type CallFact, type FileFacts, type FnFact, type RouteFact } from '../analysis/facts';
import { isKycName, isOtpName, MONEY, MONEY_OUT, namesSecretCode, wordsOf } from '../analysis/words';
import type { Detection, FileRule, ProjectContext, SourceFile } from './types';
import { isIgnored } from './types';

/*
 * The fintech rules. Each is a check over the facts of a file (see analysis/facts.ts), so they work
 * the same in every language that has an extractor, and they can follow simple calls across functions
 * and files. Each rule first looks for its words in the text, because most files have nothing for
 * it and parsing is the slow part. Silence a reviewed line with `// fortis-ignore` or `# fortis-ignore`.
 */

const SOURCE = /\.(?:[cm]?[jt]sx?|py)$/i;

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
});

const here = (file: SourceFile, facts: FileFacts, fn: FnFact): Located => ({ file, facts, fn });

/** Names that say a function is a service that loads records: `loanService.get(id)`, `get_loan(id)`. */
const SERVICE_NAME = /(?:service|svc|repo|repository|dao|store|manager|gateway|model)s?$/i;
const LOADER_METHOD = /^(?:get|find|fetch|load|read|retrieve|show|delete|remove|update|cancel|approve)/i;

/** Staff can see every customer's records. */
const isStaffRoute = (route: RouteFact | undefined) =>
  Boolean(route) && (/(?:^|\/)admin(?:\/|$)/i.test(route!.path) || route!.refs.some((r) => /admin|staff|superuser|back-?office/i.test(r)));

/* ---------- FX-OWN-001: a money record loaded by an ID from the request, for anyone who asks ---------- */

const REQUEST_INPUT = /\b(?:req|request|ctx|context|params)\b|@(?:Param|Query|Body)\b|\bdef\s+\w+\s*\(\s*(?:self\s*,\s*)?request\b|@\w+\.(?:route|get|post|put|patch|delete)\b|Depends\s*\(/;

export const ownershipRule: FileRule = {
  id: 'FX-OWN-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file, ctx) {
    if (!MONEY.test(file.text) && !MONEY.test(file.path)) return [];
    if (!REQUEST_INPUT.test(file.text) && !/queryset/.test(file.text)) return [];
    const facts = factsFor(file);
    const out: Detection[] = [];
    const flag = (line: number) => {
      if (!isIgnored(file, line) && !out.some((d) => d.line === line)) out.push(hit(file, line, 'FX-OWN-001', 'critical', 'Money record read without an ownership check'));
    };
    for (const e of facts.exposures) if (MONEY.test(`${file.path}\n${e.text}`)) flag(e.line);

    for (const fn of facts.fns) {
      const route = facts.routes.find((r) => r.fn === fn.id);
      if (fn.staffOnly || isStaffRoute(route)) continue;
      const reads = facts.reads.filter((r) => r.fn === fn.id && r.origins.includes('request'));
      const calls = callsIn(facts, fn).filter((c) => c.args.some((a) => a.includes('request')));
      if (!reads.length && !calls.length) continue;
      const whole = summarize(ctx.project, here(file, facts, fn));
      if (whole.ownerCheck) continue;
      const about = `${file.path}\n${fn.name}\n${fn.owner ?? ''}\n${route?.path ?? ''}`;
      for (const read of reads) {
        if (!read.scoped && MONEY.test(`${about}\n${read.text}\n${file.lines[read.line - 1] ?? ''}`)) flag(read.line);
      }
      for (const call of calls) {
        if (loadsRecordFor(ctx, file, facts, fn, call) && MONEY.test(`${about}\n${call.text}\n${file.lines[call.line - 1] ?? ''}`)) flag(call.line);
      }
    }
    return out;
  },
};

/** Whether a call hands the request's ID to something that loads a record with it. */
function loadsRecordFor(ctx: ProjectContext, file: SourceFile, facts: FileFacts, fn: FnFact, call: CallFact): boolean {
  const target = resolveCall(ctx.project, file, facts, fn, call.chain);
  if (target) {
    const theirs = summarize(ctx.project, target);
    return !theirs.ownerCheck && call.args.some((origins, i) => origins.includes('request') && theirs.readsById.has(i));
  }
  // Nothing to read, such as a service from a package or one injected by name: go by what it's called.
  const method = call.chain[call.chain.length - 1]!;
  const object = (call.chain[call.chain.length - 2] ?? '').replace(/\(\)$/, '');
  if (object) return SERVICE_NAME.test(object) && LOADER_METHOD.test(method);
  return LOADER_METHOD.test(method) && MONEY.test(method);
}

/* ---------- FX-HOOK-001: a payment webhook that never verifies the provider's signature ---------- */

const PROVIDER = /paystack|flutterwave|monnify|interswitch|remita|opay|kora/i;
const SIGNATURE_CHECKED =
  /x-paystack-signature|HTTP_X_PAYSTACK_SIGNATURE|verif-hash|HTTP_VERIF_HASH|monnify-signature|HTTP_MONNIFY_SIGNATURE|createHmac|timingSafeEqual|compare_digest|hmac\.|verify_?\w*signature|validate_?\w*signature|is_valid_\w*signature|verify_webhook|verifyWebhook|webhook.*secret/i;

/** Follows a route's handler and middleware, for a check that's in another file. */
function reachable(ctx: ProjectContext, file: SourceFile, facts: FileFacts, route: RouteFact): { sources: string[]; names: Set<string> } {
  const sources: string[] = [];
  const names = new Set<string>(route.refs);
  const follow = (located: Located | null) => {
    if (!located) return;
    const s = summarize(ctx.project, located);
    sources.push(...s.sources);
    for (const n of s.names) names.add(n);
  };
  if (route.fn !== null) follow(here(file, facts, facts.fns[route.fn]!));
  for (const ref of route.refs) follow(resolveCall(ctx.project, file, facts, facts.fns[0]!, [ref]));
  return { sources, names };
}

export const webhookSignatureRule: FileRule = {
  id: 'FX-HOOK-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file, ctx) {
    if (!/webhook/i.test(file.text) || !PROVIDER.test(file.text) || SIGNATURE_CHECKED.test(file.text)) return [];
    const facts = factsFor(file);
    const out: Detection[] = [];
    for (const route of facts.routes) {
      const fn = route.fn === null ? undefined : facts.fns[route.fn];
      if (!/webhook/i.test(`${route.path} ${fn?.name ?? ''} ${fn?.owner ?? ''}`)) continue;
      // A method on a class view has to accept writes; a function view can take anything.
      if (fn?.owner && !route.writes) continue;
      if (!fn?.owner && route.fn === null && !route.writes) continue;
      if (!route.writes && route.path) continue;
      if (reachable(ctx, file, facts, route).sources.some((s) => SIGNATURE_CHECKED.test(s)) || isIgnored(file, route.line)) continue;
      out.push(hit(file, route.line, 'FX-HOOK-001', 'critical', 'Payment webhook without a signature check'));
    }
    return out;
  },
};

/* ---------- FX-TXN-001: read a balance, change it, write it back, with no transaction or lock ---------- */

/** What called this function, in this file. A helper's safety can come from its caller. */
const callersOf = (facts: FileFacts, fn: FnFact) => (fn.name ? facts.calls.filter((c) => c.chain[c.chain.length - 1] === fn.name && c.fn !== fn.id && (c.chain.length === 1 || /^(?:this|self)$/.test(c.chain[c.chain.length - 2]!))) : []);

function anyCaller(facts: FileFacts, fn: FnFact, test: (caller: FnFact) => boolean, depth = 3, seen = new Set<number>()): boolean {
  if (depth === 0 || seen.has(fn.id)) return false;
  seen.add(fn.id);
  return callersOf(facts, fn).some((c) => {
    const caller = facts.fns[c.fn]!;
    return test(caller) || anyCaller(facts, caller, test, depth - 1, seen);
  });
}

export const balanceRaceRule: FileRule = {
  id: 'FX-TXN-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file) {
    if (!/balance/i.test(file.text)) return [];
    const facts = factsFor(file);
    const out: Detection[] = [];
    for (const update of facts.balances) {
      const fn = facts.fns[update.fn]!;
      if (fn.atomic || anyCaller(facts, fn, (c) => c.atomic)) continue;
      // Only a balance that's written back to storage can race. A local has to be what's written.
      if (update.local) {
        if (!fn.persists || !new RegExp(`\\.\\w+\\s*\\([^;]*\\b${update.local}\\b`).test(fn.source.split('\n').slice(update.line - fn.line + 1).join('\n'))) continue;
      } else if (!fn.persists && !anyCaller(facts, fn, (c) => c.persists)) continue;
      if (!isIgnored(file, update.line)) out.push(hit(file, update.line, 'FX-TXN-001', 'high', 'Balance update outside a transaction'));
    }
    return out;
  },
};

/* ---------- FX-PII-002: a BVN or NIN value written to logs, not just the word "BVN" ---------- */

export const kycLoggingRule: FileRule = {
  id: 'FX-PII-002',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file) {
    if (!/\b(?:bvn|nin|national|bank_?verification)|bvn|nin_?number/i.test(file.text)) return [];
    const out: Detection[] = [];
    for (const log of factsFor(file).logs) {
      if (log.values.some(isKycName) && !isIgnored(file, log.line)) out.push(hit(file, log.line, 'FX-PII-002', 'high', 'BVN or NIN written to logs'));
    }
    return out;
  },
};

/* ---------- FX-OTP-001: OTPs from a weak generator, written to logs, returned, or hard-coded ---------- */

const OTP_WORDS = /otp|passcode|verification|one_?time|Math\.random|\brandom\./i;
const OTP_IN_TEXT = /\botp\b[^\n]{0,20}?\b\d{4,8}\b/i;

export const otpRule: FileRule = {
  id: 'FX-OTP-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file) {
    if (!OTP_WORDS.test(file.text)) return [];
    const facts = factsFor(file);
    const out: Detection[] = [];
    const add = (line: number, severity: Detection['severity'], title: string) => {
      if (!isIgnored(file, line) && !out.some((d) => d.line === line)) out.push(hit(file, line, 'FX-OTP-001', severity, title));
    };
    for (const r of facts.randoms) if (namesSecretCode(r.context)) add(r.line, 'high', `OTP generated with ${r.api}`);
    for (const log of facts.logs) {
      if (log.values.some(isOtpName)) add(log.line, 'high', 'OTP written to logs');
      else if (log.literals.some((l) => OTP_IN_TEXT.test(l))) add(log.line, 'medium', 'Hard-coded OTP in source');
    }
    for (const line of facts.fixedOtps) add(line, 'medium', 'Hard-coded OTP in source');
    for (const r of facts.responses) if (r.fields.some((f) => /^otp$/i.test(f))) add(r.line, 'high', 'OTP returned in an API response');
    return out;
  },
};

/* ---------- FX-IDEM-001: a money-out route that a retry can replay ---------- */

const READ_ONLY = new Set(['quote', 'quotes', 'fee', 'fees', 'preview', 'estimate', 'validate', 'verify', 'lookup', 'enquiry', 'resolve']);
const IDEMPOTENT = /idempot|dedup|replay|paymentguard|withguard|payment_guard|with_guard/i;

export const idempotencyRule: FileRule = {
  id: 'FX-IDEM-001',
  pack: 'fintech',
  appliesTo: SOURCE,
  skipTests: true,
  run(file, ctx) {
    if (!MONEY_OUT.test(file.text) || /idempoten/i.test(file.text)) return [];
    const facts = factsFor(file);
    const out: Detection[] = [];
    for (const route of facts.routes) {
      if (!route.writes) continue;
      const fn = route.fn === null ? undefined : facts.fns[route.fn];
      const names = `${route.path} ${fn?.name ?? ''} ${fn?.owner ?? ''} ${route.refs.join(' ')}`;
      if (!MONEY_OUT.test(names) || wordsOf(names).some((w) => READ_ONLY.has(w))) continue;
      const reached = reachable(ctx, file, facts, route);
      const guarded = [...reached.names].some((n) => n !== fn?.name && (IDEMPOTENT.test(n) || ctx.idempotencyHelpers.has(n)));
      if (guarded || reached.sources.some((s) => /idempoten/i.test(s)) || isIgnored(file, route.line)) continue;
      out.push(hit(file, route.line, 'FX-IDEM-001', 'high', 'Transfer without an idempotency key'));
    }
    return out;
  },
};

export const FINTECH_RULES: FileRule[] = [ownershipRule, webhookSignatureRule, balanceRaceRule, kycLoggingRule, otpRule, idempotencyRule];
