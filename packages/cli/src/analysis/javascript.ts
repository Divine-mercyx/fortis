import type { SourceFile } from '../rules/types';

import { blanked, emptyFacts, fieldOf as field, namedOf as named, newFn, type FileFacts, type FnFact, type Origin, type RouteFact } from './facts';
import type { Ast } from './parser';
import { MASKING, OWNER_FIELD, OWNER_NAME } from './words';

/* Facts for JavaScript and TypeScript: Express-style routers, NestJS decorators and Next.js route files. */

const FUNCTION = new Set(['function_declaration', 'function_expression', 'arrow_function', 'method_definition', 'generator_function', 'generator_function_declaration']);
const STRING_PARTS = new Set(['string_fragment', 'escape_sequence']);
/** Clients, not routers: `axios.post('/x', body)` calls a route rather than defining one. */
const OUTGOING = /^(?:axios|http|https|got|fetch|superagent|ky|\$http|httpClient|httpService|client|api|apiClient|instance|request|cy|supertest|agent|needle|nock)$/i;
const MAKES_ROUTER = /^(?:new\s+)?(?:express|Router|express\.Router|fastify|Fastify|Hono|Elysia|Koa)\s*\(/;
const NEST_VERB = /^(?:Get|Post|Put|Patch|Delete|All)$/;
const NEXT_VERB = /^(?:GET|POST|PUT|PATCH|DELETE)$/;
const REQUEST_NAME = /^(?:req|request|ctx|context)$/;
const REQUEST_FIELD = /^(?:params|query|body)$/;
const BY_ID_METHOD = /^(?:findById|findByPk|findUnique|findUniqueOrThrow|findOne|findOneOrFail|findOneBy|findOneByOrFail|findFirst|findFirstOrThrow|get|getById|load|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete|updateOne|deleteOne|update|delete|destroy)$/;
/** `.get(id)` on these isn't a database. */
const NOT_A_STORE = /(?:Cache|Map)$|^(?:cache|redis|map|headers?|searchParams|params|query|session|store|res|response|req|app|router|config|process|localStorage|sessionStorage|memo|registry|env|settings|i18n|storage|logger|console|cookies?|url|form|formData|schema|joi|yup)$/i;
const ID_FIELD = /^(?:_?id|uuid)$/;
const SQL_BY_ID = /\b(?:select|update|delete)\b[\s\S]*\bwhere\b[\s\S]*\bid\s*=\s*(?:\$\d|\?|:id)/i;
const SQL_OWNER = /\b(?:user|owner|customer|account|wallet|merchant|tenant|org)_?id\s*=/i;
const SIGNED_IN = /^(?:req|request|ctx\.request)\.(?:user|auth|account|session\.user\w*)\b|^ctx\.state\.user\b|^(?:session|res\.locals|locals)\.user\b|^(?:user|me)\.(?:_?id|sub)\b|^currentUser\b/;
const SIGNED_IN_CALL = /^(?:getCurrentUser|currentUser|getUser|getSession|getServerSession|auth|getAuth)$/;
const OWNERSHIP_CALL = /(?:assert|check|verify|ensure|require|validate|enforce)\w*(?:Own|Access|Permission)|^(?:authorize|isOwner|can|canAccess|hasAccess|hasPermission)$|Ownership/;
const OWNERSHIP_DECORATOR = /Owner|Ownership|Policy|Policies|CheckAbility/;
const STAFF = /(?:^|[^a-z])admin|Admin|staff|Staff|superuser|back-?office|backOffice/;
const ATOMIC = /\$transaction|\.transaction\s*\(|startTransaction|\bBEGIN\b|FOR UPDATE|\$inc\b|increment\s*\(|decrement\s*\(|withTransaction/i;
const PERSISTS = /\.save\s*\(|\.(?:updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|upsert)\s*\(|\.update\s*\(\s*\{|\.query\s*\(|\.execute\s*\(|\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bprisma\.|\bknex\b|getRepository|\.repository\b/i;
const TRANSACTION_PARAM = /^(?:tx|trx|txn|transaction|manager)$/;
const DECIMAL_MATH = /^(?:plus|minus|add|sub|subtract)$/;
const UNWRAP = new Set(['non_null_expression', 'parenthesized_expression', 'await_expression', 'as_expression', 'satisfies_expression']);

export function extractJavaScript(file: SourceFile, root: Ast, comments: [number, number][]): FileFacts {
  const facts = emptyFacts();
  const src = file.text;
  const { noComments, code } = blanked(src, root, comments, STRING_PARTS);
  const text = (n: Ast) => src.slice(n.start, n.end);
  const module = newFn(0, { endLine: file.lines.length });
  facts.fns.push(module);

  /** What each name holds, per function. */
  const flows = new Map<FnFact, Map<string, Origin[]>>([[module, new Map()]]);
  const parents = new Map<FnFact, FnFact>();
  const routers = new Set<string>();
  const routeCalls = new Map<Ast, RouteFact>();
  const computedBalances = new Set<string>();

  /** `req.user!.id` as `req.user.id`. */
  const chainText = (n: Ast): string => {
    if (n.type === 'identifier' || n.type === 'this' || n.type === 'property_identifier' || n.type === 'shorthand_property_identifier' || n.type === 'type_identifier') return text(n);
    if (n.type === 'member_expression') {
      const object = field(n, 'object');
      const property = field(n, 'property');
      return object && property ? `${chainText(object)}.${text(property)}` : '?';
    }
    if (UNWRAP.has(n.type)) return n.children[0] ? chainText(n.children[0]) : '?';
    if (n.type === 'call_expression') return `${chainText(field(n, 'function') ?? n.children[0]!)}()`;
    if (n.type === 'new_expression') return `${chainText(field(n, 'constructor') ?? n.children[0]!)}()`;
    return '?';
  };

  const lookup = (fn: FnFact, name: string): Origin[] | undefined => {
    for (let at: FnFact | undefined = fn; at; at = parents.get(at)) {
      const found = flows.get(at)?.get(name);
      if (found) return found;
    }
    return undefined;
  };

  /** `req.params.id`, `ctx.request.body.id`, `c.req.param`. */
  const isRequestValue = (chain: string[]) => {
    const at = chain.findIndex((p) => REQUEST_NAME.test(p) || p === 'req');
    if (at === -1) return false;
    const next = chain[at + 1] === 'request' || chain[at + 1] === 'req' ? chain[at + 2] : chain[at + 1];
    return REQUEST_FIELD.test(next ?? '');
  };

  /** Where a value came from: the request, or parameters of the function it's in. */
  const originsOf = (n: Ast, fn: FnFact): Origin[] => {
    const out = new Set<Origin>();
    const visit = (e: Ast) => {
      if (FUNCTION.has(e.type)) return;
      if (e.type === 'member_expression' || e.type === 'subscript_expression') {
        const chain = chainText(e.type === 'member_expression' ? e : (field(e, 'object') ?? e)).split('.');
        if (isRequestValue(chain)) out.add('request');
        else for (const o of lookup(fn, chain[0]!) ?? []) out.add(o);
        if (e.type === 'subscript_expression') {
          const index = field(e, 'index');
          if (index) visit(index);
        }
        return;
      }
      if (e.type === 'identifier' || e.type === 'shorthand_property_identifier') {
        for (const o of lookup(fn, text(e)) ?? []) out.add(o);
        return;
      }
      if (e.type === 'call_expression') {
        const callee = field(e, 'function');
        if (callee && /(?:^|\.)(?:req|request)\.param$/.test(chainText(callee))) {
          out.add('request');
          return;
        }
        // Number(x) and x.trim() carry x along. `service.get(x)` makes something new.
        if (callee?.type === 'member_expression') {
          const object = field(callee, 'object');
          if (object) visit(object);
        } else {
          field(e, 'arguments')?.children.forEach(visit);
        }
        return;
      }
      if (e.type === 'pair') {
        const value = field(e, 'value');
        if (value) visit(value);
        return;
      }
      e.children.forEach(visit);
    };
    visit(n);
    return [...out];
  };

  /** Notes what a declaration holds: `const { id } = req.params`. */
  const bind = (pattern: Ast, value: Ast, fn: FnFact) => {
    const origins = originsOf(value, fn);
    const names: string[] = [];
    const collect = (p: Ast) => {
      if (p.type === 'identifier' || p.type === 'shorthand_property_identifier_pattern') names.push(text(p));
      else if (p.type === 'pair_pattern') {
        const v = field(p, 'value');
        if (v) collect(v);
      } else p.children.forEach(collect);
    };
    collect(pattern);
    // `const { params } = req` holds the request's fields under their own names.
    const wholeRequest = value.type === 'identifier' && REQUEST_NAME.test(text(value));
    for (const name of names) {
      if (origins.length) flows.get(fn)!.set(name, origins);
      else if (wholeRequest && REQUEST_FIELD.test(name)) flows.get(fn)!.set(name, ['request']);
    }
  };

  const decoratorName = (d: Ast) => {
    const c = named(d)[0];
    return c ? chainText(c.type === 'call_expression' ? (field(c, 'function') ?? c) : c) : '';
  };

  const readParams = (n: Ast, fn: FnFact) => {
    const single = field(n, 'parameter');
    const list = single ? [single] : (field(n, 'parameters')?.children.filter((c) => c.named && c.type !== 'decorator') ?? []);
    const known = flows.get(fn)!;
    list.forEach((p, i) => {
      const pattern = field(p, 'pattern') ?? (p.type === 'assignment_pattern' ? field(p, 'left') : undefined) ?? p;
      const decorators = p.children.filter((c) => c.type === 'decorator').map(decoratorName);
      // constructor(private readonly loans: LoanService)
      const annotation = field(p, 'type');
      if (annotation && pattern.type === 'identifier' && p.children.some((c) => c.type === 'accessibility_modifier' || c.type === 'readonly')) {
        const type = named(annotation)[0];
        if (type) facts.instances.set(text(pattern), text(type));
      }
      if (pattern.type === 'identifier') {
        fn.params.push(text(pattern));
        known.set(text(pattern), decorators.some((d) => /^(?:Param|Query|Body)$/.test(d)) ? ['request', i] : [i]);
      } else {
        fn.params.push('');
        if (pattern.type !== 'object_pattern') return;
        for (const c of pattern.children) {
          const bound = c.type === 'shorthand_property_identifier_pattern' ? text(c) : c.type === 'pair_pattern' ? text(field(c, 'value') ?? c) : '';
          if (!bound) continue;
          // Next.js: GET(request, { params })
          known.set(bound, bound === 'params' && NEXT_VERB.test(fn.name) ? ['request'] : [i]);
        }
      }
    });
  };

  const startFunction = (n: Ast, parent: FnFact, fields: Partial<FnFact>): FnFact => {
    const fn = newFn(facts.fns.length, {
      line: n.line,
      endLine: n.endLine,
      source: noComments.slice(n.start, n.end),
      persists: PERSISTS.test(noComments.slice(n.start, n.end)),
      atomic: ATOMIC.test(noComments.slice(n.start, n.end)),
      ...fields,
    });
    facts.fns.push(fn);
    flows.set(fn, new Map());
    parents.set(fn, parent);
    readParams(n, fn);
    if (fn.params.some((p) => TRANSACTION_PARAM.test(p))) fn.atomic = true;
    if (/^(?:req|request)$/.test(fn.params[0] ?? '') || NEXT_VERB.test(fn.name)) fn.handler = true;
    return fn;
  };

  /** Notes a use of the signed-in user. Testing whether there is one doesn't count. */
  const noteSignedIn = (n: Ast, fn: FnFact): boolean => {
    if (!SIGNED_IN.test(chainText(n))) return false;
    let up = n.parent;
    while (up && UNWRAP.has(up.type)) up = up.parent;
    const onlyTests =
      up?.type === 'if_statement' ||
      (up?.type === 'unary_expression' && text(up).startsWith('!')) ||
      (up?.type === 'binary_expression' && /(?:===?|!==?)\s*(?:null|undefined)\b/.test(text(up)));
    if (!onlyTests) fn.ownerCheck = true;
    return true;
  };

  /** The values a log call writes, leaving out what's only tested or masked. */
  const valuesIn = (n: Ast, out: string[], literals: string[]) => {
    const each = (nodes: Ast[]) => nodes.forEach((c) => valuesIn(c, out, literals));
    switch (n.type) {
      case 'string':
      case 'template_string':
        for (const c of n.children) {
          if (c.type === 'string_fragment') literals.push(text(c));
          else if (c.type === 'template_substitution') each(c.children);
        }
        return;
      case 'identifier':
      case 'shorthand_property_identifier':
        out.push(text(n));
        return;
      case 'member_expression': {
        const name = text(field(n, 'property') ?? n);
        if (name !== 'length') out.push(name);
        return;
      }
      case 'subscript_expression': {
        const index = field(n, 'index');
        if (index?.type === 'string') out.push(text(index).slice(1, -1));
        return;
      }
      case 'call_expression': {
        const callee = field(n, 'function');
        const name = callee ? text(callee) : '';
        if (MASKING.test(name) || name === 'Boolean') return;
        if (callee?.type === 'member_expression') {
          // x.slice(-4) is the usual way to mask, and x.toString() is still x.
          const method = text(field(callee, 'property') ?? callee);
          if (/^(?:slice|substring|substr)$/.test(method) && /-\s*4\b/.test(text(field(n, 'arguments') ?? n))) return;
          const object = field(callee, 'object');
          if (object) valuesIn(object, out, literals);
        }
        each(field(n, 'arguments')?.children ?? []);
        return;
      }
      case 'unary_expression':
        if (!text(n).startsWith('!')) each(n.children);
        return;
      case 'binary_expression':
        if (!/^(?:===?|!==?|<=?|>=?)$/.test(text(field(n, 'operator') ?? n))) each(n.children);
        return;
      case 'ternary_expression':
        each(n.children.filter((c) => c.field !== 'condition'));
        return;
      case 'pair': {
        const key = field(n, 'key');
        const value = field(n, 'value');
        if (!value) return;
        valuesIn(value, out, literals);
        // { bvn: data.x } writes a BVN whatever the variable's called. { bvn: mask(x) } and { bvn: 'set' } don't.
        const opaque = value.type === 'member_expression' || value.type === 'identifier' || value.type === 'subscript_expression' || value.type === 'template_string';
        if (key && opaque) out.push(text(key).replace(/^['"]|['"]$/g, ''));
        return;
      }
      default:
        each(n.children);
    }
  };

  /** What a lookup's argument says: `id`, `{ id }`, `{ _id: x, userId }` or `{ where: { id } }`. */
  const idInArgument = (arg: Ast, fn: FnFact): { origins: Origin[]; scoped: boolean } | null => {
    if (arg.type !== 'object') {
      if (arg.type === 'string' || arg.type === 'number') return null;
      const origins = originsOf(arg, fn);
      return origins.length ? { origins, scoped: false } : null;
    }
    const where = arg.children.find((p) => p.type === 'pair' && text(field(p, 'key') ?? p) === 'where');
    const inner = where && field(where, 'value');
    if (inner?.type === 'object') return idInArgument(inner, fn);
    let origins: Origin[] = [];
    let scoped = false;
    for (const p of arg.children) {
      const key = p.type === 'shorthand_property_identifier' ? text(p) : p.type === 'pair' ? text(field(p, 'key') ?? p).replace(/['"]/g, '') : '';
      const from = originsOf(p.type === 'pair' ? (field(p, 'value') ?? p) : p, fn);
      if (ID_FIELD.test(key)) origins = from;
      else if (OWNER_FIELD.test(key) && !from.includes('request')) scoped = true;
    }
    return origins.length ? { origins, scoped } : null;
  };

  const addRoute = (call: Ast, line: number, path: string, method: string, handlers: Ast[]) => {
    const refs: string[] = [];
    const collect = (e: Ast) => {
      if (FUNCTION.has(e.type)) return;
      if (e.type === 'identifier' || e.type === 'property_identifier') refs.push(text(e));
      e.children.forEach(collect);
    };
    handlers.forEach(collect);
    const route: RouteFact = { line, path, writes: /^(?:post|put|patch|delete|all|use)$/.test(method), fn: null, refs };
    facts.routes.push(route);
    routeCalls.set(call, route);
  };

  /** A function handed straight to a route (or to a wrapper on it) is a handler, not a callback. */
  const routeOf = (n: Ast): RouteFact | undefined => {
    for (let up = n.parent; up && up.type !== 'statement_block' && !FUNCTION.has(up.type); up = up.parent) {
      const route = routeCalls.get(up);
      if (route) return route;
    }
    return undefined;
  };

  const handleCall = (n: Ast, fn: FnFact) => {
    const callee = field(n, 'function');
    const args = field(n, 'arguments');
    if (!callee || !args) return;
    const chain = chainText(callee).split('.');
    const method = chain[chain.length - 1]!;
    const receiver = chain[chain.length - 2] ?? '';
    const line = callee.type === 'member_expression' ? (field(callee, 'property')?.line ?? n.line) : n.line;
    const list = named(args);

    if ((chain.length === 1 && SIGNED_IN_CALL.test(method)) || OWNERSHIP_CALL.test(method)) fn.ownerCheck = true;

    const isLogMethod = /^(?:log|info|warn|error|debug|trace)$/.test(method);
    if (chain.length >= 2 && ((isLogMethod && /^(?:console|_?log(?:ger)?|\w*[lL]ogger)$/.test(receiver)) || /^(?:winston|pino)$/.test(receiver))) {
      const values: string[] = [];
      const literals: string[] = [];
      list.forEach((a) => valuesIn(a, values, literals));
      facts.logs.push({ line, fn: fn.id, values, literals });
      return;
    }

    if (/^(?:json|send)$/.test(method) && /^(?:res|reply|response)$/.test(chain[0]!) && list[0]?.type === 'object') {
      const fields: string[] = [];
      for (const p of list[0].children) {
        if (p.type === 'shorthand_property_identifier') fields.push(text(p));
        else if (p.type === 'pair' && field(p, 'value')?.type !== 'string') fields.push(text(field(p, 'key') ?? p));
      }
      facts.responses.push({ line, fn: fn.id, fields });
    }

    if (text(callee) === 'Math.random') {
      let named_ = '';
      for (let up = n.parent; up && !named_ && up.type !== 'statement_block' && up.type !== 'program'; up = up.parent) {
        if (up.type === 'variable_declarator') named_ = text(field(up, 'name') ?? up);
        else if (up.type === 'assignment_expression') named_ = text(field(up, 'left') ?? up);
        else if (up.type === 'pair') named_ = text(field(up, 'key') ?? up);
      }
      facts.randoms.push({ line, fn: fn.id, api: 'Math.random', context: `${named_} ${fn.name}` });
    }

    // router.post('/x', auth, handler)
    if (chain.length >= 2 && /^(?:post|put|patch|delete|all|use|get)$/.test(method) && list.length > 1) {
      const first = list[0]!;
      const literal = first.type === 'string' || (first.type === 'template_string' && !first.children.some((c) => c.type === 'template_substitution'));
      if (literal && (routers.has(receiver) || !OUTGOING.test(receiver))) {
        const path = text(first).slice(1, -1);
        const isRouter = routers.has(receiver) || path.startsWith('/') || path.startsWith(':') || /^(?:app|\w*[rR]outer|route|server)$/.test(receiver);
        if (isRouter) addRoute(n, line, path, method, list.slice(1));
      }
    }
    // router.route('/x').post(handler)
    const object = callee.type === 'member_expression' ? field(callee, 'object') : undefined;
    if (object?.type === 'call_expression' && /^(?:post|put|patch|delete|all)$/.test(method)) {
      const inner = field(object, 'function');
      const path = field(object, 'arguments')?.children.find((c) => c.named);
      if (inner && chainText(inner).endsWith('.route') && path?.type === 'string') addRoute(n, line, text(path).slice(1, -1), method, list);
    }

    if (BY_ID_METHOD.test(method) && chain.length >= 2 && !NOT_A_STORE.test(receiver) && !OUTGOING.test(receiver) && list[0]) {
      const found = idInArgument(list[0], fn);
      if (found) {
        facts.reads.push({ line, fn: fn.id, origins: found.origins, scoped: found.scoped, text: text(n) });
        return;
      }
    }
    if (list[0]?.type === 'string' || list[0]?.type === 'template_string') {
      const sql = text(list[0]);
      if (SQL_BY_ID.test(sql)) {
        const origins = [...new Set(list.flatMap((a) => originsOf(a, fn)))];
        if (origins.length) {
          facts.reads.push({ line, fn: fn.id, origins, scoped: SQL_OWNER.test(sql), text: sql });
          return;
        }
      }
    }
    facts.calls.push({ line, fn: fn.id, chain, args: list.map((a) => originsOf(a, fn)), text: text(n).slice(0, 300) });
  };

  const functionName = (n: Ast): string => {
    const own = field(n, 'name');
    if (own) return text(own);
    let up = n.parent;
    // export const h = wrap(async (req, res) => {})
    while (up && (up.type === 'arguments' || up.type === 'call_expression')) up = up.parent;
    if (up?.type === 'variable_declarator') return text(field(up, 'name') ?? up);
    if (up?.type === 'pair') return text(field(up, 'key') ?? up);
    if (up?.type === 'public_field_definition') return text(field(up, 'property') ?? up);
    if (up?.type === 'assignment_expression') return chainText(field(up, 'left') ?? up).split('.').pop()!;
    return '';
  };

  /** The class or object a member sits in. */
  const ownerOf = (n: Ast): string | undefined => {
    for (let up = n.parent; up && up.type !== 'statement_block' && !FUNCTION.has(up.type); up = up.parent) {
      if (up.type === 'class_body') return text(field(up.parent!, 'name') ?? up.parent!);
      if (up.type === 'object') return up.parent?.type === 'variable_declarator' ? text(field(up.parent, 'name') ?? up.parent) : undefined;
    }
    return undefined;
  };

  /** Decorators sit just before a method in its class body. */
  const decoratorsBefore = (n: Ast): Ast[] => {
    const siblings = n.parent?.children ?? [];
    const out: Ast[] = [];
    for (let i = siblings.indexOf(n) - 1; i >= 0 && siblings[i]!.type === 'decorator'; i--) out.unshift(siblings[i]!);
    return out;
  };

  /** Decorators on a class sit on it, or on its `export` statement. */
  const classDecorators = (n: Ast): Ast[] => {
    let up: Ast | null = n;
    while (up && up.type !== 'class_body') up = up.parent;
    const cls = up?.parent;
    if (!cls) return [];
    return [cls, ...(cls.parent ? [cls.parent] : [])].flatMap((h) => h.children.filter((c) => c.type === 'decorator'));
  };

  const addNestRoutes = (n: Ast, fn: FnFact, decorators: Ast[]) => {
    const onClass = classDecorators(n);
    const prefix = onClass.find((d) => decoratorName(d) === 'Controller');
    const first = (d: Ast) => {
      const call = named(d)[0];
      const arg = call?.type === 'call_expression' ? field(call, 'arguments')?.children.find((c) => c.named) : undefined;
      return arg?.type === 'string' ? text(arg).slice(1, -1) : '';
    };
    const names = [...onClass, ...decorators].map(decoratorName);
    if (names.some((d) => OWNERSHIP_DECORATOR.test(d))) fn.ownerCheck = true;
    if (names.some((d) => STAFF.test(d))) fn.staffOnly = true;
    for (const d of decorators) {
      const verb = decoratorName(d);
      if (!NEST_VERB.test(verb)) continue;
      fn.handler = true;
      const path = `/${[prefix ? first(prefix) : '', first(d)].filter(Boolean).join('/')}`.replace(/\/+/g, '/');
      facts.routes.push({ line: d.line, path, writes: verb !== 'Get', fn: fn.id, refs: names.filter((x) => !NEST_VERB.test(x)) });
    }
  };

  const enterFunction = (n: Ast, fn: FnFact) => {
    const route = routeOf(n);
    const up = n.parent;
    const standsAlone =
      route ||
      n.type === 'method_definition' ||
      n.type === 'function_declaration' ||
      n.type === 'generator_function_declaration' ||
      up?.type === 'variable_declarator' ||
      up?.type === 'pair' ||
      up?.type === 'assignment_expression' ||
      up?.type === 'public_field_definition' ||
      // export const h = wrap(async (req, res) => {})
      (fn === module && up?.type === 'arguments' && functionName(n) !== '');
    const body = field(n, 'body');
    if (!standsAlone) {
      // A callback run as part of the function around it: its code counts as that function's.
      const params = field(n, 'parameters')?.children ?? [field(n, 'parameter')!].filter(Boolean);
      if (params.some((p) => TRANSACTION_PARAM.test(text(p).split(/[:=]/)[0]!.trim()))) fn.atomic = true;
      if (body) visit(body, fn);
      return;
    }
    const isMember = n.type === 'method_definition' || up?.type === 'pair' || up?.type === 'public_field_definition';
    const decorators = decoratorsBefore(n);
    const next = startFunction(n, fn, { name: functionName(n), owner: isMember ? ownerOf(n) : undefined, decorators: decorators.map((d) => ({ line: d.line, text: text(d) })) });
    if (route) {
      route.fn = next.id;
      next.handler = true;
    }
    if (n.type === 'method_definition') addNestRoutes(n, next, decorators);
    if (NEXT_VERB.test(next.name) && fn === module && !next.owner) facts.routes.push({ line: n.line, path: file.path, writes: next.name !== 'GET', fn: next.id, refs: [] });
    for (const p of field(n, 'parameters')?.children ?? []) {
      // Names in the signature, so `@Headers('idempotency-key') key` counts as using the key.
      for (const d of p.children) if (d.type === 'decorator') next.names.add(text(d));
      const pattern = field(p, 'pattern') ?? p;
      if (pattern.type === 'identifier') next.names.add(text(pattern));
    }
    for (const d of decorators) next.names.add(decoratorName(d));
    if (body) visit(body, next);
  };

  const noteBalance = (left: Ast, fn: FnFact, line: number) => {
    if (/\.[jt]sx$/i.test(file.path)) return; // UI code works out running balances for display.
    if (left.type === 'member_expression') {
      if (/balance$/i.test(text(field(left, 'property') ?? left))) facts.balances.push({ line, fn: fn.id });
    } else if (left.type === 'identifier' && /balance$/i.test(text(left))) {
      facts.balances.push({ line, fn: fn.id, local: text(left) });
    }
  };

  /** Whether an expression works out a new balance from an old one. */
  const changesBalance = (e: Ast): boolean => {
    if (UNWRAP.has(e.type)) return e.children.some(changesBalance);
    if (e.type === 'binary_expression') return /^[-+]$/.test(text(field(e, 'operator') ?? e)) && /balance/i.test(code.slice(e.start, e.end));
    if (e.type === 'call_expression') {
      const callee = field(e, 'function');
      if (callee?.type === 'member_expression') return DECIMAL_MATH.test(text(field(callee, 'property') ?? callee)) && /balance/i.test(code.slice(callee.start, callee.end));
      return field(e, 'arguments')?.children.some(changesBalance) ?? false;
    }
    return false;
  };

  const visit = (n: Ast, fn: FnFact): void => {
    if (FUNCTION.has(n.type)) return enterFunction(n, fn);
    switch (n.type) {
      case 'identifier':
      case 'property_identifier':
      case 'shorthand_property_identifier': {
        const name = text(n);
        fn.names.add(name);
        // A name like `userId` that didn't come from the request. `findById(accountId)` above doesn't count.
        if (n.type !== 'property_identifier' && OWNER_NAME.test(name) && n.field !== 'name' && n.field !== 'function' && !lookup(fn, name)?.includes('request')) fn.ownerCheck = true;
        if (n.type === 'identifier') noteSignedIn(n, fn);
        break;
      }
      case 'import_statement': {
        const source = field(n, 'source');
        const from = source ? text(source).slice(1, -1) : '';
        for (const c of n.children.find((x) => x.type === 'import_clause')?.children ?? []) {
          if (c.type === 'identifier') facts.imports.push({ local: text(c), module: from, imported: 'default' });
          if (c.type === 'namespace_import') facts.imports.push({ local: text(named(c)[0] ?? c), module: from, imported: '' });
          if (c.type === 'named_imports') {
            for (const s of c.children) {
              if (s.type === 'import_specifier') facts.imports.push({ local: text(field(s, 'alias') ?? field(s, 'name') ?? s), module: from, imported: text(field(s, 'name') ?? s) });
            }
          }
        }
        return;
      }
      case 'variable_declarator': {
        const name = field(n, 'name');
        const value = field(n, 'value');
        if (!name || !value) break;
        bind(name, value, fn);
        const inner = value.type === 'await_expression' ? value.children[0] : value;
        if (inner?.type === 'call_expression' && text(field(inner, 'function') ?? inner) === 'require') {
          // const loans = require('./loans'), const { getLoan } = require('./loans')
          const required = field(inner, 'arguments')?.children.find((c) => c.type === 'string');
          if (required && name.type === 'identifier') facts.imports.push({ local: text(name), module: text(required).slice(1, -1), imported: '' });
          if (required && name.type === 'object_pattern') {
            for (const p of name.children) {
              if (p.type === 'shorthand_property_identifier_pattern') facts.imports.push({ local: text(p), module: text(required).slice(1, -1), imported: text(p) });
            }
          }
        }
        if (name.type === 'identifier') {
          if (value.type === 'new_expression') facts.instances.set(text(name), text(field(value, 'constructor') ?? value));
          if (MAKES_ROUTER.test(text(value))) routers.add(text(name));
          if (/otp/i.test(text(name)) && value.type === 'string' && /^['"]\d{4,8}['"]$/.test(text(value))) facts.fixedOtps.push(n.line);
          if (changesBalance(value)) computedBalances.add(text(name));
        }
        break;
      }
      case 'assignment_expression': {
        const left = field(n, 'left');
        const right = field(n, 'right');
        if (!left || !right) break;
        if (left.type === 'identifier') bind(left, right, fn);
        if (left.type === 'member_expression' && chainText(left).startsWith('this.') && right.type === 'new_expression') {
          facts.instances.set(chainText(left).split('.')[1]!, text(field(right, 'constructor') ?? right));
        }
        // wallet.balance = wallet.balance - amount, or wallet.balance = newBalance
        if (changesBalance(right) || (right.type === 'identifier' && computedBalances.has(text(right)))) noteBalance(left, fn, n.line);
        break;
      }
      case 'augmented_assignment_expression': {
        const left = field(n, 'left');
        if (left && /^[-+]=$/.test(text(field(n, 'operator') ?? n))) noteBalance(left, fn, n.line);
        break;
      }
      case 'member_expression':
        if (noteSignedIn(n, fn)) {
          // `req.user.id` shouldn't count `req.user` again, or test it on its own.
          fn.names.add(text(field(n, 'property') ?? n));
          return;
        }
        break;
      case 'binary_expression':
        // wallet.ownerId !== me
        if (/^[!=]==?$/.test(text(field(n, 'operator') ?? n))) {
          for (const side of [field(n, 'left'), field(n, 'right')]) {
            if (side?.type !== 'member_expression') continue;
            const name = text(field(side, 'property') ?? side);
            if ((OWNER_FIELD.test(name) || /^(?:owner|user|customer)$/.test(name)) && !originsOf(side, fn).includes('request')) fn.ownerCheck = true;
          }
        }
        break;
      case 'call_expression':
        // Before its arguments, so a route is known by the time its handler is reached.
        handleCall(n, fn);
        break;
      case 'public_field_definition': {
        const name = field(n, 'property');
        const value = field(n, 'value');
        if (name && value?.type === 'new_expression') facts.instances.set(text(name), text(field(value, 'constructor') ?? value));
        break;
      }
    }
    for (const c of n.children) visit(c, fn);
  };

  for (const n of root.children) visit(n, module);

  // What's left of the file once its functions are taken out.
  const top = noComments.split('\n');
  for (const fn of facts.fns.slice(1)) for (let i = fn.line; i < fn.endLine - 1; i++) top[i] = '';
  module.source = top.join('\n');
  module.persists = PERSISTS.test(module.source);
  module.atomic = ATOMIC.test(module.source);
  if (/(?:^|\/)admin\//i.test(file.path)) for (const fn of facts.fns) fn.staffOnly = true;
  return facts;
}
