import type { SourceFile } from '../rules/types';

import { blanked, emptyFacts, fieldOf as field, namedOf as named, newFn, type FileFacts, type FnFact, type Origin } from './facts';
import type { Ast } from './parser';
import { MASKING, OWNER_FIELD, OWNER_NAME } from './words';

/* Facts for Python: Django with Django REST, Flask and FastAPI, on the Django ORM, SQLAlchemy and raw SQL. */

const STRING_PARTS = new Set(['string_content', 'escape_sequence']);
const ROUTE_DECORATOR = /^@[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(|^@(?:api_view|action|require_POST|require_GET|require_http_methods|csrf_exempt)\b/;
const VIEW_METHOD = /^(?:get|post|put|patch|delete|retrieve|update|partial_update|destroy|list|create)$/;
const WRITE_VIEW_METHOD = /^(?:post|put|patch|create|update|partial_update)$/;
const WRITE_DECORATOR = [
  /^@[\w.]+\.(?:post|put|patch)\s*\(/,
  /^@[\w.]+\.(?:route|api_route)\s*\([\s\S]*methods\s*=[^)]*["'](?:POST|PUT|PATCH)["']/i,
  /^@require_POST\b/,
  /^@(?:api_view|require_http_methods)\s*\([^)]*["'](?:POST|PUT|PATCH)["']/i,
  /^@action\s*\([^)]*methods\s*=[^)]*["'](?:post|put|patch)["']/i,
];
const ROUTE_PATH = /^@[\w.]+\.(?:route|get|post|put|patch|delete|api_route)\s*\(\s*f?["']([^"']*)["']/;
const SQL_BY_ID = /\b(?:select|update|delete)\b[\s\S]*\bwhere\s+(?:\w+\.)?id\s*=\s*(?:%s|\?|:\w+|%\(\w+\)s)/i;
const SQL_OWNER = /\b(?:user|owner|customer|account|wallet|merchant|tenant|org)_id\s*=/i;
const ID_KEYWORD = /^(?:pk|id|uuid)$/;
const OWNER_KEYWORD = /^(?:user|owner|customer)(?:_id)?$/;
const SIGNED_IN = /^(?:self\.)?request\.user\b|^current_user\b|^g\.user\b|^user\.id\b/;
const OWNERSHIP_CALL = /^(?:check_object_permissions|get_queryset|has_object_permission)$|(?:assert|check|verify|ensure|require|validate|enforce)_\w*(?:own|access|permission)/;
const STAFF = /staff_member_required|\badmin_required\b|IsAdminUser|\bis_staff\b|\bis_superuser\b|\/admin\//;
const SINGLE_RECORD_VIEW = /ModelViewSet|Retrieve\w*APIView|Update\w*APIView|Destroy\w*APIView|RetrieveModelMixin/;
const SCOPED_VIEW = /\bdef\s+get_queryset\b|request\.user|IsOwner|has_object_permission|check_object_permissions/;
/** `transaction.atomic` alone isn't here: without a row lock, a read-then-write can still lose an update. */
const LOCKED = /select_for_update|with_for_update|for_update|FOR UPDATE|\bF\s*\(\s*["']\w*balance/i;
const WRITES_BACK = /\.save\s*\(|\.commit\s*\(|\.flush\s*\(|\.execute\s*\(/;
const LOGGER = /^(?:_?log(?:ging|ger)?|\w*_log(?:ger)?|\w*logger|LOG|LOGGER|_LOGGER)$/i;
const LOG_METHOD = /^(?:debug|info|warning|warn|error|exception|critical|log|msg)$/;
const WEAK_RANDOM = /^(?:randint|randrange|choice|choices|random|sample|getrandbits)$/;

export function extractPython(file: SourceFile, root: Ast, comments: [number, number][]): FileFacts {
  const facts = emptyFacts();
  const src = file.text;
  const { noComments } = blanked(src, root, comments, STRING_PARTS);
  const text = (n: Ast) => src.slice(n.start, n.end);
  const module = newFn(0, { endLine: file.lines.length });
  facts.fns.push(module);
  const flows = new Map<FnFact, Map<string, Origin[]>>([[module, new Map()]]);

  const chainText = (n: Ast): string => {
    if (n.type === 'identifier') return text(n);
    if (n.type === 'attribute') {
      const object = field(n, 'object');
      const attribute = field(n, 'attribute');
      return object && attribute ? `${chainText(object)}.${text(attribute)}` : '?';
    }
    if (n.type === 'call') return `${chainText(field(n, 'function') ?? n.children[0]!)}()`;
    if (n.type === 'await' || n.type === 'parenthesized_expression') return n.children[0] ? chainText(n.children[0]) : '?';
    if (n.type === 'subscript') return `${chainText(field(n, 'value') ?? n.children[0]!)}[]`;
    return '?';
  };

  const originsOf = (n: Ast, fn: FnFact): Origin[] => {
    const out = new Set<Origin>();
    const known = flows.get(fn)!;
    const visit = (e: Ast) => {
      if (e.type === 'identifier') {
        const name = text(e);
        if (name === 'kwargs') out.add('request');
        for (const o of known.get(name) ?? []) out.add(o);
        return;
      }
      if (e.type === 'attribute') {
        const chain = chainText(e);
        if (/^(?:self\.)?request\.(?!user\b)/.test(chain) || /^self\.kwargs\b/.test(chain)) {
          out.add('request');
          return;
        }
        const object = field(e, 'object');
        if (object) visit(object);
        return;
      }
      if (e.type === 'call') {
        // str(x) and x.strip() carry x along. `service.get(x)` makes something new.
        const callee = field(e, 'function');
        if (callee?.type === 'attribute') {
          const object = field(callee, 'object');
          if (object) visit(object);
        } else {
          field(e, 'arguments')?.children.forEach(visit);
        }
        return;
      }
      if (e.type === 'keyword_argument') {
        const value = field(e, 'value');
        if (value) visit(value);
        return;
      }
      if (e.type === 'string') {
        e.children.filter((c) => c.type === 'interpolation').forEach(visit);
        return;
      }
      e.children.forEach(visit);
    };
    visit(n);
    return [...out];
  };

  const valuesIn = (n: Ast, out: string[], literals: string[]) => {
    const each = (nodes: Ast[]) => nodes.forEach((c) => valuesIn(c, out, literals));
    switch (n.type) {
      case 'string':
        for (const c of n.children) {
          if (c.type === 'string_content') literals.push(text(c));
          else if (c.type === 'interpolation') each(named(c).filter((x) => x.field === 'expression'));
        }
        return;
      case 'identifier':
        out.push(text(n));
        return;
      case 'attribute':
        out.push(text(field(n, 'attribute') ?? n));
        return;
      case 'subscript': {
        const index = field(n, 'subscript');
        // x[-4:] is the usual way to mask.
        if (index?.type === 'slice' && /^-\s*4\s*:/.test(text(index))) return;
        if (index?.type === 'string') out.push(text(index).replace(/^['"]|['"]$/g, ''));
        else valuesIn(field(n, 'value') ?? n, out, literals);
        return;
      }
      case 'call': {
        const callee = field(n, 'function');
        const name = callee ? text(callee) : '';
        if (MASKING.test(name) || /^(?:bool|len)$/.test(name)) return;
        // "...".format(x) and x.strip() are still x.
        if (callee?.type === 'attribute') {
          const object = field(callee, 'object');
          if (object) valuesIn(object, out, literals);
        }
        each(field(n, 'arguments')?.children ?? []);
        return;
      }
      case 'comparison_operator':
      case 'not_operator':
        return;
      case 'conditional_expression': {
        // a if test else b
        const [yes, , no] = named(n);
        each([yes, no].filter((x): x is Ast => Boolean(x)));
        return;
      }
      case 'keyword_argument':
      case 'pair': {
        const key = field(n, n.type === 'pair' ? 'key' : 'name');
        const value = field(n, 'value');
        if (!value) return;
        valuesIn(value, out, literals);
        // log.info("kyc", bvn=data["x"]) writes a BVN whatever the variable's called.
        const opaque = value.type === 'attribute' || value.type === 'identifier' || value.type === 'subscript';
        if (key && opaque) out.push(text(key).replace(/^['"]|['"]$/g, ''));
        return;
      }
      default:
        each(n.children);
    }
  };

  const handleCall = (n: Ast, fn: FnFact) => {
    const callee = field(n, 'function');
    const args = field(n, 'arguments');
    if (!callee || !args) return;
    const chain = chainText(callee).split('.');
    const method = chain[chain.length - 1]!;
    const receiver = chain[chain.length - 2] ?? '';
    const line = callee.type === 'attribute' ? (field(callee, 'attribute')?.line ?? n.line) : n.line;
    const list = named(args);
    const keyword = (name: RegExp) => list.filter((a) => a.type === 'keyword_argument' && name.test(text(field(a, 'name') ?? a)));
    const positional = list.filter((a) => a.type !== 'keyword_argument');

    if (OWNERSHIP_CALL.test(method)) fn.ownerCheck = true;

    if ((chain.length === 1 && method === 'print') || (chain.length >= 2 && LOG_METHOD.test(method) && LOGGER.test(receiver))) {
      const values: string[] = [];
      const literals: string[] = [];
      list.forEach((a) => valuesIn(a, values, literals));
      facts.logs.push({ line, fn: fn.id, values, literals });
      return;
    }

    if (/^(?:JsonResponse|Response|jsonify)$/.test(method)) {
      const fields = keyword(/.*/)
        .filter((a) => field(a, 'value')?.type !== 'string')
        .map((a) => text(field(a, 'name') ?? a));
      for (const a of positional) if (a.type === 'dictionary') fields.push(...dictionaryFields(a));
      if (fields.length) facts.responses.push({ line, fn: fn.id, fields });
    }

    if (chain.length === 2 && receiver === 'random' && WEAK_RANDOM.test(method)) {
      const statement = enclosingStatement(n);
      facts.randoms.push({ line, fn: fn.id, api: 'random', context: `${statement ? targetOf(statement) : ''} ${fn.name}` });
    }

    // Records read by ID, in each library's own form.
    const byId = (idValue: Ast | undefined, scoped = false) => {
      if (!idValue) return false;
      const origins = originsOf(idValue, fn);
      if (!origins.length) return false;
      const ownerKeyword = keyword(OWNER_KEYWORD).some((a) => !originsOf(a, fn).includes('request'));
      facts.reads.push({ line, fn: fn.id, origins, scoped: scoped || ownerKeyword, text: text(n) });
      return true;
    };
    const idKeyword = keyword(ID_KEYWORD)[0];
    const idKeywordValue = idKeyword && field(idKeyword, 'value');
    const whole = chainText(callee);
    let handled = false;
    if (/\.objects\.(?:get|filter)$/.test(whole) || method === 'get_object_or_404' || method === 'filter_by') handled = byId(idKeywordValue);
    else if (/^(?:\w*session|db|database)$/.test(receiver) && method === 'get' && positional.length >= 2) handled = byId(positional[1]);
    else if (/\.query\.(?:get|get_or_404)$/.test(whole) || /\.query\(\)\.get$/.test(whole)) handled = byId(positional[0]);
    else if (/^(?:filter|where)$/.test(method)) {
      // Wallet.id == id
      const comparisons = positional.filter((a) => a.type === 'comparison_operator');
      for (const c of comparisons) {
        const [left, right] = named(c);
        if (left?.type === 'attribute' && /^(?:id|uuid)$/.test(text(field(left, 'attribute') ?? left)) && right) {
          handled = byId(right);
          break;
        }
      }
    }
    if (handled) return;

    if (positional[0]?.type === 'string' || positional[0]?.type === 'concatenated_string') {
      const sql = text(positional[0]);
      if (SQL_BY_ID.test(sql)) {
        // Whatever fills the query's placeholder: a handler's parameters come from the URL.
        const origins = [...new Set(list.flatMap((a) => originsOf(a, fn)))];
        if (origins.length) {
          facts.reads.push({ line, fn: fn.id, origins, scoped: SQL_OWNER.test(sql), text: sql });
          return;
        }
      }
    }
    facts.calls.push({ line, fn: fn.id, chain, args: positional.map((a) => originsOf(a, fn)), text: text(n).slice(0, 300) });
  };

  const dictionaryFields = (d: Ast) =>
    d.children
      .filter((p) => p.type === 'pair' && field(p, 'value')?.type !== 'string')
      .map((p) => text(field(p, 'key') ?? p).replace(/^['"]|['"]$/g, ''));

  const enclosingStatement = (n: Ast): Ast | null => {
    for (let up = n.parent; up; up = up.parent) if (up.type === 'assignment' || up.type === 'expression_statement' || up.type === 'return_statement') return up;
    return null;
  };
  const targetOf = (statement: Ast) => (statement.type === 'assignment' ? text(field(statement, 'left') ?? statement) : '');

  const isBalanceName = (name: string) => /balance$/i.test(name);

  const noteBalance = (left: Ast, fn: FnFact, line: number) => {
    if (left.type === 'attribute') {
      if (isBalanceName(text(field(left, 'attribute') ?? left))) facts.balances.push({ line, fn: fn.id });
    } else if (left.type === 'identifier' && isBalanceName(text(left))) {
      facts.balances.push({ line, fn: fn.id, local: text(left) });
    }
  };

  const changesBalance = (e: Ast): boolean => {
    if (e.type === 'parenthesized_expression' || e.type === 'await') return e.children.some(changesBalance);
    if (e.type !== 'binary_operator') return false;
    return /^[-+]$/.test(text(field(e, 'operator') ?? e)) && /balance/i.test(text(field(e, 'left') ?? e));
  };

  const readParams = (n: Ast, fn: FnFact) => {
    for (const p of named(field(n, 'parameters') ?? n)) {
      const nameNode = field(p, 'name') ?? (p.type === 'identifier' ? p : named(p).find((c) => c.type === 'identifier'));
      const name = nameNode ? text(nameNode) : '';
      if (!name || name === 'self' || name === 'cls') continue;
      fn.params.push(name);
      fn.names.add(name);
    }
  };

  const isHandler = (fn: FnFact, classBases: string) => {
    if (fn.decorators.some((d) => ROUTE_DECORATOR.test(d.text))) return true;
    if (fn.owner) return VIEW_METHOD.test(fn.name) && /View|ViewSet|Mixin/.test(`${classBases} ${fn.owner}`);
    return fn.params[0] === 'request';
  };

  const enterFunction = (n: Ast, parent: FnFact, decorators: Ast[], owner?: string, classBases = '') => {
    const body = field(n, 'body');
    const source = noComments.slice(n.start, n.end);
    const fn = newFn(facts.fns.length, {
      name: text(field(n, 'name') ?? n),
      owner,
      line: n.line,
      endLine: n.endLine,
      decorators: decorators.map((d) => ({ line: d.line, text: text(d) })),
      source,
      persists: WRITES_BACK.test(source),
      atomic: LOCKED.test(source),
    });
    facts.fns.push(fn);
    readParams(n, fn);
    fn.handler = isHandler(fn, classBases);
    // A handler's parameters come from the URL, unless they're injected: `db=Depends(get_db)`.
    const known = new Map<string, Origin[]>();
    flows.set(fn, known);
    fn.params.forEach((p, i) => {
      if (p === 'request') return;
      const declared = named(field(n, 'parameters') ?? n).find((x) => (field(x, 'name') ? text(field(x, 'name')!) : text(x).split(':')[0]!.trim()) === p);
      const injected = declared ? /\bDepends\s*\(/.test(text(declared)) : false;
      known.set(p, fn.handler && !injected ? ['request', i] : injected ? [] : [i]);
    });
    if (decorators.length) for (const d of decorators) fn.names.add(text(d));
    const route = decorators.map((d) => ROUTE_PATH.exec(text(d))?.[1]).find((p) => p !== undefined);
    if (fn.handler) {
      const writes =
        fn.decorators.some((d) => WRITE_DECORATOR.some((re) => re.test(d.text))) ||
        (Boolean(fn.owner) && WRITE_VIEW_METHOD.test(fn.name)) ||
        /request\.method\s*(?:==|in)\s*[[(]?\s*["'](?:POST|PUT|PATCH)["']/.test(source);
      const line = decorators.find((d) => /webhook|transfer|payout|withdraw|disburs|send[-_]?money/i.test(text(d)))?.line ?? n.line;
      facts.routes.push({ line, path: route ?? '', writes, fn: fn.id, refs: [] });
    }
    fn.staffOnly = STAFF.test(`${decorators.map(text).join('\n')}\n${fn.name}\n${classBases}\n${source}`);
    if (body) visit(body, fn);
    // Only an owner check inside the body counts, so FastAPI's unused `me=Depends(...)` doesn't.
  };

  const enterClass = (n: Ast, parent: FnFact, decorators: Ast[]) => {
    const name = text(field(n, 'name') ?? n);
    const bases = field(n, 'superclasses') ? text(field(n, 'superclasses')!) : '';
    const body = field(n, 'body');
    if (!body) return;
    const source = noComments.slice(n.start, n.end);
    for (const c of body.children) {
      if (c.type === 'function_definition') enterFunction(c, parent, [], name, bases);
      else if (c.type === 'decorated_definition') {
        const def = field(c, 'definition');
        if (def?.type === 'function_definition') enterFunction(def, parent, c.children.filter((x) => x.type === 'decorator'), name, bases);
        else if (def?.type === 'class_definition') enterClass(def, parent, c.children.filter((x) => x.type === 'decorator'));
      } else if (c.type === 'class_definition') enterClass(c, parent, []);
      else if (c.type === 'expression_statement') {
        // queryset = Wallet.objects.all() on a view that serves single records
        const a = named(c)[0];
        if (a?.type !== 'assignment' || text(field(a, 'left') ?? a) !== 'queryset') continue;
        const right = field(a, 'right');
        if (right?.type !== 'call' || !/\.objects\.all$/.test(chainText(field(right, 'function') ?? right))) continue;
        if (SINGLE_RECORD_VIEW.test(bases) && !SCOPED_VIEW.test(source) && !STAFF.test(source)) facts.exposures.push({ line: c.line, text: `${name} ${text(c)}\n${source}` });
      }
    }
    void decorators;
  };

  const visit = (n: Ast, fn: FnFact): void => {
    switch (n.type) {
      case 'function_definition':
        enterFunction(n, fn, []);
        return;
      case 'class_definition':
        enterClass(n, fn, []);
        return;
      case 'decorated_definition': {
        const def = field(n, 'definition');
        const decorators = n.children.filter((c) => c.type === 'decorator');
        if (def?.type === 'function_definition') enterFunction(def, fn, decorators);
        else if (def?.type === 'class_definition') enterClass(def, fn, decorators);
        return;
      }
      case 'import_from_statement': {
        const from = field(n, 'module_name');
        const prefix = from ? text(from) : '';
        for (const c of n.children) {
          if (c.field !== 'name') continue;
          if (c.type === 'aliased_import') facts.imports.push({ local: text(field(c, 'alias') ?? c), module: prefix, imported: text(field(c, 'name') ?? c) });
          else facts.imports.push({ local: text(c), module: prefix, imported: text(c) });
        }
        return;
      }
      case 'import_statement':
        for (const c of n.children) {
          if (c.field !== 'name') continue;
          if (c.type === 'aliased_import') facts.imports.push({ local: text(field(c, 'alias') ?? c), module: text(field(c, 'name') ?? c), imported: '' });
          else facts.imports.push({ local: text(c), module: text(c), imported: '' });
        }
        return;
      case 'identifier': {
        const name = text(n);
        fn.names.add(name);
        // A name like `user_id` that didn't come from the request.
        if (OWNER_NAME.test(name) && n.field !== 'function' && n.parent?.type !== 'keyword_argument' && !flows.get(fn)?.get(name)?.includes('request')) fn.ownerCheck = true;
        if (/^current_user$/.test(name) && !isAuthenticatedTest(n)) fn.ownerCheck = true;
        break;
      }
      case 'attribute': {
        const chain = chainText(n);
        fn.names.add(text(field(n, 'attribute') ?? n));
        if (SIGNED_IN.test(chain)) {
          // `expense.owner = request.user` saves a record; it doesn't check one.
          if (!isAuthenticatedTest(n) && !isSavingOwner(n)) fn.ownerCheck = true;
          return;
        }
        break;
      }
      case 'keyword_argument': {
        const name = text(field(n, 'name') ?? n);
        const value = field(n, 'value');
        fn.names.add(name);
        if (OWNER_KEYWORD.test(name) && value && !originsOf(value, fn).includes('request')) fn.ownerCheck = true;
        break;
      }
      case 'comparison_operator': {
        // transfer.owner != me
        for (const side of named(n)) {
          if (side.type !== 'attribute') continue;
          const name = text(field(side, 'attribute') ?? side);
          if ((OWNER_FIELD.test(name) || OWNER_KEYWORD.test(name)) && !originsOf(side, fn).includes('request')) {
            // Only when the other side isn't the URL: `Wallet.user_id == user_id` from a path is no check.
            const others = named(n).filter((o) => o !== side);
            if (!others.some((o) => originsOf(o, fn).includes('request'))) fn.ownerCheck = true;
          }
        }
        break;
      }
      case 'assignment': {
        const left = field(n, 'left');
        const right = field(n, 'right');
        if (!left || !right) break;
        if (left.type === 'identifier') {
          const origins = originsOf(right, fn);
          if (origins.length) flows.get(fn)!.set(text(left), origins);
          if (/otp/i.test(text(left)) && right.type === 'string' && /^["']\d{4,8}["']$/.test(text(right))) facts.fixedOtps.push(n.line);
          // A class-level or module-level `x = LoanService()`
          if (right.type === 'call') facts.instances.set(text(left), chainText(field(right, 'function') ?? right));
        }
        if (left.type === 'attribute' && right.type === 'call' && chainText(left).startsWith('self.')) {
          facts.instances.set(chainText(left).split('.')[1]!, chainText(field(right, 'function') ?? right));
        }
        if (changesBalance(right)) noteBalance(left, fn, n.line);
        break;
      }
      case 'augmented_assignment': {
        const left = field(n, 'left');
        if (left && /^[-+]=$/.test(text(field(n, 'operator') ?? n))) noteBalance(left, fn, n.line);
        break;
      }
      case 'return_statement': {
        const value = named(n)[0];
        if (value?.type === 'dictionary') {
          const fields = dictionaryFields(value);
          if (fields.length) facts.responses.push({ line: n.line, fn: fn.id, fields });
        }
        break;
      }
      case 'call':
        handleCall(n, fn);
        break;
    }
    for (const c of n.children) visit(c, fn);
  };

  const isAuthenticatedTest = (n: Ast) => /\.is_(?:authenticated|active|anonymous)$/.test(text(n)) || (n.parent?.type === 'attribute' && /\.is_(?:authenticated|active|anonymous)$/.test(text(n.parent)));
  const isSavingOwner = (n: Ast) => n.parent?.type === 'assignment' && n.field === 'right' && field(n.parent, 'left')?.type === 'attribute';

  for (const n of root.children) visit(n, module);

  const top = noComments.split('\n');
  for (const fn of facts.fns.slice(1)) for (let i = fn.line - 1; i < fn.endLine; i++) top[i] = '';
  module.source = top.join('\n');
  module.persists = WRITES_BACK.test(module.source);
  module.atomic = LOCKED.test(module.source);
  return facts;
}
