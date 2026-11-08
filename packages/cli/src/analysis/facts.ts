import type { SourceFile } from '../rules/types';

import { extractJavaScript } from './javascript';
import { languageOf, parse, type Ast } from './parser';
import { extractPython } from './python';

/*
 * What a source file does, in terms that don't depend on its language: route handlers, records read
 * by ID, checks on who's signed in, transactions, log calls. Each language has an extractor that
 * produces these facts, and the rules only ever look at the facts.
 */

/** Where a value came from: the request, or the function's parameter with this index. */
export type Origin = 'request' | number;

export type Decorator = { line: number; text: string };

/** A function, or the file's top-level code (always fns[0], with an empty name). */
export type FnFact = {
  id: number;
  name: string;
  /** The class or object it's a member of. */
  owner?: string;
  line: number;
  endLine: number;
  params: string[];
  decorators: Decorator[];
  /** Answers a web request. */
  handler: boolean;
  /** Every name the code uses, including its decorators and signature. */
  names: Set<string>;
  /** Ties what it does to the signed-in user. Being signed in at all doesn't count. */
  ownerCheck: boolean;
  /** Staff only, so it may read anyone's records. */
  staffOnly: boolean;
  /** Runs in a transaction or holds a lock, as far as this language's libraries go. */
  atomic: boolean;
  /** Writes to storage. */
  persists: boolean;
  /** Its text: only for the checks that look for a word, such as a signature header's name. */
  source: string;
};

export type RouteFact = {
  line: number;
  path: string;
  /** Can change data. */
  writes: boolean;
  /** The function that handles it, when it's defined in place. */
  fn: number | null;
  /** Names on the route: its handler and middleware. */
  refs: string[];
};

/** A record loaded or changed by an ID. */
export type RecordRead = {
  line: number;
  fn: number;
  origins: Origin[];
  /** The query itself limits it to the signed-in user. */
  scoped: boolean;
  text: string;
};

export type CallFact = {
  /** The line of the called name, which is what a chained call is reported on. */
  line: number;
  fn: number;
  /** `this.loans.get(id)` is ['this', 'loans', 'get']. `new Loans().get(id)` is ['Loans()', 'get']. */
  chain: string[];
  /** Where each argument came from. */
  args: Origin[][];
  text: string;
};

export type LogFact = {
  line: number;
  fn: number;
  /** The values it writes, by name. Values that are only tested or masked aren't here. */
  values: string[];
  /** The text of its string literals. */
  literals: string[];
};

export type ResponseFact = {
  line: number;
  fn: number;
  /** The fields it sends, without those whose value is a plain string. */
  fields: string[];
};

export type BalanceUpdate = {
  line: number;
  fn: number;
  /** A local variable rather than a field of a record: only matters if it's then written somewhere. */
  local?: string;
};

export type RandomFact = {
  line: number;
  fn: number;
  /** The API used, for the finding's title. */
  api: string;
  /** Names around it, which say what the number is for. */
  context: string;
};

export type ImportFact = {
  /** The name it has in this file. */
  local: string;
  module: string;
  /** The name in that module; empty when `local` is the whole module. */
  imported: string;
};

export type FileFacts = {
  fns: FnFact[];
  routes: RouteFact[];
  reads: RecordRead[];
  /** Lines of classes that serve any record to anyone: Django REST's `queryset = Wallet.objects.all()`. */
  exposures: { line: number; text: string }[];
  calls: CallFact[];
  logs: LogFact[];
  responses: ResponseFact[];
  balances: BalanceUpdate[];
  randoms: RandomFact[];
  /** Lines that hard-code an OTP. */
  fixedOtps: number[];
  imports: ImportFact[];
  /** What a name holds: `loans` is an instance of `LoanService`, or a field injected with it. */
  instances: Map<string, string>;
};

export const emptyFacts = (): FileFacts => ({
  fns: [],
  routes: [],
  reads: [],
  exposures: [],
  calls: [],
  logs: [],
  responses: [],
  balances: [],
  randoms: [],
  fixedOtps: [],
  imports: [],
  instances: new Map(),
});

export const newFn = (id: number, fields: Partial<FnFact> = {}): FnFact => ({
  id,
  name: '',
  line: 1,
  endLine: 1,
  params: [],
  decorators: [],
  handler: false,
  names: new Set(),
  ownerCheck: false,
  staffOnly: false,
  atomic: false,
  persists: false,
  source: '',
  ...fields,
});

export const fieldOf = (n: Ast, name: string) => n.children.find((c) => c.field === name);
export const namedOf = (n: Ast) => n.children.filter((c) => c.named);

/** Copies of the text with comments blanked, and with the insides of strings blanked too, keeping every offset. */
export function blanked(text: string, root: Ast, comments: [number, number][], stringTypes: Set<string>): { noComments: string; code: string } {
  const out = text.split('');
  const blank = (from: number, to: number) => {
    for (let i = from; i < to; i++) if (out[i] !== '\n') out[i] = ' ';
  };
  for (const [from, to] of comments) blank(from, to);
  const noComments = out.join('');
  const stack = [root];
  while (stack.length) {
    const n = stack.pop()!;
    if (stringTypes.has(n.type)) blank(n.start, n.end);
    else stack.push(...n.children);
  }
  return { noComments, code: out.join('') };
}

const cache = new WeakMap<SourceFile, FileFacts>();
let failures = 0;

/** How many files couldn't be analysed since the last call. */
export function takeAnalysisFailures(): number {
  const n = failures;
  failures = 0;
  return n;
}

/** The facts of a file, worked out once. The grammar has to be loaded first (see loadGrammars). */
export function factsFor(file: SourceFile): FileFacts {
  const known = cache.get(file);
  if (known) return known;
  const language = languageOf(file.path);
  let facts = emptyFacts();
  if (language) {
    try {
      const { root, comments } = parse(language, file.text);
      facts = language === 'python' ? extractPython(file, root, comments) : extractJavaScript(file, root, comments);
    } catch (err) {
      if (err instanceof Error && /grammar isn't loaded/.test(err.message)) throw err;
      failures++; // A file that can't be read must be reported as such, not as clean.
    }
  }
  cache.set(file, facts);
  return facts;
}
