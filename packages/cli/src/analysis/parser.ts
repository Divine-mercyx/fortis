import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { brotliDecompressSync } from 'node:zlib';

import TreeSitter from '@vscode/tree-sitter-wasm';

/*
 * Parsing with Tree-sitter, compiled to WebAssembly so one engine reads every language and the CLI
 * stays a single file. The published CLI carries the grammars compressed inside it (see build.mjs)
 * and only unpacks the ones a repository needs.
 */

export type Language = 'javascript' | 'typescript' | 'tsx' | 'python';

const GRAMMARS: Record<Language, string> = {
  javascript: 'tree-sitter-javascript',
  typescript: 'tree-sitter-typescript',
  tsx: 'tree-sitter-tsx',
  python: 'tree-sitter-python',
};

export const languageOf = (path: string): Language | null => {
  if (/\.tsx$/i.test(path)) return 'tsx';
  if (/\.[cm]?ts$/i.test(path)) return 'typescript';
  if (/\.[cm]?jsx?$/i.test(path)) return 'javascript';
  if (/\.py$/i.test(path)) return 'python';
  return null;
};

/** Set by build.mjs: each grammar, Brotli-compressed and in base64. Absent when running from source. */
declare const __FORTIS_GRAMMARS__: Record<string, string> | undefined;

function wasm(name: string): Uint8Array {
  if (typeof __FORTIS_GRAMMARS__ !== 'undefined') return brotliDecompressSync(Buffer.from(__FORTIS_GRAMMARS__[name]!, 'base64'));
  return readFileSync(createRequire(import.meta.url).resolve(`@vscode/tree-sitter-wasm/wasm/${name}.wasm`));
}

let engine: Promise<void> | undefined;
const parsers = new Map<Language, TreeSitter.Parser>();

/** Loads the engine and these grammars. Call before parsing: parsing itself is synchronous, loading isn't. */
export async function loadGrammars(languages: Iterable<Language>): Promise<void> {
  engine ??= TreeSitter.Parser.init({ wasmBinary: wasm('tree-sitter') } as unknown as Parameters<typeof TreeSitter.Parser.init>[0]);
  await engine;
  for (const language of new Set(languages)) {
    if (parsers.has(language)) continue;
    const parser = new TreeSitter.Parser();
    parser.setLanguage(await TreeSitter.Language.load(wasm(GRAMMARS[language])));
    parsers.set(language, parser);
  }
}

export const ALL_LANGUAGES = Object.keys(GRAMMARS) as Language[];

/** A syntax tree as plain objects, so nothing has to be freed and rules never touch the engine. */
export type Ast = {
  type: string;
  /** Offsets into the text, and 1-based lines. */
  start: number;
  end: number;
  line: number;
  endLine: number;
  /** The node's name in its parent, such as `function` or `arguments`. */
  field: string | null;
  named: boolean;
  children: Ast[];
  parent: Ast | null;
};

/** Parses a file. Comments and most punctuation are left out: only named nodes, and tokens with a field name. */
export function parse(language: Language, text: string): { root: Ast; comments: [number, number][] } {
  const parser = parsers.get(language);
  if (!parser) throw new Error(`The ${language} grammar isn't loaded`);
  const tree = parser.parse(text);
  if (!tree) throw new Error(`Could not parse this ${language} file`);
  const cursor = tree.walk();
  const comments: [number, number][] = [];
  const make = (parent: Ast | null): Ast => ({
    type: cursor.nodeType,
    start: cursor.startIndex,
    end: cursor.endIndex,
    line: cursor.startPosition.row + 1,
    endLine: cursor.endPosition.row + 1,
    field: cursor.currentFieldName,
    named: cursor.nodeIsNamed,
    children: [],
    parent,
  });
  const root = make(null);
  let current = root;
  // Walks with the cursor instead of recursing: real files can nest deeply enough to overflow the stack.
  for (;;) {
    if (cursor.gotoFirstChild()) {
      for (;;) {
        const type = cursor.nodeType;
        if (type === 'comment') comments.push([cursor.startIndex, cursor.endIndex]);
        else if (cursor.nodeIsNamed || cursor.currentFieldName) {
          const node = make(current);
          current.children.push(node);
          if (cursor.gotoFirstChild()) {
            cursor.gotoParent();
            current = node;
            break;
          }
        }
        if (cursor.gotoNextSibling()) continue;
        // Out of siblings: climb until one has a next sibling.
        for (;;) {
          cursor.gotoParent();
          if (current === root) {
            cursor.delete();
            tree.delete();
            return { root, comments };
          }
          current = current.parent!;
          if (cursor.gotoNextSibling()) break;
        }
        // Loop on: the cursor is on the next sibling at this level.
        continue;
      }
      continue;
    }
    cursor.delete();
    tree.delete();
    return { root, comments };
  }
}
