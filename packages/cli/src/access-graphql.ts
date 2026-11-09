import type { GraphqlCheck } from './access';

/*
 * Builds access checks from a GraphQL schema: every query that reads one record by ID, paired with
 * the mutations that create, update and delete that record. The result goes into the config file
 * for review. Generated mutation values are placeholders, and mutations only run with --writes.
 */

export const INTROSPECTION_QUERY = `query FortisIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name
      fields { name args { name type { ...T } } type { ...T } }
      inputFields { name type { ...T } }
      enumValues { name }
    }
  }
}
fragment T on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }`;

type TypeRef = { kind: string; name?: string | null; ofType?: TypeRef | null };
type Arg = { name: string; type: TypeRef };
type Field = { name: string; args?: Arg[]; type: TypeRef };
type GqlType = { kind: string; name: string; fields?: Field[] | null; inputFields?: Arg[] | null; enumValues?: { name: string }[] | null };
export type GraphqlSchema = { queryType?: { name: string } | null; mutationType?: { name: string } | null; types: GqlType[] };

const named = (t: TypeRef): TypeRef => (t.ofType ? named(t.ofType) : t);
const required = (t: TypeRef) => t.kind === 'NON_NULL';
const isList = (t: TypeRef): boolean => (t.kind === 'NON_NULL' ? isList(t.ofType!) : t.kind === 'LIST');
const typeName = (t: TypeRef): string => {
  if (t.kind === 'NON_NULL') return `${typeName(t.ofType!)}!`;
  if (t.kind === 'LIST') return `[${typeName(t.ofType!)}]`;
  return t.name ?? 'String';
};

const isIdArg = (a: Arg) => /^(id|.*Id|.*_id|.*ID)$/.test(a.name) && ['ID', 'String', 'Int'].includes(named(a.type).name ?? '');

/** Reads the schema out of an introspection response, or the __schema object on its own. */
export function schemaFrom(json: unknown): GraphqlSchema {
  const j = json as { data?: { __schema?: GraphqlSchema }; __schema?: GraphqlSchema; errors?: { message?: string }[] };
  const schema = j?.data?.__schema ?? j?.__schema;
  if (!schema) throw new Error(j?.errors?.[0]?.message ?? 'The response has no schema. Introspection may be turned off on this server.');
  return schema;
}

export function checksFromGraphqlSchema(schema: GraphqlSchema): { checks: GraphqlCheck[]; notes: string[] } {
  const types = new Map(schema.types.map((t) => [t.name, t]));
  const fieldsOf = (name?: string | null) => (name ? (types.get(name)?.fields ?? []) : []);
  const queries = fieldsOf(schema.queryType?.name ?? 'Query');
  const mutations = fieldsOf(schema.mutationType?.name ?? 'Mutation');

  const isLeaf = (f: Field) => ['SCALAR', 'ENUM'].includes(named(f.type).kind) && !(f.args ?? []).some((a) => required(a.type));
  /** The scalar fields, so B's answer can be compared with A's. */
  const selection = (t: TypeRef): string => {
    const fields = fieldsOf(named(t).name).filter(isLeaf).map((f) => f.name);
    return fields.length ? ` { ${fields.slice(0, 20).join(' ')} }` : '';
  };
  const hasLeaves = (t: TypeRef) => named(t).kind === 'OBJECT' && fieldsOf(named(t).name).some(isLeaf);
  const idFieldOf = (t: TypeRef) => {
    const leaves = fieldsOf(named(t).name).filter(isLeaf).map((f) => f.name);
    return leaves.find((f) => f === 'id') ?? leaves.find((f) => /(Id|_id|ID)$/.test(f)) ?? 'id';
  };

  /** Finds the query that lists records of this type: directly, or through nodes, items or edges. */
  const listQuery = (typeWanted: string, id: string): string | undefined => {
    for (const q of queries) {
      if ((q.args ?? []).some((a) => required(a.type))) continue;
      if (isList(q.type) && named(q.type).name === typeWanted) return `query { ${q.name} { ${id} } }`;
      for (const inner of fieldsOf(named(q.type).name)) {
        if (['nodes', 'items', 'results'].includes(inner.name) && isList(inner.type) && named(inner.type).name === typeWanted) return `query { ${q.name} { ${inner.name} { ${id} } } }`;
        if (inner.name === 'edges' && isList(inner.type) && fieldsOf(named(inner.type).name).some((f) => f.name === 'node' && named(f.type).name === typeWanted)) return `query { ${q.name} { edges { node { ${id} } } } }`;
      }
    }
    return undefined;
  };

  /** A made-up value for an argument. Everything generated goes into the config for review. */
  const sample = (t: TypeRef, withOptional: boolean, depth = 0): unknown => {
    if (t.kind === 'NON_NULL') return sample(t.ofType!, withOptional, depth);
    if (t.kind === 'LIST') return [sample(t.ofType!, withOptional, depth)];
    const type = t.name ? types.get(t.name) : undefined;
    if (type?.kind === 'ENUM') return type.enumValues?.[0]?.name ?? '';
    if (type?.kind === 'INPUT_OBJECT' && depth < 4) {
      const out: Record<string, unknown> = {};
      for (const f of type.inputFields ?? []) {
        const leaf = ['SCALAR', 'ENUM'].includes(named(f.type).kind);
        if (required(f.type) || (withOptional && leaf && !isIdArg(f))) out[f.name] = sample(f.type, withOptional, depth + 1);
      }
      return out;
    }
    switch (t.name) {
      case 'Int':
      case 'Float':
        return withOptional ? 2 : 1;
      case 'Boolean':
        return true;
      case 'ID':
        return '{id}';
      default:
        return withOptional ? 'fortis-test-updated' : 'fortis-test';
    }
  };

  /** Turns a mutation field into a document with variables, or null if it can't be called this way. */
  const buildMutation = (m: Field, idArg: string | null, withOptional: boolean) => {
    const args = (m.args ?? []).filter((a) => required(a.type) || (withOptional && a.name !== idArg) || a.name === idArg);
    const decl = args.map((a) => `$${a.name}: ${typeName(a.type)}`).join(', ');
    const call = args.map((a) => `${a.name}: $${a.name}`).join(', ');
    const pick = selection(m.type);
    const mutation = `mutation${decl ? `(${decl})` : ''} { ${m.name}${call ? `(${call})` : ''}${pick} }`;
    const variables = Object.fromEntries(args.filter((a) => a.name !== idArg).map((a) => [a.name, sample(a.type, withOptional)]));
    return { mutation, ...(Object.keys(variables).length ? { variables } : {}) };
  };

  const checks: GraphqlCheck[] = [];
  const notes: string[] = [];
  for (const q of queries) {
    const idArgs = (q.args ?? []).filter(isIdArg);
    const others = (q.args ?? []).filter((a) => !isIdArg(a) && required(a.type));
    if (idArgs.length !== 1 || others.length || isList(q.type) || !hasLeaves(q.type)) continue;
    const idArg = idArgs[0]!.name;
    const typeWanted = named(q.type).name!;
    const idField = idFieldOf(q.type);
    const list = listQuery(typeWanted, idField);
    const name = q.name.replace(/[-_]/g, ' ').replace(/^\w/, (ch) => ch.toUpperCase());
    const check: GraphqlCheck = {
      name,
      read: `query($${idArg}: ${typeName(idArgs[0]!.type)}) { ${q.name}(${idArg}: $${idArg})${selection(q.type)} }`,
      ...(idArg === 'id' ? {} : { idArg }),
      ...(idField === 'id' ? {} : { idField }),
      ...(list ? { list } : { ids: ['REPLACE_WITH_AN_ID_OWNED_BY_USER_A'] }),
    };

    // The mutations for this record: createLoan, loanCreate, addLoan and so on.
    const word = q.name.toLowerCase();
    const matching = (verbs: RegExp) => mutations.find((m) => verbs.test(m.name.toLowerCase().replace(word, '')) && m.name.toLowerCase().includes(word));
    const takesId = (m: Field) => (m.args ?? []).find(isIdArg);
    const create = matching(/^(create|add|new|insert)$/);
    const update = matching(/^(update|edit|set|modify|change)$/);
    const remove = matching(/^(delete|remove|destroy)$/);
    const updateId = update && takesId(update)?.name;
    const removeId = remove && takesId(remove)?.name;
    const withId = [updateId && update, removeId && remove].filter(Boolean) as Field[];
    if (withId.length && !create) notes.push(`${withId.map((m) => m.name).join(' and ')} take an ID, but no mutation creates a throwaway ${q.name}. Add a "create" under "writes" to test them.`);
    // An ID variable has to have the same name as the read's, because one idArg fills them all.
    const sameArg = (m: Field | undefined) => !m || takesId(m)?.name === idArg;
    if (withId.length && create) {
      if (!sameArg(updateId ? update : undefined) || !sameArg(removeId ? remove : undefined)) {
        notes.push(`${q.name}: its mutations name the ID differently from the query, so writes weren't generated. Add them to the config by hand.`);
      } else {
        check.writes = {
          create: { ...buildMutation(create, null, false), ...(idField === 'id' ? {} : { idField }) },
          ...(update && updateId ? { update: buildMutation(update, idArg, true) } : {}),
          ...(remove && removeId ? { delete: buildMutation(remove, idArg, false) } : {}),
        };
      }
    }
    checks.push(check);
  }
  return { checks, notes };
}
