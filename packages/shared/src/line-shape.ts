/*
 * The shape of a line of code: its structure, with nothing that could identify a customer. Only words
 * on this list survive. Every other name becomes x, every string "…", and every number 0, so a false
 * positive reported in one workspace can become a benchmark case without any of its code.
 */
const KEEP = new Set(
  `
  const let var function async await return if else for while try catch throw new class import from export default require
  def self none true false null undefined this and or not in is with as lambda elif except raise
  req request res response ctx params query body headers user session id
  app router post put get patch delete all use route path url
  find findById findByPk findOne findUnique findFirst findMany findAll getById load filter objects first where update save
  select insert into set values transaction atomic begin commit
  console log logger info warn error debug trace print logging winston pino
  json send status jsonify Response
  balance amount wallet account transfer payout withdraw loan payment card customer
  otp bvn nin pin passcode code token verification random Math floor randint choice
  webhook paystack flutterwave monnify remita interswitch opay kora stripe signature hmac secret key password api
  env process os environ getenv
`
    .trim()
    .split(/\s+/),
);

/** Reduces a line that has already been masked to its shape. */
export function lineShape(maskedLine: string): string {
  return (
    maskedLine
      // Text in comments can say anything.
      .replace(/(^|\s)(\/\/|#(?!\{)).*$/, '')
      .replace(/\/\*.*?\*\//g, ' ')
      // Strings, including their quotes' contents.
      .replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '"…"')
      // An unfinished string on a line cut off at the end, or a masked value outside one.
      .replace(/["'`].*$/, (m) => (m.startsWith('"…"') ? m : '"…"'))
      .replace(/\S*•+\S*/g, '"…"')
      .replace(/\b\d[\d_.]*\b/g, '0')
      .replace(/[\p{L}_$][\p{L}\p{N}_$]*/gu, (word) => (KEEP.has(word) ? word : 'x'))
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 200)
  );
}

export type FalsePositive = { ruleId: string; file: string; snippet: string | null; orgId: string };
export type FalsePositiveShape = { rule: string; extension: string; shape: string; workspaces: number };

const extensionOf = (file: string) => /\.([A-Za-z0-9]{1,8})$/.exec(file)?.[1]?.toLowerCase() ?? 'txt';

/**
 * Findings marked as false positives, reduced to rule, file extension and shape. A shape is only
 * included when at least `minWorkspaces` workspaces reported it, so it can't point back at one.
 */
export function falsePositiveShapes(rows: FalsePositive[], minWorkspaces = 2): FalsePositiveShape[] {
  const groups = new Map<string, { rule: string; extension: string; shape: string; orgs: Set<string> }>();
  for (const row of rows) {
    if (!row.snippet) continue;
    const shape = lineShape(row.snippet);
    if (!shape) continue;
    const extension = extensionOf(row.file);
    const id = `${row.ruleId}|${extension}|${shape}`;
    const group = groups.get(id) ?? { rule: row.ruleId, extension, shape, orgs: new Set<string>() };
    group.orgs.add(row.orgId);
    groups.set(id, group);
  }
  return [...groups.values()]
    .filter((g) => g.orgs.size >= minWorkspaces)
    .map((g) => ({ rule: g.rule, extension: g.extension, shape: g.shape, workspaces: g.orgs.size }))
    .sort((a, b) => b.workspaces - a.workspaces || a.rule.localeCompare(b.rule) || a.shape.localeCompare(b.shape));
}
