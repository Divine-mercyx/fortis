// Generates a large repository for the scan performance check (#30):
//   node scripts/gen-large-repo.mjs <dir> [files=100000]
// A realistic mix of TypeScript, JavaScript, JSON, Python, Go and Markdown, about 1.5 KB each, with a
// handful of planted secrets so the scan has something to find. Commits everything.
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [dir, n = '100000'] = process.argv.slice(2);
if (!dir) throw new Error('usage: gen-large-repo.mjs <dir> [files]');
const total = Number(n);
const KEY = `AKIA${'ABCD2345'.repeat(2)}`;
const body = {
  ts: (i) => `import { db } from '../db';\n\nexport async function handler${i}(req: { params: { id: string } }) {\n  const row = await db.query('select * from items where id = $1', [req.params.id]);\n  return { ok: true, row, at: new Date().toISOString() };\n}\n`.repeat(4),
  js: (i) => `const items${i} = [1, 2, 3].map((x) => x * ${i});\nmodule.exports = { items${i} };\n`.repeat(8),
  json: (i) => JSON.stringify({ name: `pkg-${i}`, version: '1.0.0', description: 'generated', keywords: Array.from({ length: 40 }, (_, k) => `k${k}`) }, null, 2),
  py: (i) => `def handler_${i}(event):\n    items = [x * ${i} for x in range(10)]\n    return {"ok": True, "items": items}\n\n`.repeat(6),
  go: (i) => `package gen\n\nfunc Handler${i}(n int) int {\n\treturn n * ${i}\n}\n`.repeat(6),
  md: (i) => `# Note ${i}\n\nGenerated file for the performance check. Nothing secret here.\n\n`.repeat(8),
};
const kinds = Object.keys(body);
mkdirSync(dir, { recursive: true });
execFileSync('git', ['init', '-q', '-b', 'main', dir]);
for (let i = 0; i < total; i++) {
  const kind = kinds[i % kinds.length];
  const sub = join(dir, `pkg${Math.floor(i / 1000)}`, `mod${Math.floor(i / 50) % 20}`);
  if (i % 50 === 0) mkdirSync(sub, { recursive: true });
  let text = body[kind](i);
  if (i % 20_000 === 7) text += `\nexport const leaked${i} = '${KEY}';\n`;
  writeFileSync(join(sub, `f${i}.${kind}`), text);
}
const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
git('config', 'user.email', 'perf@example.com');
git('config', 'user.name', 'Perf');
git('add', '-A');
git('commit', '-qm', 'generated');
console.log(`generated ${total} files in ${dir}`);
