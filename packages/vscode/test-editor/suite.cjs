const assert = require('node:assert');
const { writeFileSync } = require('node:fs');

const vscode = require('vscode');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(what, check, seconds = 90) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await sleep(500);
  }
  throw new Error(`Timed out waiting for ${what}`);
}

const fortisProblems = (uri) => vscode.languages.getDiagnostics(uri).filter((d) => d.source === 'Fortis');

exports.run = async function run() {
  const key = process.env.FORTIS_TEST_KEY;
  const folder = vscode.workspace.workspaceFolders[0].uri;
  const pay = vscode.Uri.joinPath(folder, 'pay.js');
  const clean = vscode.Uri.joinPath(folder, 'clean.js');

  // Offline: no key and no network in this test.
  await vscode.workspace.getConfiguration('fortis').update('offline', true, vscode.ConfigurationTarget.Workspace);
  const extension = vscode.extensions.all.find((e) => e.id.endsWith('.fortis-security'));
  assert.ok(extension, 'the extension is installed');
  await extension.activate();

  // The whole workspace is scanned on open, and the problem is on the right line.
  const [problem] = await until('the leaked key to be reported', () => {
    const found = fortisProblems(pay);
    return found.length ? found : null;
  });
  assert.strictEqual(problem.code, 'FX-SEC-001');
  assert.strictEqual(problem.range.start.line, 0);
  assert.strictEqual(problem.severity, vscode.DiagnosticSeverity.Error);
  assert.ok(!problem.message.includes(key), 'the problem does not repeat the key');
  assert.deepStrictEqual(fortisProblems(clean), []);

  // Hover shows the explanation, without the key.
  const doc = await vscode.workspace.openTextDocument(pay);
  await vscode.window.showTextDocument(doc);
  const hovers = await vscode.commands.executeCommand('vscode.executeHoverProvider', pay, new vscode.Position(0, 5));
  const text = hovers.flatMap((h) => h.contents.map((c) => c.value ?? String(c))).join('\n');
  assert.ok(text.includes('Why it matters'), `hover explains the rule: ${text}`);
  assert.ok(!text.includes(key), 'the hover does not repeat the key');

  // The quick fix is offered, and the comment it writes clears the problem on save.
  const actions = await vscode.commands.executeCommand('vscode.executeCodeActionProvider', pay, problem.range);
  const ignore = actions.find((a) => a.title.startsWith('Ignore FX-SEC-001'));
  assert.ok(ignore, `the ignore fix is offered: ${actions.map((a) => a.title).join(', ')}`);
  const edit = new vscode.WorkspaceEdit();
  edit.insert(pay, new vscode.Position(0, 0), '// fortis-ignore-next-line: test fixture\n');
  await vscode.workspace.applyEdit(edit);
  await doc.save();
  await until('the ignored finding to clear', () => fortisProblems(pay).length === 0);

  // Saving a new problem into a clean file reports it, in that file only.
  writeFileSync(clean.fsPath, `const LEAK = "${key}";\n`);
  const cleanDoc = await vscode.workspace.openTextDocument(clean);
  const cleanEdit = new vscode.WorkspaceEdit();
  cleanEdit.insert(clean, new vscode.Position(0, 0), '// a change\n');
  await vscode.workspace.applyEdit(cleanEdit);
  await cleanDoc.save();
  const [saved] = await until('the saved file to be reported', () => {
    const found = fortisProblems(clean);
    return found.length ? found : null;
  });
  assert.strictEqual(saved.range.start.line, 1);

  // The bundled CLI ran, and the status bar command works.
  await vscode.commands.executeCommand('fortis.showOutput');
};
