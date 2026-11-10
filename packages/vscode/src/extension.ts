import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import * as vscode from 'vscode';

import { cliCandidates, MIN_CLI_VERSION, runCli, scanArgs, versionAtLeast, type Cli } from './cli';
import { advisoryUrl, editorPath, hoverText, ignoreComment, lineIndex, parseScanOutput, problemMessage, upgradeCommand, type Finding } from './findings';
import { ScanQueue, type Work } from './queue';

const SOURCE = 'Fortis';

const SEVERITY: Record<Finding['severity'], vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

export function activate(context: vscode.ExtensionContext) {
  const output = vscode.window.createOutputChannel(SOURCE);
  const problems = vscode.languages.createDiagnosticCollection('fortis');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
  status.command = 'fortis.showOutput';
  status.name = SOURCE;

  /** What each file's problems came from, for hovers and quick fixes. */
  const findings = new Map<string, Finding[]>();
  const queues = new Map<string, ScanQueue>();
  const clis = new Map<string, Promise<Cli>>();
  let running = 0;

  const settings = () => vscode.workspace.getConfiguration('fortis');
  const bundled: Cli = { label: 'this extension', kind: 'node-script', path: context.asAbsolutePath(join('dist', 'cli', 'fortis.mjs')) };

  const showCount = () => {
    let total = 0;
    for (const list of findings.values()) total += list.length;
    status.text = running ? '$(sync~spin) Fortis' : `$(shield) Fortis: ${total}`;
    status.tooltip = running ? 'Scanning' : `${total} finding(s). Select to see the output.`;
    status.show();
  };

  /** The first installed CLI new enough to use, or the one in this extension. */
  const findCli = (folder: string) => {
    let found = clis.get(folder);
    if (!found) {
      found = (async () => {
        const candidates = cliCandidates(settings().get<string>('cliPath', ''), { platform: process.platform, env: process.env, home: homedir(), workspace: folder, exists: existsSync });
        for (const cli of candidates) {
          try {
            const { code, stdout } = await runCli(cli, ['--version'], { cwd: folder, timeoutMs: 20_000 });
            const version = /\d+\.\d+\.\d+\S*/.exec(stdout)?.[0];
            if (code === 0 && version && versionAtLeast(version, MIN_CLI_VERSION)) {
              output.appendLine(`Using the Fortis CLI from ${cli.label} (${version}): ${cli.path}`);
              return cli;
            }
            output.appendLine(`Skipping the Fortis CLI at ${cli.path}: it needs to be ${MIN_CLI_VERSION} or newer.`);
          } catch (e) {
            output.appendLine(`Skipping the Fortis CLI at ${cli.path}: ${(e as Error).message}`);
          }
        }
        output.appendLine('Using the Fortis CLI in this extension.');
        return bundled;
      })();
      clis.set(folder, found);
    }
    return found;
  };

  const show = (fsPath: string, list: Finding[]) => {
    const uri = vscode.Uri.file(fsPath);
    if (!list.length) {
      findings.delete(uri.fsPath);
      problems.delete(uri);
      return;
    }
    findings.set(uri.fsPath, list);
    problems.set(
      uri,
      list.map((f) => {
        const line = lineIndex(f);
        // The editor trims the range to the real length of the line.
        const problem = new vscode.Diagnostic(new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER), problemMessage(f), SEVERITY[f.severity] ?? vscode.DiagnosticSeverity.Warning);
        problem.source = SOURCE;
        problem.code = f.ruleId;
        return problem;
      }),
    );
  };

  const scan = async (folder: string, work: Work) => {
    running++;
    showCount();
    try {
      const cli = await findCli(folder);
      const offline = settings().get<boolean>('offline', false);
      const { code, stdout, stderr } = await runCli(cli, scanArgs({ paths: !work.all, offline }), { cwd: folder, input: work.all ? '' : work.paths.join('\n'), timeoutMs: work.all ? 900_000 : 300_000 });
      // 0 means nothing blocking and 1 means findings. Anything else means the scan didn't run.
      if (code !== 0 && code !== 1) {
        output.appendLine(`The scan of ${folder} didn't run: ${stderr.trim() || `exit code ${code}`}`);
        return;
      }
      const result = parseScanOutput(stdout);
      for (const note of result.notes) output.appendLine(note);

      const byFile = new Map<string, Finding[]>();
      for (const f of result.detections) {
        if (f.baseline) continue;
        const path = vscode.Uri.file(editorPath(folder, result.root, f.file)).fsPath;
        byFile.set(path, [...(byFile.get(path) ?? []), f]);
      }
      // A whole-workspace scan replaces this folder's problems. A save replaces only the saved files'.
      const inFolder = (path: string) => path === folder || path.startsWith(`${folder}${path.includes('\\') ? '\\' : '/'}`);
      const replaced = work.all ? [...findings.keys()].filter(inFolder) : work.paths.map((p) => vscode.Uri.file(p).fsPath);
      for (const path of new Set([...replaced, ...(work.all ? byFile.keys() : [])])) show(path, byFile.get(path) ?? []);
    } catch (e) {
      output.appendLine(`The scan of ${folder} failed: ${(e as Error).message}`);
    } finally {
      running--;
      showCount();
    }
  };

  const queueFor = (folder: vscode.WorkspaceFolder) => {
    const key = folder.uri.fsPath;
    let queue = queues.get(key);
    if (!queue) {
      queue = new ScanQueue((work) => scan(key, work));
      queues.set(key, queue);
    }
    return queue;
  };

  const scanEverything = () => {
    for (const folder of vscode.workspace.workspaceFolders ?? []) {
      if (folder.uri.scheme === 'file') queueFor(folder).request();
    }
  };

  /** The finding behind a problem. Problems carry the rule and line, so they can be matched back. */
  const findingFor = (uri: vscode.Uri, problem: vscode.Diagnostic) =>
    (findings.get(uri.fsPath) ?? []).find((f) => f.ruleId === problem.code && lineIndex(f) === problem.range.start.line);

  context.subscriptions.push(
    output,
    problems,
    status,
    { dispose: () => queues.forEach((q) => q.dispose()) },

    vscode.commands.registerCommand('fortis.scanWorkspace', scanEverything),
    vscode.commands.registerCommand('fortis.showOutput', () => output.show()),

    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.uri.scheme !== 'file' || !settings().get<boolean>('scanOnSave', true)) return;
      const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
      if (folder) queueFor(folder).request([doc.uri.fsPath]);
    }),

    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('fortis.cliPath')) clis.clear();
    }),

    vscode.languages.registerHoverProvider({ scheme: 'file' }, {
      provideHover(doc, position) {
        const here = (findings.get(doc.uri.fsPath) ?? []).filter((f) => lineIndex(f) === position.line);
        if (!here.length) return undefined;
        return new vscode.Hover(here.map((f) => new vscode.MarkdownString(hoverText(f))));
      },
    }),

    vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, {
      provideCodeActions(doc, _range, ctx) {
        const actions: vscode.CodeAction[] = [];
        for (const problem of ctx.diagnostics) {
          if (problem.source !== SOURCE) continue;
          const finding = findingFor(doc.uri, problem);
          if (!finding) continue;
          const action = (title: string, command: string, args: unknown[]) => {
            const a = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
            a.command = { title, command, arguments: args };
            a.diagnostics = [problem];
            actions.push(a);
          };
          const upgrade = upgradeCommand(finding);
          if (upgrade) action(`Copy the upgrade command: ${upgrade}`, 'fortis.copyUpgrade', [upgrade]);
          const advisory = advisoryUrl(finding);
          if (advisory) action('Open the advisory', 'fortis.openAdvisory', [advisory]);
          if (ignoreComment(finding, doc.languageId, '', '')) action(`Ignore ${finding.ruleId} on this line, with a reason`, 'fortis.addIgnore', [doc.uri, problem.range.start.line, finding.ruleId]);
        }
        return actions;
      },
    }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),

    vscode.commands.registerCommand('fortis.copyUpgrade', async (command: string) => {
      await vscode.env.clipboard.writeText(command);
      void vscode.window.setStatusBarMessage('Fortis: copied the upgrade command', 3000);
    }),

    vscode.commands.registerCommand('fortis.openAdvisory', (url: string) => vscode.env.openExternal(vscode.Uri.parse(url))),

    vscode.commands.registerCommand('fortis.addIgnore', async (uri: vscode.Uri, line: number, ruleId: string) => {
      const reason = await vscode.window.showInputBox({
        title: `Ignore ${ruleId} on this line`,
        prompt: 'Why is this safe? Reviewers will read this.',
        validateInput: (v) => (v.trim() ? undefined : 'Give a reason.'),
      });
      if (!reason) return;
      const doc = await vscode.workspace.openTextDocument(uri);
      const indent = /^\s*/.exec(doc.lineAt(line).text)?.[0] ?? '';
      const comment = ignoreComment({ ruleId }, doc.languageId, indent, reason);
      if (!comment) return;
      const edit = new vscode.WorkspaceEdit();
      edit.insert(uri, new vscode.Position(line, 0), `${comment}${doc.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n'}`);
      // Saving runs the scan again, which clears the problem.
      if (await vscode.workspace.applyEdit(edit)) await doc.save();
    }),
  );

  showCount();
  if (settings().get<boolean>('scanOnOpen', true)) scanEverything();
}

export function deactivate() {}
