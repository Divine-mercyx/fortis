# Fortis Security for VS Code

See security findings while you write the code, instead of at `git push`. Works in VS Code, Cursor and VSCodium.

Fortis catches leaked payment keys, money records read without an ownership check, webhooks without a signature check and vulnerable dependencies. It's built for African fintech teams.

## What it does

- **Scans on save:** each file is checked when you save it. The whole workspace is scanned when it opens, including dependencies.
- **Shows problems at the right line:** findings appear in the editor and the Problems panel.
- **Explains on hover:** hover over a finding to see why it matters and how to fix it.
- **Offers quick fixes:**
  - ignore a line, with a reason your reviewers can read;
  - open a dependency's advisory;
  - copy the command that upgrades it.

## Getting started

1. Install the extension.
2. Open a git repository and trust the folder when asked. Fortis doesn't run in folders you haven't trusted.
3. Save a file. Findings appear in the Problems panel, and the status bar shows how many there are.

The secrets and dependency checks work straight away. For the fintech rules, add a key with `fortis login <key>`, or set `FORTIS_KEY` before starting the editor.

## Which CLI it uses

It uses the first of these that's version 0.1.0-beta.12 or newer:

1. the path in the `fortis.cliPath` setting;
2. `fortis-watchdog` in your project's `node_modules`, `.venv` or `venv`;
3. `fortis` on your `PATH`, or in `~/.fortis/bin`;
4. the CLI that comes with this extension, which needs nothing else installed.

**Fortis: Show Output** shows which one it chose. A workspace can't set `fortis.cliPath`, so a repository you clone can't choose what runs on your machine.

## What leaves your machine

- **Findings stay local.** The extension always scans with `--no-upload`, even if your project syncs to the dashboard. An editor save isn't a scan of the project, so your git hook and CI keep syncing as usual.
- **Secrets stay masked.** The extension only uses the CLI's masked output.
- **Your key's plan is checked.** With a key, each scan asks the Fortis API which rules your plan includes. No code or findings are sent.
- **Package names go to OSV.** A workspace scan, or saving a lockfile, sends package names and versions to [osv.dev](https://osv.dev) to check for advisories.

Set `fortis.offline` to make no network requests at all. Only the secrets checks run then.

## Settings

| Setting | Default | |
|---|---|---|
| `fortis.scanOnSave` | `true` | Scan a file each time you save it |
| `fortis.scanOnOpen` | `true` | Scan the whole workspace when it opens |
| `fortis.offline` | `false` | Make no network requests; secrets checks only |
| `fortis.cliPath` | empty | Path to the CLI. Can only be set for your machine, not by a workspace |

Run **Fortis: Scan Workspace** at any time. Dependency findings update on a workspace scan or when you save a lockfile.

Findings accepted in the project's `.fortis-baseline.json` aren't shown.

## Silencing a finding

The quick fix adds a comment above the line, in the right style for the language:

```js
// fortis-ignore-next-line: staff-only route, checked by requirePermission
const loan = await Loan.findById(req.params.id);
```

JSON files can't hold comments, so use `"ignore"` in `.fortis.json` for those.
