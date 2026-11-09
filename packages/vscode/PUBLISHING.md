# Publishing the extension

For maintainers. `.github/workflows/release-vscode.yml` publishes to both stores when you push a tag.

## One-time setup

1. **VS Code Marketplace:** create a publisher at [marketplace.visualstudio.com/manage](https://marketplace.visualstudio.com/manage). Then create an Azure DevOps personal access token with the **Marketplace → Manage** scope, for all accessible organisations.
2. **Open VSX (Cursor and VSCodium):** create an account at [open-vsx.org](https://open-vsx.org), sign the publisher agreement, and create an access token. Then create the namespace once:

   ```bash
   npx ovsx create-namespace <publisher> -p <token>
   ```

3. Set `publisher` in `packages/vscode/package.json` to the same ID in both stores.
4. Add the repository secrets `VSCE_PAT` and `OVSX_PAT`. A store without its secret is skipped.

## Each release

1. Set `version` in `packages/vscode/package.json`, and add it to `packages/vscode/CHANGELOG.md`.
2. Merge those changes, then push a matching tag from the deploy branch:

   ```bash
   git tag vscode-v<version>
   git push origin vscode-v<version>
   ```

The workflow runs the extension in a real VS Code on Linux, macOS and Windows first, and publishes only if that passes. The `.vsix` is saved with the workflow run.

To try a build by hand:

```bash
pnpm --filter fortis-security package
code --install-extension packages/vscode/fortis-security.vsix
```
