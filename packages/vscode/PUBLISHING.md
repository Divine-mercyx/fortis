# Publishing the extension

For maintainers. `.github/workflows/release-vscode.yml` publishes to both stores when you push a tag.

## One-time setup

1. **VS Code Marketplace:** create a publisher at [marketplace.visualstudio.com/manage](https://marketplace.visualstudio.com/manage). Then create an Azure DevOps personal access token with the **Marketplace → Manage** scope, for all accessible organisations.
2. **Open VSX (Cursor and VSCodium):** create an account at [open-vsx.org](https://open-vsx.org) by signing in with GitHub, sign the publisher agreement, and create an access token. The release workflow creates the namespace on its first run if it doesn't exist.
3. Set `publisher` in `packages/vscode/package.json` to the same ID in both stores. It must be free in both. On 2026-11-16 neither store had a `fortis` publisher or namespace, so the current value can stay if you register that ID.
4. Add the repository secrets `VSCE_PAT` and `OVSX_PAT`. In this repository the workflow fails, without publishing anything, if either is missing. In a fork, a store without its secret is skipped.

## Each release

1. Set `version` in `packages/vscode/package.json`, and add it to `packages/vscode/CHANGELOG.md`.
2. Merge those changes, then push a matching tag from the deploy branch:

   ```bash
   git tag vscode-v<version>
   git push origin vscode-v<version>
   ```

The workflow runs the extension in a real VS Code on Linux, macOS and Windows first, and publishes only if that passes. The `.vsix` is saved with the workflow run.

After publishing, the workflow waits until each store lists the new version: up to 10 minutes for Open VSX and 30 for the Marketplace, which verifies each upload first. The run passes only when people can install it. If a wait runs out, the store's publisher page says why.

If a run fails partway, re-run it. A store that already has the version skips it.

To try a build by hand:

```bash
pnpm --filter fortis-security package
code --install-extension packages/vscode/fortis-security.vsix
```
