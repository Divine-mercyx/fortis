#!/usr/bin/env node
// Writes the Homebrew formula, the Scoop manifest and the winget manifests for a release, from its
// SHA256SUMS. release-cli.yml publishes these after each release.
//   node package-manifests.mjs --version 0.1.0 --sums SHA256SUMS --out manifests
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO = 'Divine-mercyx/fortis';
export const WINGET_ID = 'DivineMercyx.Fortis';
const DESCRIPTION = 'Fintech security checks on every push, for African fintech teams';
const HOMEPAGE = 'https://fortis.dev';

export function parseSums(text) {
  const out = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = /^([0-9a-f]{64})\s+\*?(\S+)$/i.exec(line.trim());
    if (m) out.set(m[2], m[1].toLowerCase());
  }
  return out;
}

const assetUrl = (version, asset) => `https://github.com/${REPO}/releases/download/cli-v${version}/${asset}`;

function hashOf(sums, asset) {
  const hash = sums.get(asset);
  if (!hash) throw new Error(`${asset} isn't in SHA256SUMS`);
  return hash;
}

export function homebrewFormula(version, sums) {
  const block = (asset) => `      url "${assetUrl(version, asset)}"\n      sha256 "${hashOf(sums, asset)}"`;
  return `class Fortis < Formula
  desc "${DESCRIPTION}"
  homepage "${HOMEPAGE}"
  version "${version}"
  license "MIT"

  on_macos do
    on_arm do
${block('fortis-macos-arm64.tar.gz')}
    end
    on_intel do
${block('fortis-macos-x64.tar.gz')}
    end
  end

  on_linux do
    on_arm do
${block('fortis-linux-arm64.tar.gz')}
    end
    on_intel do
${block('fortis-linux-x64.tar.gz')}
    end
  end

  def install
    bin.install "fortis"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/fortis --version")
  end
end
`;
}

export function scoopManifest(version, sums) {
  const asset = 'fortis-windows-x64.zip';
  return `${JSON.stringify(
    {
      version,
      description: DESCRIPTION,
      homepage: HOMEPAGE,
      license: 'MIT',
      architecture: { '64bit': { url: assetUrl(version, asset), hash: hashOf(sums, asset) } },
      bin: 'fortis.exe',
    },
    null,
    2,
  )}\n`;
}

export function wingetManifests(version, sums) {
  const asset = 'fortis-windows-x64.zip';
  const schema = (type) => `# yaml-language-server: $schema=https://aka.ms/winget-manifest.${type}.1.6.0.schema.json\n`;
  const head = `PackageIdentifier: ${WINGET_ID}\nPackageVersion: ${version}\n`;
  const tail = 'ManifestVersion: 1.6.0\n';
  return {
    [`${WINGET_ID}.yaml`]: `${schema('version')}${head}DefaultLocale: en-US\nManifestType: version\n${tail}`,
    [`${WINGET_ID}.installer.yaml`]: `${schema('installer')}${head}InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
- RelativeFilePath: fortis.exe
  PortableCommandAlias: fortis
Installers:
- Architecture: x64
  InstallerUrl: ${assetUrl(version, asset)}
  InstallerSha256: ${hashOf(sums, asset).toUpperCase()}
ManifestType: installer
${tail}`,
    [`${WINGET_ID}.locale.en-US.yaml`]: `${schema('defaultLocale')}${head}PackageLocale: en-US
Publisher: Fortis
PackageName: Fortis
License: MIT
ShortDescription: ${DESCRIPTION}
PackageUrl: ${HOMEPAGE}
ManifestType: defaultLocale
${tail}`,
  };
}

export function writeManifests(version, sumsText, out) {
  const sums = parseSums(sumsText);
  const write = (rel, text) => {
    const path = join(out, rel);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
  };
  write('homebrew/Formula/fortis.rb', homebrewFormula(version, sums));
  write('scoop/bucket/fortis.json', scoopManifest(version, sums));
  for (const [name, text] of Object.entries(wingetManifests(version, sums))) write(`winget/${name}`, text);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const arg = (name) => {
    const i = process.argv.indexOf(`--${name}`);
    if (i < 0 || !process.argv[i + 1]) throw new Error(`Usage: package-manifests.mjs --version <v> --sums <file> --out <dir> (missing --${name})`);
    return process.argv[i + 1];
  };
  writeManifests(arg('version').replace(/^cli-v/, ''), readFileSync(arg('sums'), 'utf8'), arg('out'));
  console.log(`Wrote the manifests to ${arg('out')}`);
}
