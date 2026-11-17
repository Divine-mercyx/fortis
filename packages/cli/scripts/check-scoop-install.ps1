# Installs Scoop, then Fortis from the Scoop bucket with the README's commands, and checks it's
# this version. release-cli.yml runs it on Windows once the bucket has the release.
# Usage: check-scoop-install.ps1 -Version 0.1.0
param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = 'Stop'

if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
  # Scoop's installer, pinned to a commit and checked, like wingetcreate in the winget job.
  $installer = Join-Path ([IO.Path]::GetTempPath()) 'install-scoop.ps1'
  Invoke-WebRequest https://raw.githubusercontent.com/ScoopInstaller/Install/1e2f334083d609986d8c8bc9e31ae8e87c39fab4/install.ps1 -OutFile $installer
  if ((Get-FileHash $installer -Algorithm SHA256).Hash -ine '94f983b190438311e006b957db7c8422709e0ba62a6c2ac04e278164108f2512') { throw "Scoop's installer failed its checksum" }
  # CI runs as an administrator, which the installer refuses without this.
  & $installer -RunAsAdmin
  $env:PATH = "$env:USERPROFILE\scoop\shims;$env:PATH"
}

scoop bucket add fortis https://github.com/Divine-mercyx/scoop-bucket
if ($LASTEXITCODE -ne 0) { throw 'scoop bucket add failed' }
scoop install fortis
if ($LASTEXITCODE -ne 0) { throw 'scoop install fortis failed' }

$got = (& fortis --version).Trim()
if ($got -ne $Version) { throw "FAILED: scoop installed fortis $got, not $Version" }
Write-Host "ok: scoop install fortis installs $Version"
