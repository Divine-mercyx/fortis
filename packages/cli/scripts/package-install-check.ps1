# The Windows half of package-install-check.sh: installs through Scoop, and checks the winget manifests.
param([string]$Version, [string]$Manifests)
$ErrorActionPreference = 'Stop'

# Scoop refuses to install as an administrator unless told otherwise, and CI runs as one.
Invoke-RestMethod https://get.scoop.sh -OutFile "$env:TEMP\install-scoop.ps1"
& "$env:TEMP\install-scoop.ps1" -RunAsAdmin
$env:Path = "$HOME\scoop\shims;$env:Path"

scoop install (Join-Path $Manifests 'scoop\bucket\fortis.json')
if ($LASTEXITCODE -ne 0) { throw 'FAILED: scoop install' }
$got = (fortis --version).Trim()
if ($got -ne $Version) { throw "FAILED: scoop installed $got" }
Write-Host "ok: scoop installs $Version"
scoop uninstall fortis | Out-Null

$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) { throw 'FAILED: winget is not on this runner' }
winget validate --manifest (Join-Path $Manifests 'winget')
if ($LASTEXITCODE -ne 0) { throw 'FAILED: winget validate' }
Write-Host 'ok: the winget manifests are valid'

winget settings --enable LocalManifestFiles | Out-Null
winget install --manifest (Join-Path $Manifests 'winget') --accept-source-agreements --accept-package-agreements --disable-interactivity
if ($LASTEXITCODE -ne 0) { throw "FAILED: winget install exited with $LASTEXITCODE" }
$links = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links'
$got = (& (Join-Path $links 'fortis.exe') --version).Trim()
if ($got -ne $Version) { throw "FAILED: winget installed $got" }
Write-Host "ok: winget installs $Version"
