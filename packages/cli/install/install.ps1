# Installs the Fortis CLI on Windows. It needs no Node.
#   irm https://github.com/Divine-mercyx/fortis/releases/latest/download/install.ps1 | iex
# FORTIS_VERSION pins a version, FORTIS_INSTALL_DIR changes where it goes (default ~\.fortis\bin).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = if ($env:FORTIS_REPO) { $env:FORTIS_REPO } else { 'Divine-mercyx/fortis' }
$dir = if ($env:FORTIS_INSTALL_DIR) { $env:FORTIS_INSTALL_DIR } else { Join-Path $HOME '.fortis\bin' }
$base = if ($env:FORTIS_DOWNLOAD_BASE) { $env:FORTIS_DOWNLOAD_BASE } elseif ($env:FORTIS_VERSION) { "https://github.com/$repo/releases/download/cli-v$env:FORTIS_VERSION" } else { "https://github.com/$repo/releases/latest/download" }
$asset = 'fortis-windows-x64.zip'

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
  throw "fortis install: no build for $env:PROCESSOR_ARCHITECTURE. Use npm (npm i -D fortis-watchdog)."
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("fortis-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading $asset (about 35 MB; this can take a few minutes on a slow connection) ..."
  Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile (Join-Path $tmp $asset)
  Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

  $line = Get-Content (Join-Path $tmp 'SHA256SUMS') | Where-Object { $_ -match "[ *]$([regex]::Escape($asset))$" }
  if (-not $line) { throw "fortis install: $asset is not listed in SHA256SUMS" }
  $expected = ($line -split '\s+')[0]
  $actual = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash
  if ($actual -ine $expected) { throw "fortis install: checksum mismatch for $asset. Not installing it." }

  Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $tmp -Force
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Move-Item -Force (Join-Path $tmp 'fortis.exe') (Join-Path $dir 'fortis.exe')
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Write-Host "Installed fortis $(& (Join-Path $dir 'fortis.exe') --version) to $dir\fortis.exe"
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) {
  [Environment]::SetEnvironmentVariable('Path', "$dir;$userPath", 'User')
  Write-Host "Added $dir to your PATH. Open a new terminal to use it."
}
