# Install-and-push check from PowerShell and cmd on Windows (e2e.sh covers Git Bash).
#   pwsh scripts/e2e.ps1 <fortis-watchdog .tgz>
# Git runs the pre-push hook with its own sh whatever the shell, so this checks the part that does
# differ: installing and running Fortis from PowerShell, and pushing from PowerShell and cmd.
param([Parameter(Mandatory = $true)][string]$Tarball)
$ErrorActionPreference = 'Stop'
$Tarball = (Resolve-Path $Tarball).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ("fortis-e2e-" + [Guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
$env:FORTIS_API_URL = 'http://127.0.0.1:9'
$env:FORTIS_CACHE_DIR = Join-Path $work 'cache'
$env:NO_COLOR = '1'

function Fail($msg) { Write-Host "FAILED (powershell): $msg"; exit 1 }
function Push([string]$shell) {
  if ($shell -eq 'cmd') { cmd /c "git push -q origin main 2>&1" | Out-String } else { git push -q origin main 2>&1 | Out-String }
}

git init -q --bare (Join-Path $work 'origin.git')
git init -q -b main (Join-Path $work 'repo')
Set-Location (Join-Path $work 'repo')
git config user.email e2e@example.com
git config user.name E2E
git config core.autocrlf true
git remote add origin (Join-Path $work 'origin.git')
'{ "name": "e2e-app", "version": "1.0.0", "private": true }' | Set-Content package.json

npm install -D --no-audit --no-fund $Tarball | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'npm install failed' }
npx --no-install fortis --version
if ($LASTEXITCODE -ne 0) { Fail 'fortis does not run from PowerShell' }
npx --no-install fortis init | Out-Null
if (-not (Select-String -Quiet -Path .git/hooks/pre-push -Pattern 'fortis scan --pre-push')) { Fail 'init did not install the hook' }
"node_modules/`n" | Set-Content .gitignore

$key = 'AKIA' + ('ABCD2345' * 2)
"export const ok = true;" | Set-Content ok.js
git add -A; git commit -qm 'clean'
$out = Push 'pwsh'
if ($LASTEXITCODE -ne 0) { Fail "a clean push from PowerShell was blocked:`n$out" }

foreach ($shell in 'pwsh', 'cmd') {
  "export const key = '$key';" | Set-Content "leak-$shell.js"
  git add -A; git commit -qm "key ($shell)"
  $out = Push $shell
  if ($LASTEXITCODE -eq 0) { Fail "a push with a key from $shell was not blocked" }
  if ($out -notmatch "leak-$shell.js") { Fail "the report from $shell did not name the file:`n$out" }
  git reset -q --hard HEAD~1
  Write-Host "blocked a key pushed from $shell"
}
Write-Host 'e2e passed: powershell and cmd'
