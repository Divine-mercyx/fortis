# Signs a Windows binary with Authenticode, so SmartScreen has a publisher to check.
# Usage: sign-windows.ps1 -Binary fortis.exe
#
# WINDOWS_CERT_PFX_BASE64, WINDOWS_CERT_PASSWORD   the code-signing certificate
#
# With FORTIS_SIGN_CHECK=1 it uses a throwaway self-signed certificate. CI uses that to prove the
# binary still runs once signed. It doesn't stop SmartScreen warning: only a real certificate does.
param([Parameter(Mandatory)][string]$Binary)
$ErrorActionPreference = 'Stop'

$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' | Sort-Object FullName | Select-Object -Last 1
if (-not $signtool) { throw 'FAILED: signtool not found' }

$work = Join-Path ([IO.Path]::GetTempPath()) ("fortis-sign-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
$pfx = Join-Path $work 'cert.pfx'
try {
  $check = $env:FORTIS_SIGN_CHECK -eq '1'
  if ($check) {
    $password = [Guid]::NewGuid().ToString()
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Fortis signing check' -CertStoreLocation Cert:\CurrentUser\My
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password (ConvertTo-SecureString $password -AsPlainText -Force) | Out-Null
  } else {
    $password = $env:WINDOWS_CERT_PASSWORD
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:WINDOWS_CERT_PFX_BASE64))
  }
  # The copy of Node the binary starts from is signed, and adding the CLI invalidated that signature.
  & $signtool.FullName remove /s $Binary 2>$null
  $global:LASTEXITCODE = 0
  & $signtool.FullName sign /fd SHA256 /f $pfx /p $password /tr http://timestamp.digicert.com /td SHA256 $Binary
  if ($LASTEXITCODE -ne 0) { throw 'FAILED: signtool sign' }

  $signature = Get-AuthenticodeSignature $Binary
  if (-not $signature.SignerCertificate) { throw 'FAILED: the binary has no signature' }
  if (-not $check -and $signature.Status -ne 'Valid') { throw "FAILED: the signature is $($signature.Status)" }
  & $Binary --version
  if ($LASTEXITCODE -ne 0) { throw 'FAILED: the signed binary does not run' }
  Write-Host "ok: signed by $($signature.SignerCertificate.Subject), and it runs"
} finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
