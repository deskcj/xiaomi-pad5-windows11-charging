[CmdletBinding()]
param([string]$WdkBin='H:\Vlad\EWDK\Program Files\Windows Kits\10\bin\10.0.26100.0')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$unsigned=Join-Path $root 'build\qcpmicext8150_unsigned.sys'
$build=Get-Content -LiteralPath (Join-Path $root 'build\qcpmicext8150_unsigned.build.json') -Raw | ConvertFrom-Json
$qa=Get-Content -LiteralPath (Join-Path $root 'build\emulation-report.json') -Raw | ConvertFrom-Json
$unwind=Get-Content -LiteralPath (Join-Path $root 'build\native-unwind-report.json') -Raw | ConvertFrom-Json
$hash=(Get-FileHash -LiteralPath $unsigned).Hash
if($hash -ine $build.unsignedSHA256 -or $hash -ine $qa.sha256){throw 'QA image identity mismatch'}
if($qa.passedArithmeticARM64Cases -ne 266156 -or $qa.passedFullSetterARM64Cases -ne 259){throw 'Required ARM64 cases missing'}
if($unwind.nativeARM64UnwindCases -ne 1081 -or $unwind.failures -ne 0){throw 'Native unwind checks failed'}
$pkg=Join-Path $root 'package'
if(Test-Path -LiteralPath $pkg){throw 'Do not overwrite a signed package'}
$infVerif=Join-Path (Split-Path -Parent (Split-Path -Parent $WdkBin)) 'Tools\10.0.26100.0\arm64\InfVerif.exe'
foreach($tool in @($infVerif,(Join-Path $WdkBin 'arm64\signtool.exe'),(Join-Path $WdkBin 'x86\Inf2Cat.exe'))){
 if(!(Test-Path -LiteralPath $tool)){throw "Required WDK tool absent: $tool"}
}
$thumb='F38EDD5C105095C8342556158CE66253F045965D'
$cert=Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumb"
if(!$cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date)){throw 'Existing signing key unavailable or expired'}
$inf='C:\Windows\System32\DriverStore\FileRepository\qcpmicext8150.inf_arm64_fe1800db720f064c\qcpmicext8150.inf'
if((Get-FileHash -LiteralPath $inf).Hash -ne '8A52F8F803D001AE4F74A439B2F606903BC125569EDE84520712359C7AEF97FD'){throw 'Unknown source INF'}
$text=Get-Content -LiteralPath $inf -Raw -Encoding Unicode
$text=$text -replace 'DriverVer\s*=\s*[\d/]+,\s*[\d.]+','DriverVer   = 10/27/2026, 1.0.1849.0'
New-Item -ItemType Directory -Path $pkg | Out-Null
[IO.File]::WriteAllText((Join-Path $pkg 'qcpmicext8150.inf'),$text,[Text.Encoding]::Unicode)
Copy-Item -LiteralPath $unsigned -Destination (Join-Path $pkg 'qcpmicext8150.sys')
$sign=Join-Path $WdkBin 'arm64\signtool.exe'
& $sign sign /fd SHA256 /ph /s My /sha1 $thumb /d 'Nabu PMIC 1849 parameter encoding experiment' (Join-Path $pkg 'qcpmicext8150.sys') *> (Join-Path $root 'build\sign-sys.log')
if($LASTEXITCODE){throw 'SYS signing failed'}
& $infVerif /u /v (Join-Path $pkg 'qcpmicext8150.inf') *> (Join-Path $root 'build\infverif.log')
if($LASTEXITCODE){throw 'INF verification failed'}
& (Join-Path $WdkBin 'x86\Inf2Cat.exe') "/driver:$pkg" /os:10_GE_ARM64 /uselocaltime /v *> (Join-Path $root 'build\inf2cat.log')
if($LASTEXITCODE){throw 'Catalog generation failed'}
& $sign sign /fd SHA256 /s My /sha1 $thumb /d 'Nabu PMIC 1849 experimental package' (Join-Path $pkg 'qcpmicext8150.cat') *> (Join-Path $root 'build\sign-cat.log')
if($LASTEXITCODE){throw 'Catalog signing failed'}
foreach($name in @('qcpmicext8150.sys','qcpmicext8150.inf')){
 & $sign verify /pa /v /c (Join-Path $pkg 'qcpmicext8150.cat') (Join-Path $pkg $name) *> (Join-Path $root ('build\catalog-'+$name+'-verification.log'))
 if($LASTEXITCODE){throw "Catalog membership verification failed: $name"}
}
$entries=@(Get-ChildItem -LiteralPath $pkg -File | ForEach-Object {[ordered]@{path=('package/'+$_.Name);sha256=(Get-FileHash -LiteralPath $_.FullName).Hash;bytes=$_.Length}})
[ordered]@{
 schema=1;name='pmic1849-encoding';status='EXPERIMENTAL_NOT_HARDWARE_TESTED';version='1.0.1849.0';
 hardwareId='ACPI\QCOM05E5';signerThumbprint=$thumb;files=$entries;
 legacyUnmodifiedBinary=$false;installed=$false;bootTested=$false;completeChargingFix=$false;
 base='Unmodified stock 1840 package / PE FileVersion1680';
 scope='Four parameter encoding operations only. No role/suspend/USB recovery changes.'
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'package-manifest.json') -Encoding utf8
'Test-signed package created. No installation, certificate import, BCD change or reboot.'
