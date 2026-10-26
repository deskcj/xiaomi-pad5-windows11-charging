[CmdletBinding()]
param([string]$WdkBin='H:\Vlad\EWDK\Program Files\Windows Kits\10\bin\10.0.26100.0')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$unsigned=Join-Path $root 'build\qcpmicext8150_unsigned.sys'
$expected='FF92BA8D2C300FED5732E751FEF13C6F60E7BDCA44471333AA7F0E98F949CBE5'
if((Get-FileHash -LiteralPath $unsigned).Hash -ne $expected){throw 'Unexpected r6 image'}
foreach($pair in @(@('emulation-report.json','passedARM64Cases',3907),@('diagnostic-emulation-report.json','DiagnosticCallbackCases',882),@('role-vbus-sequence-report.json','statefulSequences',18),@('native-unwind-report.txt','nativeARM64UnwindCases',276))){
 $report=Get-Content -LiteralPath (Join-Path $root ('build\'+$pair[0])) -Raw | ConvertFrom-Json
 if($report.($pair[1]) -ne $pair[2]){throw "Offline check missing: $($pair[0])"}
 if($report.sha256 -and $report.sha256 -ine $expected){throw 'Test image hash mismatch'}
 if($report.candidateSHA256 -and $report.candidateSHA256 -ine $expected){throw 'Sequence test image hash mismatch'}
 if($report.failures -gt 0){throw 'Native unwind failure'}
}
$diag=Get-Content -LiteralPath (Join-Path $root 'build\diagnostic-emulation-report.json') -Raw | ConvertFrom-Json
if($diag.OriginalDispatcherIntegrationCases -ne 19 -or $diag.PMICWriteAttempts -ne 0){throw 'Diagnostic safety checks failed'}
$pkg=Join-Path $root 'package'
if(Test-Path -LiteralPath $pkg){throw 'Do not overwrite signed package'}
$thumb='F38EDD5C105095C8342556158CE66253F045965D'
$cert=Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumb"
if(!$cert.HasPrivateKey){throw 'Existing test-signing key unavailable; never create or import another'}
$inf='C:\Windows\System32\DriverStore\FileRepository\qcpmicext8150.inf_arm64_fe1800db720f064c\qcpmicext8150.inf'
if((Get-FileHash -LiteralPath $inf).Hash -ne '8A52F8F803D001AE4F74A439B2F606903BC125569EDE84520712359C7AEF97FD'){throw 'Unknown baseline INF'}
$text=Get-Content -LiteralPath $inf -Raw -Encoding Unicode
$text=$text -replace 'DriverVer\s*=\s*[\d/]+,\s*[\d.]+','DriverVer   = 10/27/2026, 1.0.1848.0'
New-Item -ItemType Directory -Path $pkg | Out-Null
[IO.File]::WriteAllText((Join-Path $pkg 'qcpmicext8150.inf'),$text,[Text.Encoding]::Unicode)
Copy-Item -LiteralPath $unsigned -Destination (Join-Path $pkg 'qcpmicext8150.sys')
$sign=Join-Path $WdkBin 'arm64\signtool.exe'
& $sign sign /fd SHA256 /ph /s My /sha1 $thumb /d 'Nabu PMIC r6 offline role VBUS separation candidate' (Join-Path $pkg 'qcpmicext8150.sys') *> (Join-Path $root 'build\sign-sys.log')
if($LASTEXITCODE){throw 'SYS signing failed'}
& (Join-Path $WdkBin 'x86\Inf2Cat.exe') "/driver:$pkg" /os:10_GE_ARM64 /uselocaltime /v *> (Join-Path $root 'build\inf2cat.log')
if($LASTEXITCODE){throw 'Catalog generation failed'}
& $sign sign /fd SHA256 /s My /sha1 $thumb /d 'Nabu PMIC r6 OFFLINE ONLY' (Join-Path $pkg 'qcpmicext8150.cat') *> (Join-Path $root 'build\sign-cat.log')
if($LASTEXITCODE){throw 'Catalog signing failed'}
& $sign verify /pa /v /c (Join-Path $pkg 'qcpmicext8150.cat') (Join-Path $pkg 'qcpmicext8150.sys') *> (Join-Path $root 'build\catalog-verification.log')
if($LASTEXITCODE){throw 'Catalog membership verification failed'}
$entries=@(Get-ChildItem -LiteralPath $pkg -File | ForEach-Object {[ordered]@{path=('package/'+$_.Name);sha256=(Get-FileHash -LiteralPath $_.FullName).Hash;bytes=$_.Length}})
[ordered]@{schema=1;name='candidate-fix20r6-role-vbus';status='OFFLINE_ONLY_NOT_HARDWARE_VALIDATED';version='1.0.1848.0';hardwareId='ACPI\QCOM05E5';signerThumbprint=$thumb;files=$entries;installed=$false;installationAuthorized=$false;installerIncluded=$false;liveBaselineMustRemain='1840/oem92';typeCLockFixIncluded=$false;completePDStack=$false;note='Source rebuild separates role request from explicit VBUS. Cold hub attachment and SSD Code43 are not proven fixed.'}|ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'package-manifest.json') -Encoding utf8
'Signed offline candidate only. No install, reboot, certificate import, BCD edit or device reset performed.'
