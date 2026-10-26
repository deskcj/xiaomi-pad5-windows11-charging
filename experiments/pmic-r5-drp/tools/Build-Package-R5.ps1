param([string]$ProjectRoot='H:\Vlad\Charging',[string]$WdkBin='H:\Vlad\EWDK\Program Files\Windows Kits\10\bin\10.0.26100.0')
$ErrorActionPreference='Stop'
$root=Join-Path $ProjectRoot 'candidate-fix20r5-drp'
$pkg=Join-Path $root 'package'
$unsigned=Join-Path $root 'build\qcpmicext8150_unsigned.sys'
if((Get-FileHash -LiteralPath $unsigned).Hash -ne '0259D1267A08BD26D4611D5529A91E5902EE7B9819B74668D479AB438579EA0D'){throw 'Unexpected unsigned r5 SYS'}
$emulation=Get-Content -LiteralPath (Join-Path $root 'build\emulation-report.json') -Raw|ConvertFrom-Json
$unwind=Get-Content -LiteralPath (Join-Path $root 'build\native-unwind-report.txt') -Raw|ConvertFrom-Json
if($emulation.passedARM64Cases -ne 3907 -or $unwind.nativeARM64UnwindCases -ne 307 -or $unwind.failures -ne 0){throw 'Required offline checks have not passed'}
$diag=Get-Content -LiteralPath (Join-Path $root 'build\diagnostic-emulation-report.json') -Raw|ConvertFrom-Json
if($diag.DiagnosticCallbackCases -ne 882 -or $diag.OriginalDispatcherIntegrationCases -ne 19 -or $diag.PMICWriteAttempts -ne 0){throw 'Diagnostic tests have not passed'}
$thumb='F38EDD5C105095C8342556158CE66253F045965D'
$cert=Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumb"
if(!$cert.HasPrivateKey){throw 'Existing test signing key unavailable'}
New-Item -ItemType Directory -Path $pkg -Force|Out-Null
if(@(Get-ChildItem -LiteralPath $pkg -File|Where-Object Name -notin @('qcpmicext8150.inf','qcpmicext8150.sys','qcpmicext8150.cat')).Count){throw 'Unexpected package file'}
$originalInf=Join-Path $ProjectRoot 'Charging-Rollback-2026-10-26\packages\qcpmicext8150.inf_arm64_fe1800db720f064c\qcpmicext8150.inf'
$text=Get-Content -LiteralPath $originalInf -Raw -Encoding Unicode
if($text -notmatch 'ACPI\\QCOM05E5'){throw 'Unexpected INF hardware ID'}
$text=$text -replace 'DriverVer\s*=\s*[\d/]+,\s*[\d.]+','DriverVer   = 10/26/2026, 1.0.1847.0'
[IO.File]::WriteAllText((Join-Path $pkg 'qcpmicext8150.inf'),$text,[Text.Encoding]::Unicode)
Copy-Item -LiteralPath $unsigned -Destination (Join-Path $pkg 'qcpmicext8150.sys') -Force
$sign=Join-Path $WdkBin 'arm64\signtool.exe'
& $sign sign /fd SHA256 /ph /s My /sha1 $thumb /d 'Nabu PMIC r5 DRP request preservation' (Join-Path $pkg 'qcpmicext8150.sys')
if($LASTEXITCODE){throw 'SYS signing failed'}
& (Join-Path $WdkBin 'x86\Inf2Cat.exe') "/driver:$pkg" /os:10_GE_ARM64 /v *> (Join-Path $root 'inf2cat.log')
if($LASTEXITCODE){throw 'Catalog generation failed'}
& $sign sign /fd SHA256 /s My /sha1 $thumb /d 'Nabu PMIC r5 experimental DRP package' (Join-Path $pkg 'qcpmicext8150.cat')
if($LASTEXITCODE){throw 'Catalog signing failed'}
& $sign verify /pa /v /c (Join-Path $pkg 'qcpmicext8150.cat') (Join-Path $pkg 'qcpmicext8150.sys') *> (Join-Path $root 'catalog-verification.log')
if($LASTEXITCODE){throw 'Catalog/SYS verification failed'}
$entries=@(Get-ChildItem -LiteralPath $pkg -File|ForEach-Object {[ordered]@{path=('package/'+$_.Name);sha256=(Get-FileHash -LiteralPath $_.FullName).Hash;bytes=$_.Length}})
[ordered]@{schema=1;name='candidate-fix20r5-drp';status='EXPERIMENTAL_NOT_HARDWARE_TESTED';version='1.0.1847.0';hardwareId='ACPI\QCOM05E5';signerThumbprint=$thumb;miniclassRequired='1.0.1680.0';legacyUnmodifiedBinary=$false;legacyUnmodifiedCode=$false;files=$entries;installed=$false;supportedLogicalSlots=@(0,1);note='Remove legacy SOURCE override for DRP; diagnostic interface retained; hardware validation pending'}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'package-manifest.json') -Encoding utf8
'R5 DRP package signed and catalog membership verified. No driver installation performed.'
