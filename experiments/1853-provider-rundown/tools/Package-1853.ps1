[CmdletBinding()]
param([string]$Python='C:\Users\Xiaomi\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$pkg=Join-Path $root 'package'
if(Test-Path -LiteralPath $pkg){throw 'Signed package exists: never overwrite it'}
& $Python "$PSScriptRoot\audit_1853.py"
if($LASTEXITCODE){throw '1853 QA audit failed'}
$sdk='H:\Vlad\EWDK\Program Files\Windows Kits\10'
$sign=Join-Path $sdk 'bin\10.0.26100.0\arm64\signtool.exe'
$infverif=Join-Path $sdk 'Tools\10.0.26100.0\arm64\InfVerif.exe'
$inf2cat=Join-Path $sdk 'bin\10.0.26100.0\x86\Inf2Cat.exe'
$thumb='F38EDD5C105095C8342556158CE66253F045965D'
$cert=Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumb"
if(!$cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date)){throw 'Existing signing certificate unavailable'}
$name='qcusbctcpm8150'
$ref=Join-Path $root "reference\$name.inf"
if((Get-FileHash -LiteralPath $ref).Hash -ine '611A25FCFFFECDE9FD414F8FF5E8FABAF26B1C07DB7B8C40D0E7EA4AD6EBFC4C'){throw 'OEM INF mismatch'}
$text=[IO.File]::ReadAllText($ref)
if([regex]::Matches($text,'(?im)^DriverVer\s*=.*$').Count -ne 1 -or !$text.Contains('ACPI\QCOM057D')){throw 'INF binding mismatch'}
New-Item -ItemType Directory -Path $pkg | Out-Null
$text=[regex]::Replace($text,'(?im)^DriverVer\s*=\s*[\d/]+,\s*[\d.]+','DriverVer   = 10/28/2026, 1.0.1853.0')
[IO.File]::WriteAllText("$pkg\$name.inf",$text,[Text.Encoding]::Unicode)
Copy-Item -LiteralPath "$root\build\$name.sys" -Destination "$pkg\$name.sys"
& $sign sign /fd SHA256 /ph /s My /sha1 $thumb /d 'Nabu Charging1853 experimental alert rundown' "$pkg\$name.sys" *> "$root\build\sign-1853-sys.log"
if($LASTEXITCODE){throw 'SYS signing failed'}
& $infverif /u /v "$pkg\$name.inf" *> "$root\build\infverif-1853.log"
if($LASTEXITCODE){throw 'INF validation failed'}
& $inf2cat "/driver:$pkg" /os:10_GE_ARM64 /uselocaltime /v *> "$root\build\inf2cat-1853.log"
if($LASTEXITCODE){throw 'Catalog generation failed'}
& $sign sign /fd SHA256 /s My /sha1 $thumb /d 'Nabu Charging1853 experimental alert rundown' "$pkg\$name.cat" *> "$root\build\sign-1853-cat.log"
if($LASTEXITCODE){throw 'CAT signing failed'}
foreach($ext in @('sys','inf')){
 & $sign verify /pa /v /c "$pkg\$name.cat" "$pkg\$name.$ext" *> "$root\build\verify-1853-$ext.log"
 if($LASTEXITCODE){throw "Catalog signature/membership failed: $ext"}
}
& $sign verify /pa /v "$pkg\$name.sys" *> "$root\build\verify-1853-embedded.log"
if($LASTEXITCODE){throw 'Embedded signature verification failed'}
& $Python "$PSScriptRoot\audit_1853.py" --signed
if($LASTEXITCODE){throw 'Signature changed tested image'}
$files=@(Get-ChildItem -LiteralPath $pkg -File | Sort-Object Name | ForEach-Object {[ordered]@{path=('package/'+$_.Name);sha256=(Get-FileHash -LiteralPath $_.FullName).Hash;bytes=$_.Length}})
if($files.Count -ne 3){throw 'Expected one complete client SYS/INF/CAT package'}
[ordered]@{schema=1;name='SK-Charging-1853-provider-rundown';driverVersion='1.0.1853.0';hardwareId='ACPI\QCOM057D';
 status='TEST_SIGNED_OFFLINE_QA_PASSED_HARDWARE_BLOCKED';files=$files;signerThumbprint=$thumb;signerSubject=$cert.Subject;
 signatureType='Existing development certificate; Authenticode /pa verified; not Microsoft production/WHQL';
 qaSHA256=(Get-FileHash "$root\build\qa-1853.json").Hash;signedPayloadSHA256=(Get-FileHash "$root\build\signed-payload-1853.json").Hash;
 installed=$false;bootTested=$false;hardwareTested=$false;kernelExecuted=$false;completeChargingFixProven=$false;
 scope='1852 client fixes plus independent private-provider MMIO admission/rundown, atomic publication of mappings, guarded cleanup and PrepareHardware failure propagation. No PEP replacement included.';
 knownBlockers=@('PEP2140 lifetime0x13A remains unfixed','Initial pending-alert replay and single-producer audit remain open','Initial PEP power request retry after DEVICE_NOT_READY not implemented','Ghost AC and power-direction repair not included','No electrical PD, storage continuity or real SMP verification');
 deployment='Offline candidate; no installation script supplied; do not treat as complete hotplug fix';
 exclusions=@('PEP','PMIC1849','backend1851','battery manager/miniclass','URS/xHCI','camera','existing rollback');
 noInstallNoResetNoReboot=$true
} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath "$root\package-manifest.json" -Encoding utf8
'1853 test-signed offline package complete; nothing installed.'
