[CmdletBinding()]
param(
 [ValidateSet('Inspect','Stage','Activate')][string]$Mode='Inspect',
 [switch]$AcknowledgeExperimental,
 [string]$StagedRecoveryDirectory='',
 [string]$ExternalRecoveryRoot='',
 [string]$BackupRoot=(Join-Path $env:ProgramData 'NabuCharging\Rollback')
)
$ErrorActionPreference='Stop'
$manifestPath=Join-Path $PSScriptRoot 'package-manifest.json'
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
if($manifest.schema -ne 1 -or $manifest.hardwareId -ne 'ACPI\QCOM05E5'){throw 'Unknown package manifest'}
$expectedSigner='F38EDD5C105095C8342556158CE66253F045965D'
if($manifest.signerThumbprint -ne $expectedSigner){throw 'Unexpected package signer'}
if($manifest.status -ne 'EXPERIMENTAL_NOT_HARDWARE_TESTED'){throw 'Unexpected package status'}
$pkg=Join-Path $PSScriptRoot 'package'
$sourceHashes=@{}
foreach($f in $manifest.files){
 if($f.path -notmatch '^package/(qcpmicext8150\.(inf|sys|cat))$'){throw 'Unexpected manifest path'}
 $file=Join-Path $PSScriptRoot $f.path
 if((Get-FileHash -LiteralPath $file).Hash -ne $f.sha256){throw "Package hash mismatch: $($f.path)"}
 $sourceHashes[(Split-Path -Leaf $file)]=$f.sha256
}
if($sourceHashes.Count -ne 3){throw 'Incomplete package'}
$cat=Get-AuthenticodeSignature -LiteralPath (Join-Path $pkg 'qcpmicext8150.cat')
$catalogTrusted=($cat.Status -eq 'Valid' -and $cat.SignerCertificate.Thumbprint -eq $expectedSigner)
if($manifest.legacyUnmodifiedBinary){
 if($sourceHashes['qcpmicext8150.sys'] -ne '9955517922E3A0D13287034616C08F8DBAD1322C248954477A144073F5F606D2'){throw 'Legacy binary is not the original fix20'}
}else{
 $signedSys=Get-AuthenticodeSignature -LiteralPath (Join-Path $pkg 'qcpmicext8150.sys')
 if($signedSys.SignerCertificate.Thumbprint -ne $expectedSigner){throw 'Unexpected SYS signer'}
 if($Mode -ne 'Inspect' -and $signedSys.Status -ne 'Valid'){throw 'SYS signature is not trusted'}
}
$computer=Get-CimInstance Win32_ComputerSystem
if($computer.Manufacturer -ne 'Xiaomi' -or $computer.Model -ne 'Pad 5'){throw 'This package is restricted to Xiaomi Pad 5 nabu'}
if($env:PROCESSOR_ARCHITECTURE -ne 'ARM64'){throw 'Run native ARM64 PowerShell'}
$devs=@(Get-PnpDevice -PresentOnly|Where-Object InstanceId -like 'ACPI\QCOM05E5\*')
if($devs.Count -ne 1){throw 'Expected exactly one present QCOM05E5 node'}
$id=$devs[0].InstanceId
function Prop([string]$instance,[string]$name){(Get-PnpDeviceProperty -InstanceId $instance -KeyName ('DEVPKEY_Device_'+$name)).Data}
$published=Prop $id 'DriverInfPath'
$service=Prop $id 'Service'
if($service -ne 'qcpmicext'){throw 'Unexpected device service'}
$battery=@(Get-PnpDevice -PresentOnly|Where-Object InstanceId -like 'ACPI\QCOM052D\*')
if($battery.Count -ne 1){throw 'Expected one nabu battery miniclass node'}
$batteryVersion=Prop $battery[0].InstanceId 'DriverVersion'
if($batteryVersion -ne '1.0.1680.0'){throw "Battery miniclass must remain 1680, found $batteryVersion. This installer does not change it."}
$serviceSettings=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\qcpmicext'
$rawImage=[Environment]::ExpandEnvironmentVariables($serviceSettings.ImagePath)
$image=$rawImage -replace '^\\SystemRoot\\',($env:SystemRoot+'\') -replace '^\\\?\?\\',''
if(![IO.Path]::IsPathRooted($image)){$image=Join-Path $env:SystemRoot $image}
$image=[IO.Path]::GetFullPath($image)
$store=Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
if(!$image.StartsWith($store+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected current image location'}
$currentHash=(Get-FileHash -LiteralPath $image).Hash
$allowed=@('533C3A555E111D4B12B657D026C92D63D5170D57297432D03BDAF3BE96C7886A','9955517922E3A0D13287034616C08F8DBAD1322C248954477A144073F5F606D2',$sourceHashes['qcpmicext8150.sys'])
if($currentHash -notin $allowed){throw 'Unknown current PMIC image; investigate before any installation'}
$version=Prop $id 'DriverVersion'
$info=[ordered]@{Mode=$Mode;Package=$manifest.name;Status=$manifest.status;TargetVersion=$manifest.version;CurrentPublishedInf=$published;CurrentVersion=$version;CurrentImageSHA256=$currentHash;BatteryVersion=$batteryVersion;CatalogTrusted=$catalogTrusted;RequiresTestMode=$true;AutomaticRestart=$false;DeviceRemoval=$false;HostModeChanges=$false}
$info|ConvertTo-Json
if($Mode -eq 'Inspect'){
 Write-Output 'READ-ONLY INSPECTION. Nothing staged, installed, disabled or restarted. Stage/Activate require an elevated terminal, trusted certificate and test signing.'
 return
}
if(!$AcknowledgeExperimental){throw 'Stage/Activate require -AcknowledgeExperimental. This package is not hardware-validated.'}
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(!$admin){throw 'Stage/Activate require an elevated native ARM64 PowerShell'}
if(!$catalogTrusted){throw 'Catalog test certificate is not trusted. Review NabuCameraDev-public.cer separately; this installer never imports certificates.'}
$bootText=(& bcdedit.exe /enum '{current}' 2>&1|Out-String)
if($LASTEXITCODE -or $bootText -notmatch '(?im)^\s*testsigning\s+Yes\s*$'){throw 'Cannot confirm current testsigning=Yes; no BCD changes will be made'}
$secure=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop).UEFISecureBootEnabled
if($null -eq $secure -or $secure -ne 0){throw 'Secure Boot must be confirmed disabled; no firmware settings will be changed'}
$pending=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations
if(($pending|Out-String) -match 'qcpmicext8150'){throw 'Pending PMIC replacement found. Resolve it before staging; queue is not modified.'}
if($currentHash -eq $sourceHashes['qcpmicext8150.sys']){Write-Output 'The selected binary is already on disk; no operation performed.';return}
$priorStage=$null
if($Mode -eq 'Activate'){
 if(!$StagedRecoveryDirectory){throw 'Activate requires -StagedRecoveryDirectory from the successful Stage operation'}
 if(!$ExternalRecoveryRoot){throw 'Activate requires -ExternalRecoveryRoot on an external volume; verified rescue copies must exist before changing the live binding'}
 $externalRoot=[IO.Path]::GetFullPath($ExternalRecoveryRoot)
 if([IO.Path]::GetPathRoot($externalRoot) -ieq [IO.Path]::GetPathRoot($env:SystemRoot)){throw 'External recovery must be on another volume'}
 if(!(Test-Path -LiteralPath ([IO.Path]::GetPathRoot($externalRoot)))){throw 'External recovery volume is unavailable'}
 $priorPath=Join-Path $StagedRecoveryDirectory 'recovery-record.json'
 $priorStage=Get-Content -LiteralPath $priorPath -Raw|ConvertFrom-Json
 if($priorStage.Mode -ne 'Stage' -or $priorStage.Package -ne $manifest.name -or $priorStage.NewSysSHA256 -ne $sourceHashes['qcpmicext8150.sys'] -or $priorStage.BaselinePublishedInf -ne $published -or $priorStage.BaselineSysSHA256 -ne $currentHash -or $priorStage.InstanceId -ne $id){throw 'Stage record does not match this package and current baseline'}
 if($priorStage.NewPackageExistedBefore -ne $false -or $priorStage.NewPublishedInf -notmatch '^oem\d+\.inf$'){throw 'Cannot establish that the tracked Stage created the experimental package'}
 if((Get-FileHash -LiteralPath (Join-Path $StagedRecoveryDirectory 'SYSTEM-before.hiv')).Hash -ne $priorStage.SYSTEMSHA256){throw 'Stage SYSTEM backup hash mismatch'}
}
$backupAbs=[IO.Path]::GetFullPath($BackupRoot)
if([IO.Path]::GetPathRoot($backupAbs) -ine [IO.Path]::GetPathRoot($env:SystemRoot)){throw 'BackupRoot must be on the internal Windows volume'}
$stamp=(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N').Substring(0,6)
$run=Join-Path $backupAbs $stamp
New-Item -ItemType Directory -Path "$run\baseline-package","$run\new-package" -Force|Out-Null
Start-Transcript -LiteralPath "$run\install-transcript.txt"|Out-Null
try{
 $currentDir=Split-Path -Parent $image
 foreach($name in @('qcpmicext8150.sys','qcpmicext8150.inf','qcpmicext8150.cat')){
  Copy-Item -LiteralPath (Join-Path $currentDir $name) -Destination "$run\baseline-package\$name"
  if((Get-FileHash -LiteralPath "$run\baseline-package\$name").Hash -ne (Get-FileHash -LiteralPath (Join-Path $currentDir $name)).Hash){throw 'Baseline backup verification failed'}
  Copy-Item -LiteralPath (Join-Path $pkg $name) -Destination "$run\new-package\$name"
  if((Get-FileHash -LiteralPath "$run\new-package\$name").Hash -ne $sourceHashes[$name]){throw 'Internal staging copy mismatch'}
 }
 & reg.exe save HKLM\SYSTEM "$run\SYSTEM-before.hiv" /y
 if($LASTEXITCODE){throw 'Full SYSTEM backup failed; staging cancelled'}
 & bcdedit.exe /export "$run\BCD-before"
 if($LASTEXITCODE){throw 'BCD backup failed; staging cancelled'}
 & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\qcpmicext' "$run\qcpmicext-service-before.reg" /y
 if($LASTEXITCODE){throw 'Service export failed'}
 $beforeDrivers=@(Get-WindowsDriver -Online|Where-Object {$_.OriginalFileName -like '*\qcpmicext8150.inf'})
 $record=[ordered]@{At=(Get-Date -Format o);Mode=$Mode;BaselinePublishedInf=$published;BaselineVersion=$version;BaselineImagePath=$rawImage;BaselineWindowsRelativeDirectory=$currentDir.Substring($env:SystemRoot.Length+1);BaselineSysSHA256=$currentHash;InstanceId=$id;BaselineDriverKey=(Prop $id 'Driver');Package=$manifest.name;NewSysSHA256=$sourceHashes['qcpmicext8150.sys'];NewPublishedInf=$null;SYSTEMSHA256=(Get-FileHash "$run\SYSTEM-before.hiv").Hash;BCDSHA256=(Get-FileHash "$run\BCD-before").Hash;NativePnPExit=$null;ActivationRequested=($Mode -eq 'Activate')}
 $record.BaselineFiles=@(Get-ChildItem -LiteralPath "$run\baseline-package" -File|ForEach-Object {[ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Restore-ExperimentOffline.ps1') -Destination "$run\Restore-ExperimentOffline.ps1"
 # Recovery removes the staged package through DISM. Restore a SYSTEM hive
 # from BEFORE that package entered DriverDatabase, not the Activate snapshot
 # which already contains its staged registration.
 if($priorStage){
  Copy-Item -LiteralPath (Join-Path $StagedRecoveryDirectory 'SYSTEM-before.hiv') -Destination "$run\SYSTEM-before-stage.hiv"
  if((Get-FileHash -LiteralPath "$run\SYSTEM-before-stage.hiv").Hash -ne $priorStage.SYSTEMSHA256){throw 'Pre-stage SYSTEM backup verification failed'}
  $record.RestoreSYSTEMFile='SYSTEM-before-stage.hiv'
  $record.RestoreSYSTEMSHA256=$priorStage.SYSTEMSHA256
 }else{
  $record.RestoreSYSTEMFile='SYSTEM-before.hiv'
  $record.RestoreSYSTEMSHA256=$record.SYSTEMSHA256
 }
 $record|ConvertTo-Json -Depth 4|Set-Content -LiteralPath "$run\recovery-record.json" -Encoding utf8
 # Stage only first. Native PnP validates catalog membership. No live PMIC reset.
 & pnputil.exe /add-driver "$run\new-package\qcpmicext8150.inf"
 $stageExit=$LASTEXITCODE
 if($stageExit -notin @(0,3010)){throw "Native package staging failed: $stageExit"}
 $afterDrivers=@(Get-WindowsDriver -Online|Where-Object {$_.OriginalFileName -like '*\qcpmicext8150.inf'})
 $exact=@($afterDrivers|Where-Object { $path=Join-Path (Split-Path -Parent $_.OriginalFileName) 'qcpmicext8150.sys';(Test-Path -LiteralPath $path) -and (Get-FileHash -LiteralPath $path).Hash -eq $sourceHashes['qcpmicext8150.sys'] })
 if($exact.Count -ne 1){throw 'Cannot identify exactly one staged experimental package; activation cancelled. Keep recovery-record.json.'}
 $record.NewPublishedInf=$exact[0].Driver
 if($record.NewPublishedInf -eq $published){throw 'Experimental package identification overlaps baseline; activation cancelled'}
 $record.NewPackageExistedBeforeThisInvocation=($record.NewPublishedInf -in @($beforeDrivers.Driver))
 if($priorStage){
  if($record.NewPublishedInf -ne $priorStage.NewPublishedInf){throw 'Staged package identity changed since Stage; activation cancelled'}
  $record.NewPackageExistedBefore=$false
  $record.TrackedStageRecordSHA256=(Get-FileHash -LiteralPath (Join-Path $StagedRecoveryDirectory 'recovery-record.json')).Hash
 }else{$record.NewPackageExistedBefore=$record.NewPackageExistedBeforeThisInvocation}
 $record|ConvertTo-Json -Depth 4|Set-Content -LiteralPath "$run\recovery-record.json" -Encoding utf8
 if($Mode -eq 'Activate'){
  # Complete and verify an EXTERNAL rescue copy before the first operation that
  # can change the live PMIC binding. It survives an immediate failure/BSOD.
  $mirror=Join-Path $externalRoot $stamp
  if(Test-Path -LiteralPath $mirror){throw 'External recovery destination already exists'}
  New-Item -ItemType Directory -Path $mirror -Force|Out-Null
  Get-ChildItem -LiteralPath $run -Force|Where-Object Name -ne 'install-transcript.txt'|Copy-Item -Destination $mirror -Recurse
  foreach($source in (Get-ChildItem -LiteralPath $run -Recurse -File|Where-Object Name -ne 'install-transcript.txt')){
   $relative=$source.FullName.Substring($run.Length+1)
   $copy=Join-Path $mirror $relative
   # Close Copy-Item's buffered writes before a possible immediate system fault.
   $attributes=[IO.File]::GetAttributes($copy)
   if($attributes -band [IO.FileAttributes]::ReadOnly){[IO.File]::SetAttributes($copy,($attributes -band (-bnot [IO.FileAttributes]::ReadOnly)))}
   $flush=[IO.File]::Open($copy,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
   try{$flush.Flush($true)}finally{$flush.Dispose()}
   if((Get-FileHash -LiteralPath $source.FullName).Hash -ne (Get-FileHash -LiteralPath $copy).Hash){throw 'External rescue verification failed; activation cancelled'}
  }
  Write-Output "Verified external rescue snapshot: $mirror"
  # May update the running PnP binding. User must close external-drive activity
  # and prepare recovery before explicitly selecting Activate. Never auto-reboot.
  & pnputil.exe /add-driver "$run\new-package\qcpmicext8150.inf" /install
  $record.NativePnPExit=$LASTEXITCODE
  $record.PostPublishedInf=Prop $id 'DriverInfPath'
  $record.PostVersion=Prop $id 'DriverVersion'
  $record|ConvertTo-Json -Depth 4|Set-Content -LiteralPath "$run\recovery-record.json" -Encoding utf8
  if($record.NativePnPExit -notin @(0,3010)){throw "PnP activation failed: $($record.NativePnPExit). Preserve the recovery record."}
  if($record.PostPublishedInf -ne $record.NewPublishedInf){throw 'Windows retained another binding; do not force device removal. Inspect rank and logs.'}
 }
 Write-Output "Operation complete. Full backups and exact package identity: $run"
 Write-Output 'No reboot issued. Stage does not activate the package; Activate may change the live binding and still requires a controlled reboot/test.'
}finally{Stop-Transcript|Out-Null}
