param(
 [Parameter(Mandatory=$true)][string]$WindowsRoot,
 [Parameter(Mandatory=$true)][string]$RecoveryDirectory,
 [switch]$Apply
)
$ErrorActionPreference='Stop'
$win=(Resolve-Path -LiteralPath $WindowsRoot).Path.TrimEnd('\')
$run=(Resolve-Path -LiteralPath $RecoveryDirectory).Path.TrimEnd('\')
if($win -ieq ([IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\'))){throw 'Refusing the running Windows installation'}
foreach($path in @($win,(Split-Path -Parent $win),$run)){if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse-point root rejected'}}
$record=Get-Content -LiteralPath "$run\recovery-record.json" -Raw|ConvertFrom-Json
if($record.BaselineSysSHA256 -notin @('533C3A555E111D4B12B657D026C92D63D5170D57297432D03BDAF3BE96C7886A','9955517922E3A0D13287034616C08F8DBAD1322C248954477A144073F5F606D2')){throw 'Unknown baseline'}
if($record.NewPublishedInf -notmatch '^oem\d+\.inf$' -or $record.NewPublishedInf -eq $record.BaselinePublishedInf){throw 'Missing or unsafe experimental package identity. Inspect recovery record manually.'}
if($record.NewPackageExistedBefore){throw 'Experimental package existed before this operation. Do not automatically remove it; inspect manually.'}
if($record.BaselineWindowsRelativeDirectory -notmatch '^System32\\DriverStore\\FileRepository\\qcpmicext8150\.inf_arm64_[a-f0-9]+$'){throw 'Unexpected baseline directory'}
$targetDir=Join-Path $win $record.BaselineWindowsRelativeDirectory
if(!(Test-Path -LiteralPath "$win\System32\config\SYSTEM") -or !(Test-Path -LiteralPath $targetDir)){throw 'Not the expected mounted offline Windows/package tree'}
if((Get-FileHash -LiteralPath "$run\SYSTEM-before.hiv").Hash -ne $record.SYSTEMSHA256){throw 'SYSTEM snapshot hash mismatch'}
 $restoreSYSTEMFile=$record.RestoreSYSTEMFile
 $restoreSYSTEMHash=$record.RestoreSYSTEMSHA256
 if(!$restoreSYSTEMFile -or !$restoreSYSTEMHash){
  if($record.Mode -eq 'Activate'){throw 'Activate record lacks a verified pre-stage SYSTEM snapshot. Do not restore the hive containing the removed package registration.'}
  $restoreSYSTEMFile='SYSTEM-before.hiv';$restoreSYSTEMHash=$record.SYSTEMSHA256
 }
 if($restoreSYSTEMFile -notin @('SYSTEM-before.hiv','SYSTEM-before-stage.hiv')){throw 'Unexpected SYSTEM restore file'}
 if($record.Mode -eq 'Activate' -and $restoreSYSTEMFile -ne 'SYSTEM-before-stage.hiv'){throw 'Activate recovery requires the pre-stage SYSTEM snapshot'}
 if((Get-FileHash -LiteralPath (Join-Path $run $restoreSYSTEMFile)).Hash -ne $restoreSYSTEMHash){throw 'Pre-stage SYSTEM snapshot hash mismatch'}
if((Get-FileHash -LiteralPath "$run\BCD-before").Hash -ne $record.BCDSHA256){throw 'BCD snapshot hash mismatch'}
if(@($record.BaselineFiles).Count -ne 3){throw 'Incomplete baseline file manifest'}
foreach($f in $record.BaselineFiles){
 if($f.name -notmatch '^qcpmicext8150\.(sys|inf|cat)$'){throw 'Unexpected baseline file name'}
 if((Get-FileHash -LiteralPath "$run\baseline-package\$($f.name)").Hash -ne $f.sha256){throw 'Baseline file hash mismatch'}
}
Write-Output "Offline Windows: $win"
Write-Output "SYSTEM snapshot selected for restore: $restoreSYSTEMFile"
Write-Output "Remove only the recorded experimental package: $($record.NewPublishedInf)"
Write-Output "Restore baseline package: $($record.BaselinePublishedInf) and complete pre-experiment SYSTEM snapshot"
Write-Output 'BCD will not be overwritten; the installer never changed BCD. Full SYSTEM restoration also reverts other system configuration changes made since its snapshot.'
if(!$Apply){Write-Output 'PREVIEW ONLY. No package, hive or driver file changed.';return}
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(!$admin){throw 'Apply requires an elevated recovery terminal'}
# Verify the exact newly published INF before DISM removal. Do not infer it by version/name.
$offlineInf=Join-Path $win ('INF\'+$record.NewPublishedInf)
if(!(Test-Path -LiteralPath $offlineInf)){throw 'Recorded experimental INF is absent; inspect the offline image before proceeding'}
$newInf=Join-Path $run 'new-package\qcpmicext8150.inf'
if((Get-FileHash -LiteralPath $offlineInf).Hash -ne (Get-FileHash -LiteralPath $newInf).Hash){throw 'Offline experimental INF does not match the recorded package'}
$undo=Join-Path (Split-Path -Parent $win) ('Charging-rescue-undo-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path "$undo\baseline-package" -Force|Out-Null
Copy-Item -LiteralPath "$win\System32\config\SYSTEM" -Destination "$undo\SYSTEM.before-rescue"
foreach($f in $record.BaselineFiles){Copy-Item -LiteralPath (Join-Path $targetDir $f.name) -Destination "$undo\baseline-package\$($f.name)"}
# The offline hive must not be loaded by another program. DISM itself verifies
# that this is an offline image and refuses servicing the running OS this way.
$imageRoot=Split-Path -Parent $win
& dism.exe "/Image:$imageRoot" /Remove-Driver "/Driver:$($record.NewPublishedInf)" "/LogPath:$undo\dism-remove.log"
if($LASTEXITCODE -notin @(0,3010)){throw 'DISM did not remove the recorded experiment. Stop and inspect its log; SYSTEM not replaced.'}
foreach($f in $record.BaselineFiles){
 Copy-Item -LiteralPath "$run\baseline-package\$($f.name)" -Destination (Join-Path $targetDir $f.name) -Force
 if((Get-FileHash -LiteralPath (Join-Path $targetDir $f.name)).Hash -ne $f.sha256){throw 'Restored baseline file failed verification'}
}
Copy-Item -LiteralPath (Join-Path $run $restoreSYSTEMFile) -Destination "$win\System32\config\SYSTEM" -Force
if((Get-FileHash -LiteralPath "$win\System32\config\SYSTEM").Hash -ne $restoreSYSTEMHash){throw 'Restored SYSTEM hash mismatch'}
# SYSTEM.LOG1/LOG2 belong to the newer hive and must not be replayed onto the
# restored snapshot. Preserve them in the undo directory instead of deleting.
foreach($name in @('SYSTEM.LOG1','SYSTEM.LOG2')){
 $log=Join-Path $win ('System32\config\'+$name)
 if(Test-Path -LiteralPath $log){Move-Item -LiteralPath $log -Destination (Join-Path $undo $name)}
}
Write-Output "Recorded experiment removed, baseline and SYSTEM restored. Rescue undo: $undo"
Write-Output 'No reboot performed. Disconnect only after all offline access has finished.'
