param([Parameter(Mandatory=$true)][string]$PackageDirectory,[Parameter(Mandatory=$true)][string]$WorkDirectory)
$ErrorActionPreference='Stop'
$fixture=Join-Path $WorkDirectory ('prestage-recovery-fixture-'+[guid]::NewGuid().ToString('N'))
$win=Join-Path $fixture 'offline\Windows'
$run=Join-Path $fixture 'recovery'
$relative='System32\DriverStore\FileRepository\qcpmicext8150.inf_arm64_fe1800db720f064c'
New-Item -ItemType Directory -Path "$win\System32\config",(Join-Path $win $relative),"$run\baseline-package" -Force|Out-Null
[IO.File]::WriteAllText("$win\System32\config\SYSTEM",'OFFLINE_FIXTURE_NOT_A_REAL_HIVE')
[IO.File]::WriteAllText("$run\SYSTEM-before.hiv",'POST_STAGE_FIXTURE')
[IO.File]::WriteAllText("$run\SYSTEM-before-stage.hiv",'PRE_STAGE_FIXTURE')
[IO.File]::WriteAllText("$run\BCD-before",'BCD_FIXTURE')
$files=@()
foreach($name in @('qcpmicext8150.sys','qcpmicext8150.inf','qcpmicext8150.cat')){
 [IO.File]::WriteAllText("$run\baseline-package\$name",'BASELINE_FIXTURE_'+$name)
 $files+=@{name=$name;sha256=(Get-FileHash -LiteralPath "$run\baseline-package\$name").Hash}
}
$record=[ordered]@{Mode='Activate';BaselineSysSHA256='533C3A555E111D4B12B657D026C92D63D5170D57297432D03BDAF3BE96C7886A';BaselinePublishedInf='oem92.inf';NewPublishedInf='oem9999.inf';NewPackageExistedBefore=$false;BaselineWindowsRelativeDirectory=$relative;SYSTEMSHA256=(Get-FileHash -LiteralPath "$run\SYSTEM-before.hiv").Hash;BCDSHA256=(Get-FileHash -LiteralPath "$run\BCD-before").Hash;BaselineFiles=$files;RestoreSYSTEMFile='SYSTEM-before-stage.hiv';RestoreSYSTEMSHA256=(Get-FileHash -LiteralPath "$run\SYSTEM-before-stage.hiv").Hash}
function SaveRecord{$record|ConvertTo-Json -Depth 4|Set-Content -LiteralPath "$run\recovery-record.json" -Encoding utf8}
function Preview{& (Join-Path $PackageDirectory 'Restore-ExperimentOffline.ps1') -WindowsRoot $win -RecoveryDirectory $run}
SaveRecord
$output=Preview|Out-String
if($output -notmatch 'SYSTEM snapshot selected for restore: SYSTEM-before-stage.hiv' -or $output -notmatch 'PREVIEW ONLY'){throw 'Did not select the pre-stage snapshot in preview'}
$passed=1
# r2 must accept the exact installed r1 baseline for its recovery preview.
$record.BaselineSysSHA256='52B631FC7DA75D3CB3BFA9F9FAC6E6220AAEEF30AD297D76891BE42AD5FABA15';SaveRecord
$r1Preview=Preview|Out-String
if($r1Preview -notmatch 'PREVIEW ONLY'){throw 'r1 baseline recovery preview failed'}
$passed++
$record.BaselineSysSHA256='5257CD32AAD6591113B191D45183CDC6BB397DDB4FD7B2580A9B70AECC80A474';SaveRecord
$r2Preview=Preview|Out-String
if($r2Preview -notmatch 'PREVIEW ONLY'){throw 'r2 baseline recovery preview failed'}
$passed++
$record.BaselineSysSHA256='0'*64;SaveRecord
try{Preview;throw 'GUARD_FAILED'}catch{if($_.Exception.Message -ne 'Unknown baseline'){throw};$passed++}
$record.BaselineSysSHA256='52B631FC7DA75D3CB3BFA9F9FAC6E6220AAEEF30AD297D76891BE42AD5FABA15';SaveRecord
$record.RestoreSYSTEMSHA256='0'*64;SaveRecord
try{Preview;throw 'GUARD_FAILED'}catch{if($_.Exception.Message -ne 'Pre-stage SYSTEM snapshot hash mismatch'){throw};$passed++}
$record.Remove('RestoreSYSTEMFile');$record.Remove('RestoreSYSTEMSHA256');SaveRecord
try{Preview;throw 'GUARD_FAILED'}catch{if($_.Exception.Message -notlike 'Activate record lacks*'){throw};$passed++}
$record.RestoreSYSTEMFile='SYSTEM-before.hiv';$record.RestoreSYSTEMSHA256=$record.SYSTEMSHA256;SaveRecord
try{Preview;throw 'GUARD_FAILED'}catch{if($_.Exception.Message -ne 'Activate recovery requires the pre-stage SYSTEM snapshot'){throw};$passed++}
if([IO.File]::ReadAllText("$win\System32\config\SYSTEM") -ne 'OFFLINE_FIXTURE_NOT_A_REAL_HIVE'){throw 'Preview changed the fixture hive'}
[ordered]@{PassedSnapshotSelectionGuards=$passed;OfflineApplyTested=$false;RealWindowsModified=$false}|ConvertTo-Json
