param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'Common.ps1')
$qa=Join-Path $PSScriptRoot ('qa-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $qa|Out-Null
$checks=@()
function Expect-Rejection([string]$Name,[scriptblock]$Action){
    $rejected=$false
    try{& $Action|Out-Null}catch{$rejected=$true}
    if(!$rejected){throw ('Guard failed: '+$Name)}
    $script:checks+=$Name
}
$m=Assert-SkPackage $Root -RequireTrusted;$checks+='four packages trusted and all15 payload hashes verified'
$devices=@(Get-SkDevices);$before=@(Get-SkBaseline $devices)
if(!(Assert-SkCompatibility $m $before)){throw 'Release does not match installed stack'}
$checks+='matches current five-package stack'
$copy=Join-Path $qa 'damaged-copy';Copy-Item -LiteralPath $Root -Destination $copy -Recurse
$file=Join-Path $copy 'packages\qcpmicext8150.sys';$bytes=[IO.File]::ReadAllBytes($file);$bytes[100]=$bytes[100] -bxor 1;[IO.File]::WriteAllBytes($file,$bytes)
Expect-Rejection 'corrupted SYS rejected' {Assert-SkPackage $copy}
Copy-Item -LiteralPath (Join-Path $Root 'packages\qcpmicext8150.sys') -Destination $file -Force
$cat=Join-Path $copy 'packages\qcpmictcc8150.cat';Move-Item -LiteralPath $cat -Destination ($cat+'.missing')
Expect-Rejection 'missing CAT rejected' {Assert-SkPackage $copy}
Move-Item -LiteralPath ($cat+'.missing') -Destination $cat
Set-Content -LiteralPath (Join-Path $copy 'packages\unexpected.txt') -Value 'test'
Expect-Rejection 'unexpected payload file rejected' {Assert-SkPackage $copy}
$fake=$before|ConvertTo-Json -Depth 5|ConvertFrom-Json
($fake|Where-Object Service -eq 'qcbattmngr').Version='1.0.99999.0'
Expect-Rejection 'automatic downgrade rejected' {Assert-SkCompatibility $m $fake}
$fake=$before|ConvertTo-Json -Depth 5|ConvertFrom-Json
($fake|Where-Object Service -eq 'qcbattminiclass').SHA256=('0'*64)
Expect-Rejection 'incompatible base miniclass rejected' {Assert-SkCompatibility $m $fake}
Expect-Rejection 'USB backup destination rejected' {Assert-SkInternalPath 'H:\SK-Charging-Test'}
$arch=$env:PROCESSOR_ARCHITECTURE
try{$env:PROCESSOR_ARCHITECTURE='AMD64';Expect-Rejection 'non ARM64 environment rejected' {Assert-SkTablet}}finally{$env:PROCESSOR_ARCHITECTURE=$arch}
$saved=Join-Path $qa 'Previous';Save-SkBackup $devices $saved;$reserve=Assert-SkBackup $saved
if(@($reserve.Packages.Files).Count -ne 15){throw 'Backup is incomplete'}
$checks+='real DriverStore backup15 files copied and verified'
$backupCat=Join-Path $saved 'packages\qcbattmngr8150.cat';$bytes=[IO.File]::ReadAllBytes($backupCat);$bytes[100]=$bytes[100] -bxor 1;[IO.File]::WriteAllBytes($backupCat,$bytes)
Expect-Rejection 'damaged backup rejected' {Assert-SkBackup $saved}
Copy-Item -LiteralPath (Join-Path (Split-Path (Get-SkImage 'qcbattmngr')) 'qcbattmngr8150.cat') -Destination $backupCat -Force
$null=Assert-SkBackup $saved
$after=@(Get-SkBaseline @(Get-SkDevices))
if(($before|ConvertTo-Json -Compress) -cne ($after|ConvertTo-Json -Compress)){throw 'Live baseline changed during packaging tests'}
$checks+='live driver hashes versions states unchanged'
[ordered]@{Passed=$true;Checks=$checks;CheckCount=$checks.Count;DriverInstallCalled=$false;CertificatesChanged=$false;RebootIssued=$false}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $qa 'result.json') -Encoding UTF8
Write-Host ('QA passed: '+$checks.Count+' checks. '+(Join-Path $qa 'result.json')) -ForegroundColor Green
