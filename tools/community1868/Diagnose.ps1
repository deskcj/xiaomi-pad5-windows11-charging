param([ValidateRange(0,600)][int]$Seconds=0)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$base=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'SK-Charging-Diagnostics'
Assert-SkInternalPath $base
$root=Join-Path $base ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $root -Force|Out-Null
$report=[ordered]@{Build=1868;At=(Get-Date).ToString('o');ReadOnlyHardware=$true;PrivatePMICIOCTLUsed=$false;DevicesReset=$false;DriverInstalled=$false;RebootIssued=$false;Errors=@()}
try {$report.Computer=Get-CimInstance Win32_ComputerSystem|Select-Object Manufacturer,Model,SystemType;$report.OS=Get-CimInstance Win32_OperatingSystem|Select-Object Caption,Version,BuildNumber,LastBootUpTime}catch{$report.Errors+=$_.Exception.Message}
try {$m=Assert-SkPackage $PSScriptRoot;$report.PackageVerified=$true;$report.Target=@((@($m.Packages)+@($m.Reference))|Select-Object Service,Version)}catch{$report.PackageVerified=$false;$report.Errors+=$_.Exception.Message}
try {
    $report.Drivers=@(Get-SkBaseline @(Get-SkDevices))
    if($m){$report.ReleaseMatches=@(foreach($p in (@($m.Packages)+@($m.Reference))){
        $installed=@($report.Drivers|Where-Object Service -eq $p.Service)[0]
        $expected=@($p.Files|Where-Object Name -eq ($p.Name+'.sys'))[0]
        [pscustomobject]@{Service=$p.Service;VersionMatches=([version]$installed.Version -eq [version]$p.Version);SHA256Matches=($installed.SHA256 -ieq $expected.SHA256);Running=($installed.State -eq 'Running');ProblemCode=$installed.Problem}
    })}
}catch{$report.Errors+=$_.Exception.Message}
try {Initialize-SkNative;$report.ActiveTestSigning=[SkCommunityNative]::TestSigning()}catch{$report.Errors+=$_.Exception.Message}
try {$report.Support=@(Get-SkSupportingHashes)}catch{$report.Errors+=$_.Exception.Message}
try {
    if(!('SkCommunityBattery' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'BatteryTelemetry.cs')}
    $report.Battery=@([SkCommunityBattery]::Read())
    if($Seconds){
        $clock=[Diagnostics.Stopwatch]::StartNew()
        while($clock.Elapsed.TotalSeconds -lt $Seconds){
            [pscustomobject]@{At=(Get-Date).ToString('o');Battery=@([SkCommunityBattery]::Read())}|ConvertTo-Json -Depth 5 -Compress|Add-Content -LiteralPath (Join-Path $root 'battery-samples.jsonl') -Encoding UTF8
            Start-Sleep -Seconds 5
        }
    }
}catch{$report.Errors+=$_.Exception.Message}
try {$report.USB=@(Get-PnpDevice -PresentOnly|Where-Object {$_.InstanceId -like 'USB*'}|ForEach-Object {[pscustomobject]@{Class=$_.Class;FriendlyName=$_.FriendlyName;Status=$_.Status;Problem=$_.Problem;InstanceId=$_.InstanceId}});$report.Disks=@(Get-CimInstance Win32_DiskDrive|Select-Object Model,InterfaceType,Size,Status);$report.Volumes=@(Get-CimInstance Win32_LogicalDisk|Select-Object DeviceID,VolumeName,FileSystem,Size)}catch{$report.Errors+=$_.Exception.Message}
try {$events=@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 1000 -ErrorAction Stop|Where-Object {$_.ProviderName -match 'PnP|USB|Kernel-Power|Disk|Ntfs|stor|WHEA|BugCheck'}|Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message);$events|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $root 'events.json') -Encoding UTF8}catch{$report.Errors+=$_.Exception.Message}
$report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $root 'diagnostic.json') -Encoding UTF8
$zip=$root+'.zip';Compress-Archive -LiteralPath $root -DestinationPath $zip
Write-Host ('Diagnostic archive: '+$zip) -ForegroundColor Green
if($report.ReleaseMatches){$report.ReleaseMatches|Format-Table -AutoSize|Out-Host}
Write-Host 'Battery values are driver telemetry. At 100%, unchanged capacity does not disprove charging.'
Write-Host 'Review the archive before sharing: USB identifiers can include serial numbers. No report is uploaded automatically.'
[pscustomobject]@{DiagnosticArchive=$zip;Report=(Join-Path $root 'diagnostic.json');Errors=$report.Errors;ReadOnlyHardware=$true}
