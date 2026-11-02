param([switch]$CheckOnly,[switch]$Restore,[string]$BackupPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$result=[ordered]@{Build=1868;Started=(Get-Date).ToString('o');Success=$false;CheckOnly=[bool]$CheckOnly;Restore=[bool]$Restore;RebootIssued=$false;PrivateIOCTLUsed=$false;LiveDevicesReset=$false}
$run=$null
function Save-SkResult {if($run){$result|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $run 'result.json') -Encoding UTF8}}
try {
    if($CheckOnly -and $Restore){throw 'Use CheckOnly for the release package; Restore is a separate action.'}
    Assert-SkTablet
    $devices=@(Get-SkDevices);$result.Before=@(Get-SkBaseline $devices)
    $base=Join-Path $env:ProgramData 'SK-Charging';Assert-SkInternalPath $base
    Initialize-SkNative;$result.ActiveTestSigning=[SkCommunityNative]::TestSigning()
    if($Restore){
        if(!$BackupPath){
            if(Test-Path -LiteralPath (Join-Path $PSScriptRoot 'reserve.json')){$BackupPath=$PSScriptRoot}
            else{$BackupPath=(Get-Content -LiteralPath (Join-Path $base 'latest-backup.json') -Raw|ConvertFrom-Json).Path}
        }
        $manifest=Assert-SkBackup $BackupPath
        $targets=@($manifest.Packages|Where-Object Service -ne 'qcbattminiclass')
        $reference=@($manifest.Packages|Where-Object Service -eq 'qcbattminiclass')[0]
        $current=@($result.Before|Where-Object Service -eq 'qcbattminiclass')[0]
        if($current.SHA256 -ine @($reference.Files|Where-Object Name -eq ($reference.Name+'.sys'))[0].SHA256){throw 'Battery miniclass changed since this backup. Restore the complete base system manually.'}
        $same=$true
        foreach($p in $targets){
            $current=@($result.Before|Where-Object Service -eq $p.Service)[0]
            $desired=@($p.Files|Where-Object Name -eq ($p.Name+'.sys'))[0]
            if([version]$current.Version -ne [version]$p.Version -or $current.SHA256 -ine $desired.SHA256){$same=$false}
        }
        $result.RestoreFrom=$BackupPath
    }else{
        $manifest=Assert-SkPackage $PSScriptRoot
        $targets=@($manifest.Packages);$same=Assert-SkCompatibility $manifest $result.Before
    }
    $result.Target=@($targets|Select-Object Service,Version)
    if($CheckOnly){
        $result.Success=$true;$result.AlreadyInstalled=$same;$result.ReadyForInstallation=$result.ActiveTestSigning
        $result.Phase='Checked; no driver, certificate or boot-setting changes'
        Write-Host 'Check complete. No installation was performed.' -ForegroundColor Green
        if(!$result.ActiveTestSigning){Write-Warning 'Enable Test Mode using the nabu Windows guide before installation. This installer does not change boot settings.'}
        [pscustomobject]$result;return
    }
    if($same){$result.Success=$true;$result.Phase='Already selected; no changes';Write-Host 'These driver versions and hashes are already selected. Run Diagnose to check their state.' -ForegroundColor Green;[pscustomobject]$result;return}
    if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run Install.cmd and allow its Administrator prompt.'}
    if(!$result.ActiveTestSigning){throw 'Active Test Mode is required. Boot settings were not changed. Follow the linked nabu Windows guide, reboot, then run Install again.'}
    if($Restore -and @(Get-Disk|Where-Object {$_.BusType -eq 'USB'}).Count){throw 'Safely eject and disconnect USB storage before Restore; restoring can restart the USB/charging stack.'}
    $prefix=if($Restore){'Restore-'}else{'Install-'}
    $run=Join-Path $base ($prefix+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $run|Out-Null
    $backup=Join-Path $run 'Previous';Save-SkBackup $devices $backup
    foreach($name in @('Common.ps1','Install.ps1','Launch.ps1','Restore.cmd')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $backup}
    $result.Backup=$backup;$result.BackupVerified=$true;Save-SkResult
    $payload=Join-Path $run 'Candidate';New-Item -ItemType Directory -Path (Join-Path $payload 'packages') -Force|Out-Null
    if($Restore){
        # Restore uses only the four saved driver packages; miniclass is preserved.
        foreach($p in $targets){foreach($f in $p.Files){
            $from=Join-Path $BackupPath ('packages\'+$f.Name);$to=Join-Path $payload ('packages\'+$f.Name)
            Copy-Item -LiteralPath $from -Destination $to
            if((Get-FileHash -LiteralPath $to).Hash -ine $f.SHA256){throw 'Restore payload copy failed'}
            if($f.Name -match '\.(sys|cat)$' -and (Get-AuthenticodeSignature -LiteralPath $to).Status -ne 'Valid'){throw 'Saved package is not trusted on this Windows installation. No restore was attempted.'}
        }}
    }else{
        New-Item -ItemType Directory -Path (Join-Path $payload 'reference')|Out-Null
        foreach($name in @('manifest.json','development.cer')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $payload}
        foreach($p in (@($manifest.Packages)+@($manifest.Reference))){
            $kind=if($p.Service -eq 'qcbattminiclass'){'reference'}else{'packages'}
            foreach($f in $p.Files){Copy-Item -LiteralPath (Join-Path $PSScriptRoot ($kind+'\'+$f.Name)) -Destination (Join-Path $payload $kind)}
        }
        $null=Assert-SkPackage $payload
        foreach($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')){
            if(!(Test-Path -LiteralPath (Join-Path $store $manifest.DevelopmentSigner))){Import-Certificate -FilePath (Join-Path $payload 'development.cer') -CertStoreLocation $store|Out-Null}
        }
        $null=Assert-SkPackage $payload -RequireTrusted
    }
    # Keep a recovery pointer before calling Windows, even if staging fails.
    [ordered]@{Path=$backup;At=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $base 'latest-backup.json') -Encoding UTF8
    $result.Phase='Requesting Windows installation';Save-SkResult;[bool]$need=$false
    if($Restore){
        $result.LiveDevicesReset=$true;Save-SkResult
        foreach($p in $targets){
            [bool]$one=$false
            if(![SkCommunityNative]::Install([IntPtr]::Zero,(Join-Path $payload ('packages\'+$p.Name+'.inf')),2,[ref]$one)){throw "Restore failed: Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error()). Keep the verified backup and result.json."}
            $need=$need -or $one
        }
    }else{
        # DIIRFLAG_INSTALL_AS_SET: Windows defers activation of the set until reboot.
        if(![SkCommunityNative]::Install([IntPtr]::Zero,(Join-Path $payload 'packages'),0x40,[ref]$need)){throw "Deferred installation failed: Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error()). Keep the verified backup and result.json."}
        $result.After=@(Get-SkBaseline @(Get-SkDevices))
        if(($result.After|ConvertTo-Json -Compress) -cne ($result.Before|ConvertTo-Json -Compress)){throw 'Current stack changed unexpectedly during staging. Keep result.json and the backup.'}
    }
    $result.Success=$true;$result.WindowsRequestedReboot=$need;$result.NeedManualReboot=$true
    $result.Phase=if($Restore){'Restore requested; reboot manually'}else{'Driver set staged; reboot manually'};Save-SkResult
    Write-Host ('Saved previous drivers: '+$backup) -ForegroundColor Green
    Write-Host ('Recovery launcher: '+(Join-Path $backup 'Restore.cmd'))
    Write-Host 'Save your work, safely eject USB storage, and reboot manually. After reboot run Diagnose.cmd.' -ForegroundColor Yellow
    [pscustomobject]$result
}catch{
    $result.Error=$_.Exception.Message;$result.Phase='Failed';Save-SkResult
    Write-Host $result.Error -ForegroundColor Red
    if($run){Write-Host ('Installation record: '+$run)}
    throw
}
