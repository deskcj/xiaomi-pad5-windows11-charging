param([ValidateSet('Install','Diagnose','Restore')][string]$Action='Install')
$ErrorActionPreference='Stop'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($Action -ne 'Diagnose' -and !$admin){
    # This console is interactive: the person launching Install needs to see its result.
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        $process=Start-Process -FilePath $shell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-Action',$Action) -Verb RunAs -WindowStyle Normal -Wait -PassThru
        exit $process.ExitCode
    }catch{
        Write-Host ('Administrator launch failed or was cancelled: '+$_.Exception.Message) -ForegroundColor Red
        $null=Read-Host 'Press Enter to close'
        exit 1
    }
}
try {
    if($Action -eq 'Diagnose'){& (Join-Path $PSScriptRoot 'Diagnose.ps1')|Format-List}
    elseif($Action -eq 'Restore'){& (Join-Path $PSScriptRoot 'Install.ps1') -Restore|Format-List}
    else {& (Join-Path $PSScriptRoot 'Install.ps1')|Format-List}
    $code=0
}catch{Write-Host $_.Exception.Message -ForegroundColor Red;$code=1}
$null=Read-Host 'Press Enter to close'
exit $code
