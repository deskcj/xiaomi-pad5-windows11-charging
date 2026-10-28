[CmdletBinding()]
param([string]$Python='C:\Users\Xiaomi\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
foreach($folder in @('build','package','reproduce')){
 if(Test-Path -LiteralPath "$root\$folder"){throw 'Use a new source/reference folder without previous build, package or reproduce artifacts'}
}
New-Item -ItemType Directory -Path "$root\build" | Out-Null
& "$PSScriptRoot\Compile.ps1"
& "$PSScriptRoot\Analyze.ps1"
& $Python "$PSScriptRoot\link_backend.py" client
if($LASTEXITCODE){throw '1852 client PE bind failed'}
& $Python -c 'import sys;sys.path.insert(0,sys.argv[1]);from patch_policy_client import patch_client;patch_client()' $PSScriptRoot
if($LASTEXITCODE){throw '1851 client transport integration failed'}
foreach($test in @('test_client_pe.py','test_alert_lifecycle.py')){
 & $Python "$root\tests\$test"
 if($LASTEXITCODE){throw "Actual PE emulation failed: $test"}
}
& "$PSScriptRoot\Test-Unwind.ps1"
& "$PSScriptRoot\Rebuild-Compare.ps1" -Python $Python
& $Python "$PSScriptRoot\audit_1852.py"
if($LASTEXITCODE){throw '1852 final audit failed'}
'Unsigned1852 client reproduced and verified. No signing, driver installation, PnP reset or reboot.'
