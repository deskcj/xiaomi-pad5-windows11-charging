[CmdletBinding()]
param([string]$Python='C:\Users\Xiaomi\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe',[string]$DirectoryName='reproduce')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if($DirectoryName -notmatch '^reproduce[-a-z0-9]*$'){throw 'Rebuild directory must be an immediate reproduce* child'}
$repro=Join-Path $root $DirectoryName
if(Test-Path -LiteralPath $repro){throw 'Separate rebuild directory exists; do not mix old and new evidence'}
New-Item -ItemType Directory -Path "$repro\build" -Force | Out-Null
foreach($folder in @('src','reference','support','tools')){Copy-Item -LiteralPath "$root\$folder" -Destination "$repro\$folder" -Recurse}
& "$repro\tools\Compile.ps1"
if(!$?){throw 'Separate recompilation failed'}
& $Python "$repro\tools\link_backend.py" client *> "$root\build\rebuild-bind.log"
if($LASTEXITCODE){throw 'Separate native bind failed'}
$patchScript="import sys;sys.path.insert(0,sys.argv[1]);from patch_policy_client import patch_client;patch_client()"
& $Python -c $patchScript "$repro\tools"
if($LASTEXITCODE){throw 'Separate policy repair failed'}
& $Python "$PSScriptRoot\compare_rebuild.py" $DirectoryName
if($LASTEXITCODE){throw 'Separate rebuild identity check failed'}
