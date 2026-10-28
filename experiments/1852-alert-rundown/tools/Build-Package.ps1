[CmdletBinding()]
param([string]$Python='C:\Users\Xiaomi\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
$ErrorActionPreference='Stop'
#1852 contains one TCPM client. Legacy1851 three-driver packaging is disabled.
& "$PSScriptRoot\Package-1852.ps1" -Python $Python
