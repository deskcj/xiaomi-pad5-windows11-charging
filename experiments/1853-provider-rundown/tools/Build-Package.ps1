[CmdletBinding()]
param([string]$Python='C:\Users\Xiaomi\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
$ErrorActionPreference='Stop'
#1853 contains one TCPM client. Legacy1851 three-driver packaging is disabled.
& "$PSScriptRoot\Package-1853.ps1" -Python $Python
