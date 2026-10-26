param([Parameter(Mandatory=$true)][string]$PackageDirectory,[Parameter(Mandatory=$true)][string]$WorkDirectory)
$ErrorActionPreference='Stop'
$pkg=(Resolve-Path -LiteralPath $PackageDirectory).Path
$fixture=Join-Path $WorkDirectory ('package-tamper-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path "$fixture\package" -Force|Out-Null
Copy-Item -LiteralPath "$pkg\Install-PmicPackage.ps1","$pkg\package-manifest.json" -Destination $fixture
Get-ChildItem -LiteralPath "$pkg\package" -File|Copy-Item -Destination "$fixture\package"
[IO.File]::AppendAllText("$fixture\package\qcpmicext8150.sys",'test-fixture-corruption')
$tampered=$false;$activationGuard=$false;$liveRestoreGuard=$false
try{& "$fixture\Install-PmicPackage.ps1" -Mode Inspect;throw 'GUARD_FAILED'}catch{if($_.Exception.Message -notlike 'Package hash mismatch:*'){throw};$tampered=$true}
try{& "$pkg\Install-PmicPackage.ps1" -Mode Stage;throw 'GUARD_FAILED'}catch{if($_.Exception.Message -notlike 'Stage/Activate require -AcknowledgeExperimental*'){throw};$activationGuard=$true}
try{& "$pkg\Restore-ExperimentOffline.ps1" -WindowsRoot $env:SystemRoot -RecoveryDirectory $fixture;throw 'GUARD_FAILED'}catch{if($_.Exception.Message -notlike 'Refusing the running Windows*'){throw};$liveRestoreGuard=$true}
[ordered]@{TamperedPackageRejectedBeforeSystemProbe=$tampered;StageWithoutExperimentFlagRejected=$activationGuard;LiveWindowsRestoreRejected=$liveRestoreGuard;StagePerformed=$false;ActivationPerformed=$false;OfflineApplyTested=$false}|ConvertTo-Json
