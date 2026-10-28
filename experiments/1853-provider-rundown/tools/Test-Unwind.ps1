param([string[]]$Kinds=@('client','alert','provider'))
$ErrorActionPreference='Stop'
foreach($kind in $Kinds){if($kind -notin @('client','alert','provider')){throw 'Unknown fixture kind'}}
$root=Split-Path -Parent $PSScriptRoot
& 'C:\Users\Xiaomi\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' "$PSScriptRoot\audit_leaf_unwind.py"
if($LASTEXITCODE){throw 'Omitted leaf proof failed'}
$vc='H:\Vlad\EWDK\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$sdk='H:\Vlad\EWDK\Program Files\Windows Kits\10'
$env:INCLUDE="$vc\include;$sdk\Include\10.0.26100.0\shared;$sdk\Include\10.0.26100.0\um;$sdk\Include\10.0.26100.0\ucrt"
$env:LIB="$vc\lib\arm64;$sdk\Lib\10.0.26100.0\um\arm64;$sdk\Lib\10.0.26100.0\ucrt\arm64"
& "$vc\bin\Hostarm64\arm64\cl.exe" /nologo /c /W4 /WX /O2 /GS /guard:cf /MT "$root\tests\native_unwind.c" "/Fo:$root\build\native_unwind.obj" *> "$root\build\unwind-compile.log"
if($LASTEXITCODE){Get-Content "$root\build\unwind-compile.log";throw 'Unwind compile failed'}
& "$vc\bin\Hostarm64\arm64\link.exe" /nologo /MACHINE:ARM64 /SUBSYSTEM:CONSOLE /guard:cf /DYNAMICBASE /NXCOMPAT "/OUT:$root\build\native_unwind.exe" "$root\build\native_unwind.obj" kernel32.lib *> "$root\build\unwind-link.log"
if($LASTEXITCODE){throw 'Unwind EXE link failed'}

$leaves=Get-Content -LiteralPath "$root\build\client-leaf-unwind-proof.json" -Raw | ConvertFrom-Json
$inputs=@('qcusbctcpm8150.sys')+@($Kinds | ForEach-Object {"$_-unwind-fixtures.bin"})
$before=@($inputs | ForEach-Object {[ordered]@{name=$_;sha256=(Get-FileHash -LiteralPath "$root\build\$_").Hash}})
$reports=@{}
foreach($kind in $Kinds){
 $completion=if($kind -in @('alert','provider')){'0x400ff0'}else{'0x400000'}
 & "$root\build\native_unwind.exe" "$root\build\qcusbctcpm8150.sys" "$root\build\$kind-unwind-fixtures.bin" $completion ([string]$leaves.leafLow) ([string]$leaves.leafHigh) *> "$root\build\$kind-native-unwind-report.txt"
 if($LASTEXITCODE){Get-Content "$root\build\$kind-native-unwind-report.txt" -TotalCount 25;throw "$kind native unwind failed"}
 Get-Content "$root\build\$kind-native-unwind-report.txt"
 $reports[$kind]=Get-Content "$root\build\$kind-native-unwind-report.txt" -Raw | ConvertFrom-Json
}
$after=@($inputs | ForEach-Object {[ordered]@{name=$_;sha256=(Get-FileHash -LiteralPath "$root\build\$_").Hash}})
if(($before | ConvertTo-Json -Compress) -cne ($after | ConvertTo-Json -Compress)){throw 'Unwind inputs changed during verification'}
[ordered]@{inputs=$before;testSourceSHA256=(Get-FileHash -LiteralPath "$root\tests\native_unwind.c").Hash;reports=$reports} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$root\build\unwind-identity.json" -Encoding utf8
