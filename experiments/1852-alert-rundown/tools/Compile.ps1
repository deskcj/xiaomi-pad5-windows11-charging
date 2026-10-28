$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$vc='H:\Vlad\EWDK\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$wdk='H:\Vlad\EWDK\Program Files\Windows Kits\10\Include'
$includes=@("/I$vc\include","/I$wdk\10.0.26100.0\shared","/I$wdk\10.0.26100.0\km","/I$wdk\10.0.26100.0\ucrt","/I$wdk\wdf\kmdf\1.23")
$before=@(Get-ChildItem -LiteralPath "$root\src" -Filter '*.c' | ForEach-Object {[ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
foreach($name in @('client_repair')) {
 # Native ARMv8.0 LL/SC intrinsics: no dependency on user CRT outlined atomics.
 & "$vc\bin\Hostarm64\arm64\cl.exe" /nologo /c /kernel /W4 /WX /O2 /Oi /forceInterlockedFunctions- /GS /guard:cf /Gy- /Zl /external:anglebrackets /external:W0 /D_ARM64_ @includes "$root\src\$name.c" "/Fo:$root\build\$name.obj" *> "$root\build\$name-compile.log"
 if($LASTEXITCODE){Get-Content "$root\build\$name-compile.log";throw 'Native compile failed'}
 Get-Content "$root\build\$name-compile.log"
}
$after=@(Get-ChildItem -LiteralPath "$root\src" -Filter '*.c' | ForEach-Object {[ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
if(($before | ConvertTo-Json -Compress) -cne ($after | ConvertTo-Json -Compress)){throw 'Sources changed during compilation'}
[ordered]@{sources=$before;compiler=(Get-FileHash -LiteralPath "$vc\bin\Hostarm64\arm64\cl.exe").Hash;flags=@('/kernel','/W4','/WX','/O2','/Oi','/forceInterlockedFunctions-','/GS','/guard:cf');objects=@(Get-ChildItem -LiteralPath "$root\build" -Filter 'client_repair.obj' | ForEach-Object {[ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$root\build\compile-record.json" -Encoding utf8
