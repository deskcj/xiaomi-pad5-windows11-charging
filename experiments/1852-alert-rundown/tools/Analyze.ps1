$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$vc='H:\Vlad\EWDK\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$wdk='H:\Vlad\EWDK\Program Files\Windows Kits\10\Include'
$includes=@("/I$vc\include","/I$wdk\10.0.26100.0\shared","/I$wdk\10.0.26100.0\km","/I$wdk\10.0.26100.0\ucrt","/I$wdk\wdf\kmdf\1.23")
$before=@(Get-ChildItem -LiteralPath "$root\src" -Filter '*.c' | ForEach-Object {[ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
foreach($name in @('client_repair')) {
 & "$vc\bin\Hostarm64\arm64\cl.exe" /nologo /c /kernel /W4 /WX /O2 /Oi /forceInterlockedFunctions- /GS /guard:cf /Gy- /Zl /analyze /analyze:external- /external:anglebrackets /external:W0 /D_ARM64_ @includes "$root\src\$name.c" "/Fo:$root\build\$name-analyze.obj" *> "$root\build\$name-analyze.log"
 if($LASTEXITCODE){Get-Content "$root\build\$name-analyze.log";throw 'Native analyzer failed'}
 Get-Content "$root\build\$name-analyze.log"
}
$after=@(Get-ChildItem -LiteralPath "$root\src" -Filter '*.c' | ForEach-Object {[ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
if(($before | ConvertTo-Json -Compress) -cne ($after | ConvertTo-Json -Compress)){throw 'Analyzer sources changed'}
[ordered]@{sources=$before;compiler=(Get-FileHash -LiteralPath "$vc\bin\Hostarm64\arm64\cl.exe").Hash;passed=$true;warningAsError=$true;kernel=$true;hardwareAccess=$false} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$root\build\analyze-record.json" -Encoding utf8
