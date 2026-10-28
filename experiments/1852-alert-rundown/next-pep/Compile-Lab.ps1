$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$vc='H:\Vlad\EWDK\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$sdk='H:\Vlad\EWDK\Program Files\Windows Kits\10\Include\10.0.26100.0'
New-Item -ItemType Directory -Path "$root\build" -Force | Out-Null
$includes=@("/I$vc\include","/I$sdk\shared","/I$sdk\km","/I$sdk\ucrt")
$before=(Get-FileHash "$root\pep_lifetime.c").Hash
& "$vc\bin\Hostarm64\arm64\cl.exe" /nologo /c /kernel /W4 /WX /O2 /Oi /forceInterlockedFunctions- /GS /guard:cf /Zl /Gy- /external:anglebrackets /external:W0 /D_ARM64_ @includes "$root\pep_lifetime.c" "/Fo:$root\build\pep_lifetime.obj" *> "$root\build\compile.log"
if($LASTEXITCODE){Get-Content "$root\build\compile.log";throw 'Laboratory object compile failed'}
& "$vc\bin\Hostarm64\arm64\cl.exe" /nologo /c /kernel /W4 /WX /O2 /Oi /forceInterlockedFunctions- /GS /guard:cf /Zl /Gy- /analyze /analyze:external- /external:anglebrackets /external:W0 /D_ARM64_ @includes "$root\pep_lifetime.c" "/Fo:$root\build\pep_lifetime-analyze.obj" *> "$root\build\analyze.log"
if($LASTEXITCODE){Get-Content "$root\build\analyze.log";throw 'Laboratory analyzer failed'}
if((Get-FileHash "$root\pep_lifetime.c").Hash -cne $before){throw 'Source changed during compile'}
[ordered]@{status='LAB_OBJECT_ONLY_NOT_INSTALLABLE';sourceSHA256=$before;objectSHA256=(Get-FileHash "$root\build\pep_lifetime.obj").Hash;compilerSHA256=(Get-FileHash "$vc\bin\Hostarm64\arm64\cl.exe").Hash;analyzerPassed=$true;installed=$false;kernelExecuted=$false} | ConvertTo-Json | Set-Content "$root\build\identity.json" -Encoding utf8
Get-Content "$root\build\compile.log"
