$ErrorActionPreference='Stop'
$vc='H:\Vlad\EWDK\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
$dir=Join-Path $PSScriptRoot 'build'
foreach($name in @('probe_get','probe_data')){
 & "$vc\bin\Hostarm64\arm64\cl.exe" /nologo /c /W4 /WX /O2 /Oi /GS /Gy- /Zl "$PSScriptRoot\$name.c" "/Fo:$dir\$name.obj" *> "$dir\$name.log"
 if($LASTEXITCODE){Get-Content "$dir\$name.log";throw 'COFF probe compile failed'}
}
# This DLL is laboratory DATA for byte comparison. It is never executed/loaded.
& "$vc\bin\Hostarm64\arm64\link.exe" /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:ARM64 /EXPORT:get_after /EXPORT:get_zero /EXPORT:get_before /OPT:NOICF,NOREF /DYNAMICBASE /NXCOMPAT /BASE:0x180000000 "/OUT:$dir\reloc-probe-NOT-LOADED.dll" "/MAP:$dir\reloc-probe.map" "$dir\probe_get.obj" "$dir\probe_data.obj" *> "$dir\probe-link.log"
if($LASTEXITCODE){Get-Content "$dir\probe-link.log";throw 'Microsoft reference link failed'}
& 'C:\Users\Xiaomi\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' "$PSScriptRoot\test_relocations.py"
if($LASTEXITCODE){throw 'Relocations differ from Microsoft LINK'}
