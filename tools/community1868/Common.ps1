$ErrorActionPreference='Stop'
$script:SkSpecs=@(
    @{Service='qcpmicext';Name='qcpmicext8150';HardwareId='ACPI\QCOM05E5'},
    @{Service='qcpmictcc';Name='qcpmictcc8150';HardwareId='ACPI\QCOM0582'},
    @{Service='qcusbctcpm';Name='qcusbctcpm8150';HardwareId='ACPI\QCOM057D'},
    @{Service='qcbattmngr';Name='qcbattmngr8150';HardwareId='ACPI\QCOM0531'},
    @{Service='qcbattminiclass';Name='qcbattminiclass8150';HardwareId='ACPI\QCOM052D'})
function Get-SkImage([string]$Service) {
    $p=[Environment]::ExpandEnvironmentVariables((Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Service").ImagePath)
    if($p.StartsWith('\SystemRoot\')){$p=$env:SystemRoot+$p.Substring(11)}
    if($p.StartsWith('\??\')){$p=$p.Substring(4)}
    if(![IO.Path]::IsPathRooted($p)){$p=Join-Path $env:SystemRoot $p}
    [IO.Path]::GetFullPath($p)
}
function Assert-SkInternalPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path);$systemRoot=[IO.Path]::GetPathRoot($env:SystemRoot)
    if([IO.Path]::GetPathRoot($full) -ine $systemRoot){throw 'Use the internal Windows drive for saved installation/diagnostic data.'}
    $disk=Get-Partition -DriveLetter $systemRoot.Substring(0,1) | Get-Disk
    if(@($disk).Count -ne 1 -or $disk.BusType -in @('USB','iSCSI','File Backed Virtual','Unknown')){throw 'Cannot confirm that the Windows drive is internal.'}
    $parent=$full
    while($parent){
        if(Test-Path -LiteralPath $parent){if((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Saved data path must not pass through a junction or symbolic link.'}}
        $parent=Split-Path -Parent $parent
    }
}
function Assert-SkTablet {
    if($env:PROCESSOR_ARCHITECTURE -ine 'ARM64'){throw 'Use native ARM64 Windows PowerShell on the tablet.'}
    $c=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem
    if($c.Manufacturer -ine 'Xiaomi' -or $c.Model -ine 'Pad 5'){throw 'This package supports Xiaomi Pad 5 (nabu) only.'}
    if([int]$os.BuildNumber -lt 22000 -or $os.ProductType -ne 1){throw 'Windows 11 ARM64 is required.'}
}
function Get-SkDevices {
    $present=@(Get-PnpDevice -PresentOnly)
    foreach($spec in $script:SkSpecs){
        $found=@($present|Where-Object {$_.InstanceId.StartsWith($spec.HardwareId+'\',[StringComparison]::OrdinalIgnoreCase)})
        $matches=@($found|Where-Object {@(Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_HardwareIds).Data -icontains $spec.HardwareId})
        if($matches.Count -ne 1){throw "Expected one $($spec.HardwareId) device; found $($matches.Count). Install the base nabu Windows drivers first."}
        $props=@{}
        Get-PnpDeviceProperty -InstanceId $matches[0].InstanceId -KeyName DEVPKEY_Device_DriverVersion,DEVPKEY_Device_DriverInfPath,DEVPKEY_Device_Service,DEVPKEY_Device_ProblemCode|ForEach-Object {$props[$_.KeyName]=$_.Data}
        if($props.DEVPKEY_Device_Service -ine $spec.Service){throw "Unexpected service for $($spec.HardwareId)"}
        [pscustomobject]@{Service=$spec.Service;Name=$spec.Name;HardwareId=$spec.HardwareId;InstanceId=$matches[0].InstanceId;Version=$props.DEVPKEY_Device_DriverVersion;PublishedInf=$props.DEVPKEY_Device_DriverInfPath;Problem=$props.DEVPKEY_Device_ProblemCode;Image=(Get-SkImage $spec.Service)}
    }
}
function Get-SkBaseline($Devices) {
    @($Devices|ForEach-Object {
        $s=Get-CimInstance Win32_SystemDriver -Filter "Name='$($_.Service)'"
        [pscustomobject]@{Service=$_.Service;Version=$_.Version;Problem=$_.Problem;Image=$_.Image;SHA256=(Get-FileHash -LiteralPath $_.Image).Hash;State=$s.State}
    })
}
function Get-SkSupportingHashes {
    foreach($service in @('qcpep','qcspmi','UrsSynopsys','USBXHCI')){
        try{$image=Get-SkImage $service;[pscustomobject]@{Service=$service;SHA256=(Get-FileHash -LiteralPath $image).Hash}}
        catch{[pscustomobject]@{Service=$service;Error=$_.Exception.Message}}
    }
}
function Initialize-SkNative {
    if('SkCommunityNative' -as [type]){return}
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class SkCommunityNative {
 [StructLayout(LayoutKind.Sequential)] private struct CI {public uint Length; public uint Options;}
 [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int cls,ref CI info,uint length,out uint returned);
 public static bool TestSigning() {CI info=new CI(); info.Length=8;uint returned;
  int status=NtQuerySystemInformation(103,ref info,8,out returned);
  if(status<0 || returned<8) throw new InvalidOperationException("Cannot read active Code Integrity policy");
  return (info.Options & 2)!=0;
 }
 [DllImport("newdev.dll",EntryPoint="DiInstallDriverW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]
 [return:MarshalAs(UnmanagedType.Bool)]
 public static extern bool Install(IntPtr window,string path,uint flags,[MarshalAs(UnmanagedType.Bool)]out bool reboot);
}
'@
}
function Assert-SkPackage([string]$Root,[switch]$RequireTrusted) {
    $m=Get-Content -LiteralPath (Join-Path $Root 'manifest.json') -Raw|ConvertFrom-Json
    if($m.Schema -ne 2 -or $m.Build -ne 1868 -or $m.Model -ne 'Xiaomi Pad 5' -or @($m.Packages).Count -ne 4 -or @($m.Reference).Count -ne 1){throw 'Invalid release manifest'}
    if(@($m.Packages|Where-Object Service -eq 'qcbattminiclass').Count -or $m.Reference[0].Service -cne 'qcbattminiclass'){throw 'Miniclass must be reference only'}
    $signer='F38EDD5C105095C8342556158CE66253F045965D';$certHash='1C655BB59BEF778420AB5E47BAE06A6FB8FF9178AA5881D99FCFC32904642D3B'
    if($m.DevelopmentSigner -ine $signer -or $m.CertificateSHA256 -ine $certHash){throw 'Unexpected development certificate'}
    $certPath=Join-Path $Root 'development.cer';$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 $certPath
    if($cert.HasPrivateKey -or $cert.Thumbprint -ine $signer -or (Get-FileHash -LiteralPath $certPath).Hash -ine $certHash){throw 'Invalid public certificate'}
    $seen=@{};$paths=@()
    foreach($p in (@($m.Packages)+@($m.Reference))){
        $spec=@($script:SkSpecs|Where-Object Service -eq $p.Service)
        if($spec.Count -ne 1 -or $seen.ContainsKey($p.Service) -or $p.Name -cne $spec[0].Name -or $p.HardwareId -cne $spec[0].HardwareId){throw 'Unexpected/duplicate driver specification'}
        $seen[$p.Service]=$true;$kind=if($p.Service -eq 'qcbattminiclass'){'reference'}else{'packages'}
        if($kind -eq 'packages' -and $p.Signer -ine $signer){throw 'Unexpected package signer'}
        if(@($p.Files).Count -ne 3){throw 'Incomplete driver package'}
        $names=@($p.Files|ForEach-Object {$_.Name})
        if(@(Compare-Object ($names|Sort-Object) (@('sys','inf','cat')|ForEach-Object {$p.Name+'.'+$_}|Sort-Object)).Count){throw 'Unexpected driver filenames'}
        foreach($f in $p.Files){
            $relative=$kind+'\'+$f.Name;$path=Join-Path $Root $relative;$paths+=$relative;$item=Get-Item -LiteralPath $path -Force
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Payload cannot contain symbolic links'}
            if((Get-FileHash -LiteralPath $path).Hash -ine $f.SHA256 -or $item.Length -ne $f.Bytes){throw "SHA256/size mismatch: $($f.Name)"}
            if($kind -eq 'packages' -and $f.Name -match '\.(sys|cat)$'){
                $s=Get-AuthenticodeSignature -LiteralPath $path
                # Missing trust is allowed before importing the public certificate.
                # Afterwards Windows must report Valid; broken/missing signatures fail.
                if(!$s.SignerCertificate -or $s.SignerCertificate.Thumbprint -ine $signer -or $s.Status -notin @('Valid','NotTrusted','UnknownError') -or ($RequireTrusted -and $s.Status -ne 'Valid')){throw "Invalid/untrusted signature: $($f.Name), $($s.Status)"}
            }
        }
        $inf=[IO.File]::ReadAllText((Join-Path $Root ($kind+'\'+$p.Name+'.inf')))
        if($inf -notmatch ('(?im)^DriverVer\s*=\s*[^,\r\n]+,\s*'+[regex]::Escape($p.Version)+'\s*$') -or $inf -notmatch 'NTarm64' -or $inf -notmatch [regex]::Escape($p.HardwareId)){throw 'INF version/hardware mismatch'}
    }
    $actual=@(foreach($kind in @('packages','reference')){Get-ChildItem -LiteralPath (Join-Path $Root $kind) -Recurse -File|ForEach-Object {$_.FullName.Substring([IO.Path]::GetFullPath($Root).TrimEnd('\').Length+1)}})
    if($actual.Count -ne 15 -or @(Compare-Object ($actual|Sort-Object) ($paths|Sort-Object)).Count){throw 'Unexpected payload file'}
    $m
}
function Assert-SkCompatibility($Manifest,$Before) {
    $ref=$Manifest.Reference[0];$current=@($Before|Where-Object Service -eq $ref.Service)[0];$desired=@($ref.Files|Where-Object Name -eq ($ref.Name+'.sys'))[0]
    if(!$current -or [version]$current.Version -ne [version]$ref.Version -or $current.SHA256 -ine $desired.SHA256){throw 'Unsupported battery miniclass. Restore/install the compatible base nabu driver set first; this pack does not replace it.'}
    $same=$true
    foreach($p in $Manifest.Packages){
        $current=@($Before|Where-Object Service -eq $p.Service)[0]
        if(!$current){throw 'Required base driver is missing'}
        if([version]$current.Version -gt [version]$p.Version){throw "Newer $($p.Service) is installed. Automatic downgrade refused."}
        $desired=@($p.Files|Where-Object Name -eq ($p.Name+'.sys'))[0]
        if([version]$current.Version -ne [version]$p.Version -or $current.SHA256 -ine $desired.SHA256){$same=$false}
    }
    $same
}
function Save-SkBackup($Devices,[string]$Destination) {
    Assert-SkInternalPath $Destination;New-Item -ItemType Directory -Path (Join-Path $Destination 'packages') -Force|Out-Null;$rows=@()
    foreach($d in $Devices){
        $folder=Split-Path -Parent $d.Image
        if($folder -notlike ((Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository')+'\*')){throw 'Cannot find complete installed DriverStore package for backup'}
        $row=[ordered]@{Service=$d.Service;Name=$d.Name;HardwareId=$d.HardwareId;Version=$d.Version;Files=@()}
        foreach($ext in @('inf','sys','cat')){
            $name=$d.Name+'.'+$ext;$from=Join-Path $folder $name;$to=Join-Path $Destination ('packages\'+$name);$hash=(Get-FileHash -LiteralPath $from).Hash
            Copy-Item -LiteralPath $from -Destination $to
            if((Get-FileHash -LiteralPath $to).Hash -ine $hash){throw 'Backup copy verification failed'}
            $row.Files+=@{Name=$name;SHA256=$hash;Bytes=(Get-Item -LiteralPath $to).Length}
        }
        $rows+=[pscustomobject]$row
    }
    [ordered]@{Schema=1;Model='Xiaomi Pad 5';SavedAt=(Get-Date).ToString('o');Packages=$rows}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $Destination 'reserve.json') -Encoding UTF8
    $null=Assert-SkBackup $Destination
}
function Assert-SkBackup([string]$Root) {
    Assert-SkInternalPath $Root;$m=Get-Content -LiteralPath (Join-Path $Root 'reserve.json') -Raw|ConvertFrom-Json
    if($m.Schema -ne 1 -or $m.Model -ne 'Xiaomi Pad 5' -or @($m.Packages).Count -ne 5){throw 'Invalid backup manifest'}
    $seen=@{}
    foreach($p in $m.Packages){
        $spec=@($script:SkSpecs|Where-Object Service -eq $p.Service)
        if($spec.Count -ne 1 -or $seen.ContainsKey($p.Service) -or $spec[0].Name -cne $p.Name -or $spec[0].HardwareId -cne $p.HardwareId){throw 'Unexpected backup package'}
        $seen[$p.Service]=$true;$expected=@('inf','sys','cat')|ForEach-Object {$p.Name+'.'+$_}
        if(@($p.Files).Count -ne 3 -or @(Compare-Object ($expected|Sort-Object) (@($p.Files.Name)|Sort-Object)).Count){throw 'Incomplete backup'}
        foreach($f in $p.Files){
            $path=Join-Path $Root ('packages\'+$f.Name)
            if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Backup cannot contain links'}
            if((Get-FileHash -LiteralPath $path).Hash -ine $f.SHA256 -or (Get-Item -LiteralPath $path).Length -ne $f.Bytes){throw 'Backup hash/size mismatch'}
        }
    }
    $m
}
