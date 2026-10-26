param([switch]$Capture,[switch]$Validate,[Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
if($Capture -and $Validate){throw 'Capture and Validate must be separate'}
$output=[IO.Path]::GetFullPath($OutputPath)
if([IO.Path]::GetPathRoot($output) -ine [IO.Path]::GetPathRoot($env:SystemRoot)){throw 'Internal output required'}
$registers=[ordered]@{TYPEC_STATE=0x1509;TYPEC_MISC=0x150b;TYPEC_MODE=0x1544;TYPEC_SINK_STATUS=0x1506;TYPEC_SOURCE_STATUS=0x1508;OTG_COMMAND=0x1140;OTG_STATUS=0x110d;OTG_CONFIG=0x1153;APSD_STATUS=0x1307;APSD_RESULT=0x1308;POWER_PATH_STATUS=0x130b;USBIN_INT_RT=0x1310;USBIN_OPTIONS=0x1358;USBIN_ICL=0x1370}
if($Capture -or $Validate){
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class PmicDiagnosticRead20261026 : IDisposable {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr sa,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint code,byte[] input,uint inSize,byte[] output,uint outSize,out uint returned,IntPtr overlapped);
 SafeFileHandle handle;
 public PmicDiagnosticRead20261026(string path) {
  handle=CreateFileW(path,0x80000000,7,IntPtr.Zero,3,0x80,IntPtr.Zero);
  if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
 }
 public static byte[] Header(ushort register) {
  switch(register){
   case 0x110d:case 0x1140:case 0x1153:case 0x1307:case 0x1308:case 0x130b:case 0x1310:
   case 0x1358:case 0x1370:case 0x1506:case 0x1508:case 0x1509:case 0x150b:case 0x1544:break;
   default:throw new ArgumentOutOfRangeException("register");
  }
  byte[] b=new byte[16];Buffer.BlockCopy(BitConverter.GetBytes(1u),0,b,0,4);
  Buffer.BlockCopy(BitConverter.GetBytes(0x51u),0,b,4,4);
  Buffer.BlockCopy(BitConverter.GetBytes(0x4e420000u|register),0,b,8,4);
  Buffer.BlockCopy(BitConverter.GetBytes(1u),0,b,12,4);return b;
 }
 public byte Read(ushort register) {
  byte[] input=Header(register),output=new byte[4];uint returned;
  if(!DeviceIoControl(handle,0x802a0fb4,input,16,output,4,out returned,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());
  if(returned!=4)throw new Exception("Unexpected diagnostic response size");
  uint packet=BitConverter.ToUInt32(output,0);
  if((packet&0xffff0000u)==0x4e430000u)throw new Exception("PMIC read error: 0x"+(packet&0xffffu).ToString("X"));
  if((packet&0xffffff00u)!=0x4e420000u)throw new Exception("Diagnostic protocol absent or invalid response; no register value accepted");
  return (byte)packet;
 }
 public void Dispose(){if(handle!=null)handle.Dispose();}
}
'@
}
if($Validate){
 $vectors=@()
 foreach($name in $registers.Keys){
  $bytes=[PmicDiagnosticRead20261026]::Header([uint16]$registers[$name])
  if($bytes.Length -ne 16 -or [BitConverter]::ToUInt32($bytes,0) -ne 1 -or [BitConverter]::ToUInt32($bytes,4) -ne 0x51 -or [BitConverter]::ToUInt32($bytes,8) -ne (0x4e420000 -bor $registers[$name]) -or [BitConverter]::ToUInt32($bytes,12) -ne 1){throw 'Invalid protocol header'}
  $vectors+=@{Register=('0x{0:X4}' -f $registers[$name]);Hex=([BitConverter]::ToString($bytes)).Replace('-','')}
 }
 $rejected=$false;try{[PmicDiagnosticRead20261026]::Header(0x1540)|Out-Null}catch{$rejected=$true}
 if(!$rejected){throw 'Non-whitelisted register accepted'}
 [ordered]@{Mode='Validate';PassedHeaderVectors=$vectors.Count;UnlistedRegisterRejected=$true;DeviceOpened=$false;RegisterWritesImplemented=$false;Vectors=$vectors}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $output -Encoding utf8
 return
}
$svc=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\qcpmicext'
$image=$svc.ImagePath
if($image.StartsWith('System32\',[StringComparison]::OrdinalIgnoreCase)){$image=Join-Path $env:SystemRoot $image}
if((Get-FileHash -LiteralPath $image).Hash -ne '314BBF81ED5263388EFCD8316E0CC8C030894B98B7348089C35D6174E55685B3'){throw 'PMIC is not the audited r4 diagnostic build; no device opened'}
$result=[ordered]@{At=(Get-Date -Format o);PMICVersion='1.0.1847.0';ExpectedImageSHA256=(Get-FileHash -LiteralPath $image).Hash;Mode='Inspect';DeviceOpened=$false;CaptureCompleted=$false;ReadOnly=$true;RegisterWritesImplemented=$false;Values=[ordered]@{}}
if($Capture){
 $client=$null
 try{
  $guid='{cf54664c-bf1e-4533-819a-cec9588a2533}'
  $keys=@(Get-ChildItem -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\'+$guid)|Where-Object PSChildName -Like '*#QCOM05E5#*')
  if($keys.Count -ne 1){throw 'Expected exactly one PMIC interface'}
  $encoded=$keys[0].PSChildName
  if(!$encoded.StartsWith('##?#ACPI#QCOM05E5#',[StringComparison]::OrdinalIgnoreCase) -or !$encoded.EndsWith('#'+$guid,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected interface key'}
  $client=[PmicDiagnosticRead20261026]::new('\\?\'+$encoded.Substring(4));$result.DeviceOpened=$true;$result.Mode='Capture'
  foreach($name in $registers.Keys){$value=$client.Read([uint16]$registers[$name]);$result.Values[$name]=[ordered]@{Address=('0x{0:X4}' -f $registers[$name]);Value=[int]$value;Hex=('0x{0:X2}' -f $value)}}
  $misc=$result.Values.TYPEC_MISC.Value;$mode=$result.Values.TYPEC_MODE.Value;$state=$result.Values.TYPEC_STATE.Value
  $result.Decoded=[ordered]@{CCAttached=([bool]($misc -band 1));PowerRole=if(!($misc -band 1)){'UNATTACHED'}elseif($misc -band 0x40){'SOURCE'}else{'SINK'};AttachStateBit5=([bool]($state -band 0x20));OTGCommandEnabled=([bool]($result.Values.OTG_COMMAND.Value -band 1));TypeCDisabled=([bool]($mode -band 1));SinkOnly=([bool]($mode -band 2));SourceOnly=([bool]($mode -band 4));TrySink=([bool]($mode -band 0x10));TrySource=([bool]($mode -band 0x08));InheritedFix20WouldForceSource=($state -ge 5 -and $state -le 34)}
  $result.CaptureCompleted=$true;$result.Finished=Get-Date -Format o
 }catch{$result.Error=$_.Exception.Message;$result.CaptureCompleted=$false}
 finally{if($client){$client.Dispose()}}
}
$result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $output -Encoding utf8
$result|ConvertTo-Json -Depth 6
