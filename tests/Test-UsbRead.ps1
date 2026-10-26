param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)][string]$ReferencePath)
$ErrorActionPreference='Stop'
if(!('ChargingUsbRead' -as [type])){
Add-Type @'
using System;
using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public static class ChargingUsbRead {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(SafeFileHandle h,IntPtr b,uint size,out uint done,IntPtr overlapped);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr VirtualAlloc(IntPtr p,UIntPtr size,uint allocation,uint protect);
 [DllImport("kernel32.dll")] static extern bool VirtualFree(IntPtr p,UIntPtr size,uint mode);
 public static string Read(string path,string reference) {
  const int length=32768;
  byte[] expected=File.ReadAllBytes(reference);
  if(expected.Length<length)throw new Exception("Reference too short");
  IntPtr buffer=VirtualAlloc(IntPtr.Zero,new UIntPtr(length),0x3000,4);
  if(buffer==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  var clock=Stopwatch.StartNew();
  try {
   using(var file=CreateFileW(path,0x80000000,7,IntPtr.Zero,3,0x20000000|0x08000000,IntPtr.Zero)) {
    if(file.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
    uint done;
    if(!ReadFile(file,buffer,length,out done,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());
    if(done!=length)throw new Exception("Short USB read");
    byte[] actual=new byte[length];Marshal.Copy(buffer,actual,0,length);
    using(var sha=SHA256.Create()) {
     string a=BitConverter.ToString(sha.ComputeHash(actual)).Replace("-","");
     string b=BitConverter.ToString(sha.ComputeHash(expected,0,length)).Replace("-","");
     if(a!=b)throw new Exception("USB read differs from internal reference");
     return "{\"unbufferedReadBytes\":"+length+",\"matchesInternalReference\":true,\"writePerformed\":false,\"elapsedMs\":"+clock.ElapsedMilliseconds+",\"blockSHA256\":\""+a+"\"}";
    }
   }
  } finally {VirtualFree(buffer,UIntPtr.Zero,0x8000);}
 }
}
'@
}
[ChargingUsbRead]::Read($Path,$ReferencePath)
