using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class SkCommunityBattery {
    [StructLayout(LayoutKind.Sequential)] private struct InterfaceData {
        public int Size; public Guid Guid; public int Flags; public IntPtr Reserved;
    }
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr SetupDiGetClassDevs(ref Guid guid, IntPtr enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError=true)]
    private static extern bool SetupDiEnumDeviceInterfaces(IntPtr set, IntPtr device, ref Guid guid, uint index, ref InterfaceData data);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr set, ref InterfaceData data, IntPtr detail, uint size, out uint required, IntPtr device);
    [DllImport("setupapi.dll")] private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool DeviceIoControl(IntPtr file, uint code, byte[] input, uint inputSize, byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr file);

    private static byte[] Query(IntPtr file, uint code, byte[] input, int size) {
        if(code!=0x294040 && code!=0x294044 && code!=0x29404c) throw new ArgumentException("Only documented battery queries are allowed");
        byte[] result=new byte[size]; uint returned;
        if(!DeviceIoControl(file,code,input,(uint)input.Length,result,(uint)size,out returned,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if(returned!=(uint)size) throw new InvalidOperationException("Unexpected battery response size");
        return result;
    }
    private static byte[] Words(params uint[] values) {
        byte[] bytes=new byte[values.Length*4];
        for(int i=0;i<values.Length;i++) Array.Copy(BitConverter.GetBytes(values[i]),0,bytes,i*4,4);
        return bytes;
    }
    public static object[] Read() {
        Guid guid=new Guid("72631e54-78a4-11d0-bcf7-00aa00b7b32a");
        IntPtr set=SetupDiGetClassDevs(ref guid,IntPtr.Zero,IntPtr.Zero,0x12);
        if(set==new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        List<object> rows=new List<object>();
        try {
            for(uint index=0;index<16;index++) {
                InterfaceData data=new InterfaceData(); data.Size=Marshal.SizeOf(typeof(InterfaceData));
                if(!SetupDiEnumDeviceInterfaces(set,IntPtr.Zero,ref guid,index,ref data)) {
                    int error=Marshal.GetLastWin32Error(); if(error==259) break; throw new Win32Exception(error);
                }
                uint required;
                SetupDiGetDeviceInterfaceDetail(set,ref data,IntPtr.Zero,0,out required,IntPtr.Zero);
                if(required<8 || required>32768) throw new InvalidOperationException("Invalid interface detail size");
                IntPtr detail=Marshal.AllocHGlobal((int)required);
                string path;
                try {
                    Marshal.WriteInt32(detail,IntPtr.Size==8 ? 8 : 6);
                    if(!SetupDiGetDeviceInterfaceDetail(set,ref data,detail,required,out required,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    path=Marshal.PtrToStringUni(IntPtr.Add(detail,4));
                } finally {Marshal.FreeHGlobal(detail);}
                IntPtr file=CreateFile(path,0x80000000,3,IntPtr.Zero,3,0,IntPtr.Zero);
                if(file==new IntPtr(-1)) {rows.Add(new {Interface=path,Error=new Win32Exception(Marshal.GetLastWin32Error()).Message});continue;}
                try {
                    uint tag=BitConverter.ToUInt32(Query(file,0x294040,Words(0),4),0);
                    if(tag==0) throw new InvalidOperationException("No valid battery tag");
                    byte[] info=Query(file,0x294044,Words(tag,0,0),36);
                    // QUERY_STATUS timeout zero requests the current state, without a wait for change.
                    byte[] status=Query(file,0x29404c,Words(tag,0,0,0,uint.MaxValue),16);
                    uint capability=BitConverter.ToUInt32(info,0), state=BitConverter.ToUInt32(status,0);
                    uint capacity=BitConverter.ToUInt32(status,4), voltage=BitConverter.ToUInt32(status,8);
                    int rate=BitConverter.ToInt32(status,12); bool relative=(capability&0x40000000)!=0;
                    rows.Add(new {Interface=path,PowerOnline=(state&1)!=0,Discharging=(state&2)!=0,Charging=(state&4)!=0,
                        RelativeUnits=relative,Capacity_mWh=relative || capacity==uint.MaxValue ? (long?)null : capacity,
                        FullChargedCapacity_mWh=relative ? (long?)null : BitConverter.ToUInt32(info,16),
                        Voltage_mV=voltage==uint.MaxValue ? (long?)null : voltage,
                        Rate_mW=relative || rate==int.MinValue ? (long?)null : rate,
                        DriverReportedTelemetry=true,IndependentPhysicalInputPowerMeasured=false});
                } catch(Exception error) {rows.Add(new {Interface=path,Error=error.Message});}
                finally {CloseHandle(file);}
            }
        } finally {SetupDiDestroyDeviceInfoList(set);}
        return rows.ToArray();
    }
}
