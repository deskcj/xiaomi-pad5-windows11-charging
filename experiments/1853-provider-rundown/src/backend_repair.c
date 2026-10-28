#include <ntddk.h>
#include <wdf.h>

/* Bound by the hash-pinned PE linker to THIS driver's WDF globals, never
 * handles belonging to another driver. Original discovery/PD remain in place. */
extern PVOID *SkWdfTable;
extern PWDF_DRIVER_GLOBALS SkWdfGlobals;
extern const WDF_OBJECT_CONTEXT_TYPE_INFO *SkContextType;
extern WDFIOTARGET SkAdcTarget;
extern WDFIOTARGET SkPmicTarget;
extern volatile UCHAR SkPmicReady;
extern volatile UCHAR SkAdcReady, SkDriverActive;
extern HANDLE SkThreadHandle;
NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(HANDLE,BOOLEAN,PLARGE_INTEGER);
extern NTSTATUS OriginalSetPower(PVOID context,UCHAR on);
extern NTSTATUS OriginalCommand99(PVOID context);
extern NTSTATUS OriginalDispatch(PVOID context);
extern NTSTATUS OriginalTransmit(PVOID),OriginalRoleControl(PVOID),OriginalPowerControl(PVOID);
extern NTSTATUS OriginalAlertMask(PVOID),OriginalReceiveDetect(PVOID),OriginalMessageHeader(PVOID);
extern NTSTATUS OriginalPendingAck(PVOID,ULONG);
extern NTSTATUS OriginalWriteVirtual(PVOID,ULONG,UCHAR,PVOID);
extern NTSTATUS OriginalResetBackend(PVOID);
NTSTATUS RepairStop(PVOID c);
extern ULONG_PTR OriginalWppInitialize(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,
                                      ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);

static KEVENT PowerGate;
static KEVENT StopGate;
static volatile LONG GateReady;
static ULONG Epoch,PendingEpoch,Attempts;
static UCHAR Pending,Desired;
static PVOID PendingContext;
static PKTHREAD ApplyingThread;
static ULONG ApplyingEpoch;
static NTSTATUS LastFault;
static PKTHREAD volatile WorkerThread;
static PVOID StoppedContext;
static UCHAR StopSettled;

static NTSTATUS gate(void)
{
    PVOID objects[1]={&PowerGate};
    if(!GateReady || KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_DEVICE_NOT_READY;
    return KeWaitForMultipleObjects(1,objects,WaitAny,Executive,KernelMode,FALSE,NULL,NULL);
}
static VOID ungate(void) { KeSetEvent(&PowerGate,IO_NO_INCREMENT,FALSE); }
static VOID lock_context(PVOID c)
{
    ((PFN_WDFSPINLOCKACQUIRE)SkWdfTable[0x9e0/8])
        (SkWdfGlobals,*(WDFSPINLOCK *)((PUCHAR)c+0x218));
}
static VOID unlock_context(PVOID c)
{
    ((PFN_WDFSPINLOCKRELEASE)SkWdfTable[0x9e8/8])
        (SkWdfGlobals,*(WDFSPINLOCK *)((PUCHAR)c+0x218));
}
static VOID wake(PVOID c)
{
    if(SkDriverActive==1)KeSetEvent((PKEVENT)((PUCHAR)c+0x350),IO_NO_INCREMENT,FALSE);
}

ULONG_PTR RepairInitialize(ULONG_PTR a,ULONG_PTR b,ULONG_PTR c,ULONG_PTR d,
                          ULONG_PTR e,ULONG_PTR f,ULONG_PTR g,ULONG_PTR h)
{
    KeInitializeEvent(&PowerGate,SynchronizationEvent,TRUE);
    KeInitializeEvent(&StopGate,SynchronizationEvent,TRUE);
    /* DriverEntry finishes this initialization before device callbacks exist. */
    GateReady=1;
    return OriginalWppInitialize(a,b,c,d,e,f,g,h);
}

static NTSTATUS exchange(WDFIOTARGET target,ULONG code,PVOID in,ULONG in_size,
                         PVOID out,ULONG out_size)
{
    WDF_MEMORY_DESCRIPTOR input,output;
    WDF_REQUEST_SEND_OPTIONS options;
    ULONG_PTR returned=0;
    NTSTATUS status;
    if(!target || KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_DEVICE_NOT_READY;
    WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&input,in,in_size);
    WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&output,out,out_size);
    WDF_REQUEST_SEND_OPTIONS_INIT(&options,WDF_REQUEST_SEND_OPTION_TIMEOUT);
    options.Timeout=-10000000LL;
    status=((PFN_WDFIOTARGETSENDIOCTLSYNCHRONOUSLY)SkWdfTable[0x5d0/8])
        (SkWdfGlobals,target,NULL,code,&input,&output,&options,&returned);
    if(status!=STATUS_SUCCESS)return NT_SUCCESS(status)?STATUS_IO_DEVICE_ERROR:status;
    if(returned!=out_size || *(ULONG *)out!=0)return STATUS_IO_DEVICE_ERROR;
    return STATUS_SUCCESS;
}

/* ABI of original A578: no cache; no output publication until both operations
 * succeed, including byte count and vendor result. */
NTSTATUS RepairReadAdc(WDFIOTARGET target,PULONG microvolts)
{
    UCHAR name[7]={'U','S','B','_','I','N',0};
    ULONG channel_result[2]={MAXULONG,MAXULONG},sample[5]={MAXULONG,0,0,0,0};
    NTSTATUS status;
    if(!microvolts)return STATUS_INVALID_PARAMETER;
    status=exchange(target,0x8adc2000,name,sizeof(name),channel_result,sizeof(channel_result));
    if(status!=STATUS_SUCCESS)return status;
    if((channel_result[1]>>16)>1)return STATUS_DATA_ERROR;
    status=exchange(target,0x8adc2004,&channel_result[1],4,sample,sizeof(sample));
    if(status==STATUS_SUCCESS)*microvolts=sample[3];
    return status;
}

/* All stock AF20 callers bind here. The gate covers PMIC I/O only; class
 * callbacks in OriginalSetPower run after this function releases it. */
NTSTATUS RepairPowerIo(WDFIOTARGET target,UCHAR mode,UCHAR on)
{
    ULONG value=mode,result=MAXULONG;
    NTSTATUS status=gate();
    if(status!=STATUS_SUCCESS)return status;
    if(!SkPmicReady) {ungate();return STATUS_DEVICE_NOT_READY;}
    if(on) {
        if(!SkDriverActive || !Pending || !Desired ||
           ApplyingThread!=KeGetCurrentThread() || ApplyingEpoch!=Epoch) {
            ungate();return STATUS_CANCELLED;
        }
    } else {
        if(!(Pending && !Desired && ApplyingThread==KeGetCurrentThread() && ApplyingEpoch==Epoch)) {
            ++Epoch;Pending=0;
        }
    }
    status=exchange(target,0x801c0fa8,&value,4,&result,4);
    if(status==STATUS_SUCCESS) {
        value=on;result=MAXULONG;
        status=exchange(target,0x801c0fac,&value,4,&result,4);
    }
    ungate();return status;
}

NTSTATUS RepairCommand(PVOID context)
{
    UCHAR command;
    NTSTATUS status;
    if(!context || KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
    lock_context(context);command=*((PUCHAR)context+0x33);unlock_context(context);
    if(command==0x77 || command==0x66 || command==0x44 || command==0x55) {
        status=gate();if(status!=STATUS_SUCCESS)return status;
        if(!SkDriverActive || !SkPmicReady || (command==0x77 && !SkAdcReady)) {
            ungate();return STATUS_DEVICE_NOT_READY;
        }
        if(Pending && PendingContext!=context) {ungate();return STATUS_DEVICE_BUSY;}
        PendingEpoch=++Epoch;Attempts=0;Desired=(command==0x77);
        PendingContext=context;Pending=1;
        ungate();
    } else if(command==0x99) {
        status=gate();if(status!=STATUS_SUCCESS)return status;
        ++Epoch;Pending=0;ungate();
        status=OriginalCommand99(context);if(status!=STATUS_SUCCESS)return status;
    }
    lock_context(context);
    if(*((PUCHAR)context+0x33)==command)*((PUCHAR)context+0x33)=0;
    unlock_context(context);
    wake(context);
    return STATUS_SUCCESS;
}

/* The old 3550 discarded every handler failure by returning F988's success.
 * Keep failed bits pending and return the first failure. Source commands now
 * report acceptance of the worker intent; ADC returns an actual valid sample.
 * Existing PHY/PD handlers retain their original nonnegative acceptance ABI. */
NTSTATUS RepairExecutePending(PVOID c,ULONG mask)
{
    ULONG pending,accepted=0,voltage=0;
    USHORT encoded;
    NTSTATUS first=STATUS_SUCCESS,s,ack;
    if(!c)return STATUS_INVALID_PARAMETER;
    lock_context(c);pending=*(ULONG *)((PUCHAR)c+0x210)&mask;unlock_context(c);
#define EXECUTE(bit,call) do { if(pending&(bit)) {s=(call); if(NT_SUCCESS(s))accepted|=(bit); else if(first==STATUS_SUCCESS)first=s;} } while(0)
    EXECUTE(0x80,OriginalTransmit(c));
    EXECUTE(0x40,OriginalRoleControl(c));
    EXECUTE(0x20,OriginalPowerControl(c));
    EXECUTE(0x08,OriginalAlertMask(c));
    EXECUTE(0x02,OriginalReceiveDetect(c));
    EXECUTE(0x01,OriginalMessageHeader(c));
    if(pending&4)accepted|=4; /* already copied software register */
    EXECUTE(0x10,RepairCommand(c));
    if(pending&0x100) {
        s=SkAdcReady?RepairReadAdc(SkAdcTarget,&voltage):STATUS_DEVICE_NOT_READY;
        if(s==STATUS_SUCCESS) {
            encoded=(USHORT)((voltage/25000u)&0x3ff);
            s=OriginalWriteVirtual(c,0x70,2,&encoded);
        }
        if(s==STATUS_SUCCESS)accepted|=0x100;
        else if(first==STATUS_SUCCESS)first=NT_SUCCESS(s)?STATUS_IO_DEVICE_ERROR:s;
    }
    ack=OriginalPendingAck(c,accepted);
    return first==STATUS_SUCCESS?ack:first;
#undef EXECUTE
}

/* Source timer has no power I/O and no class callback. One-shot wake only. */
VOID RepairSourceTimer(WDFTIMER timer)
{
    WDFOBJECT parent;
    PVOID context;
    parent=((PFN_WDFTIMERGETPARENTOBJECT)SkWdfTable[0xa08/8])(SkWdfGlobals,timer);
    context=((PFN_WDFOBJECTGETTYPEDCONTEXTWORKER)SkWdfTable[0x650/8])
        (SkWdfGlobals,parent,SkContextType);
    if(context)wake(context);
}

static VOID retry(PVOID c)
{
    ((PFN_WDFTIMERSTART)SkWdfTable[0x9f8/8])
        (SkWdfGlobals,*(WDFTIMER *)((PUCHAR)c+0x230),-1000000LL);
}

static VOID power_fault(PVOID c,NTSTATUS reason)
{
    NTSTATUS off=OriginalSetPower(c,0);
    LastFault=reason;
    /* ForceOffVbus is published only after the PMIC reports an executed OFF,
     * not on the basis of the failed ADC value. Actual electrical discharge
     * remains a hardware-test question. */
    if(off==STATUS_SUCCESS) {
        lock_context(c);
        *((PUCHAR)c+0x2f)|=0x10;
        *(USHORT *)((PUCHAR)c+0x20)|=0x200;
        unlock_context(c);
        KeSetEvent((PKEVENT)((PUCHAR)c+0x338),IO_NO_INCREMENT,FALSE);
    }
}

static NTSTATUS process_power(PVOID c)
{
    ULONG epoch,voltage=MAXULONG;
    UCHAR on;
    NTSTATUS status=gate();
    if(status!=STATUS_SUCCESS)return status;
    if(!Pending || PendingContext!=c || !SkDriverActive) {ungate();return STATUS_SUCCESS;}
    epoch=PendingEpoch;on=Desired;
    ungate();
    status=STATUS_SUCCESS;
    if(on)status=SkAdcReady?RepairReadAdc(SkAdcTarget,&voltage):STATUS_DEVICE_NOT_READY;
    if(gate()!=STATUS_SUCCESS)return STATUS_DEVICE_NOT_READY;
    if(!SkDriverActive || !Pending || Epoch!=epoch || PendingEpoch!=epoch || Desired!=on) {
        ungate();return STATUS_CANCELLED;
    }
    if(on && (status!=STATUS_SUCCESS || voltage>800000)) {
        if(++Attempts<10) {ungate();retry(c);return STATUS_SUCCESS;}
        Pending=0;++Epoch;ungate();
        power_fault(c,status==STATUS_SUCCESS?STATUS_IO_TIMEOUT:status);
        return status==STATUS_SUCCESS?STATUS_IO_TIMEOUT:status;
    }
    ApplyingThread=KeGetCurrentThread();ApplyingEpoch=epoch;
    ungate();
    status=OriginalSetPower(c,on);
    if(gate()!=STATUS_SUCCESS)return STATUS_DEVICE_NOT_READY;
    ApplyingThread=NULL;
    if(PendingEpoch==epoch) {
        if(status==STATUS_SUCCESS)Pending=0;
        else if(++Attempts<10) {ungate();retry(c);return status;}
        else {Pending=0;++Epoch;ungate();power_fault(c,status);return status;}
    }
    ungate();return status;
}

/* Inserted at the actual FE40 system-thread dispatch call. */
NTSTATUS RepairDispatch(PVOID context)
{
    NTSTATUS original=OriginalDispatch(context),power=process_power(context);
    return original!=STATUS_SUCCESS?original:power;
}

/* Hooked into FE40's first KeGetCurrentThread call, before any class alert. */
PKTHREAD RepairThreadIdentity(VOID)
{
    PKTHREAD thread=KeGetCurrentThread();
    if(gate()==STATUS_SUCCESS) {WorkerThread=thread;StopSettled=0;StoppedContext=NULL;ungate();}
    return thread;
}

/* Stop waits for the actual system-thread handle before closing it. All
 * callers are PASSIVE PnP paths; no lock is held across timer stop or join. */
NTSTATUS RepairStop(PVOID c)
{
    HANDLE thread;
    PVOID objects[1]={&StopGate};
    NTSTATUS status;
    if(!c || KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
    if(!GateReady)return STATUS_DEVICE_NOT_READY;
    if(WorkerThread==KeGetCurrentThread())return STATUS_INVALID_DEVICE_STATE;
    status=KeWaitForMultipleObjects(1,objects,WaitAny,Executive,KernelMode,FALSE,NULL,NULL);
    if(status!=STATUS_SUCCESS)return status;
    if(StopSettled && StoppedContext==c) {status=STATUS_SUCCESS;goto done;}
    status=gate();if(status!=STATUS_SUCCESS)goto done;
    SkDriverActive=0;++Epoch;Pending=0;ungate();
    KeSetEvent((PKEVENT)((PUCHAR)c+0x320),IO_NO_INCREMENT,FALSE);
    thread=SkThreadHandle;
    if(thread) {
        status=ZwWaitForSingleObject(thread,FALSE,NULL);
        if(status!=STATUS_SUCCESS)goto done;
        status=ZwClose(thread);if(status!=STATUS_SUCCESS)goto done;
        SkThreadHandle=NULL;
    }
    WorkerThread=NULL;
    ((PFN_WDFTIMERSTOP)SkWdfTable[0xa00/8])
        (SkWdfGlobals,*(WDFTIMER *)((PUCHAR)c+0x230),TRUE);
    status=RepairPowerIo(SkPmicTarget,0,0);
    if(status!=STATUS_SUCCESS)goto done;
    lock_context(c);*(ULONG *)((PUCHAR)c+0x2ec)=1;unlock_context(c);
    StoppedContext=c;StopSettled=1;
    *((PUCHAR)c+0x288)=0;
done:
    KeSetEvent(&StopGate,IO_NO_INCREMENT,FALSE);
    return status;
}

/* 13E30 used to reset AA28/AA40 readiness before stopping FE40. Order the
 * real stop + confirmed PMIC OFF ahead of that reset. The later stock stop
 * call is idempotent and doesn't issue I/O to the now-unready targets. */
NTSTATUS RepairResetBackend(PVOID c)
{
    NTSTATUS status=RepairStop(c);
    return status==STATUS_SUCCESS?OriginalResetBackend(c):status;
}
