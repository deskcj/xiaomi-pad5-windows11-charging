#include <ntddk.h>
#include <wdf.h>
#include <intrin.h>
#pragma intrinsic(_InterlockedCompareExchange)
#pragma intrinsic(_InterlockedExchange)
#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_InterlockedExchange64)
#pragma intrinsic(_InterlockedExchangeAdd64)
#pragma intrinsic(_InterlockedOr64)
extern PVOID *SkWdfTable;
extern PWDF_DRIVER_GLOBALS SkWdfGlobals;
extern const WDF_OBJECT_CONTEXT_TYPE_INFO *SkContextType;
extern PVOID SkClassGlobals;
extern PVOID SkClassAlert;
extern NTSTATUS OriginalD0Entry(PVOID,ULONG);
extern NTSTATUS OriginalD0Exit(PVOID,ULONG);

/* Bit0 closes admission; the remaining bits count active alert leases.
 * This state and the live handles have nonpaged backing in .skdata. */
static volatile LONG64 AlertState=1;
static volatile LONG LifeLock;
static volatile LONG StopRequested=1;
static PVOID LiveDevice,LiveController;

static VOID pause_one_ms(VOID)
{
    LARGE_INTEGER delay;
    delay.QuadPart=-10000LL;
    (void)KeDelayExecutionThread(KernelMode,FALSE,&delay);
}

static VOID life_lock(VOID)
{
    while(InterlockedCompareExchange(&LifeLock,1,0)!=0)pause_one_ms();
}
static VOID life_unlock(VOID) { InterlockedExchange(&LifeLock,0); }

static BOOLEAN alert_enter(VOID)
{
    LONG64 old;
    for(;;) {
        old=InterlockedCompareExchange64(&AlertState,0,0);
        if((old&1) || old>MAXLONGLONG-2)return FALSE;
        if(InterlockedCompareExchange64(&AlertState,old+2,old)==old)return TRUE;
    }
}
static VOID alert_leave(VOID) { InterlockedExchangeAdd64(&AlertState,-2); }

/* PASSIVE lifecycle paths only. Never held by synchronous register I/O.
 * The close bit is published before waiting, so a new alert cannot enter. */
static VOID alert_close(VOID)
{
    InterlockedOr64(&AlertState,1);
    while((InterlockedCompareExchange64(&AlertState,0,0)&~1LL)!=0)pause_one_ms();
    LiveDevice=NULL;LiveController=NULL;
}

NTSTATUS RepairD0Entry(PVOID device,ULONG previous)
{
    NTSTATUS status;
    life_lock();
    alert_close();
    InterlockedExchange(&StopRequested,0);
    life_unlock();
    status=OriginalD0Entry(device,previous);
    if(!NT_SUCCESS(status)) {
        InterlockedExchange(&StopRequested,1);
        life_lock();alert_close();life_unlock();
    }
    return status;
}

NTSTATUS RepairD0Exit(PVOID device,ULONG target)
{
    /* An old queued Start must not reopen admission after D0 exit begins. */
    InterlockedExchange(&StopRequested,1);
    InterlockedOr64(&AlertState,1);
    life_lock();alert_close();life_unlock();
    return OriginalD0Exit(device,target);
}

/* The tiny call-site adapter passes X26 (actual WDFDEVICE) as argument3
 * and the original validated class Start address as argument4. */
NTSTATUS RepairClassStart(PVOID globals,PVOID controller,PVOID device,PVOID entry)
{
    NTSTATUS status;
    typedef NTSTATUS (*START)(PVOID,PVOID);
    life_lock();
    if(InterlockedCompareExchange(&StopRequested,0,0)!=0) {
        life_unlock();return STATUS_CANCELLED;
    }
    alert_close();
    status=((START)entry)(globals,controller);
    if(status==STATUS_SUCCESS && InterlockedCompareExchange(&StopRequested,0,0)==0) {
        LiveDevice=device;LiveController=controller;
        KeMemoryBarrier();
        InterlockedExchange64(&AlertState,0);
    }
    life_unlock();
    return status;
}

VOID RepairClassStop(PVOID globals,PVOID controller,PVOID entry)
{
    typedef VOID (*STOP)(PVOID,PVOID);
    InterlockedExchange(&StopRequested,1);
    InterlockedOr64(&AlertState,1);
    life_lock();
    alert_close();
    ((STOP)entry)(globals,controller);
    life_unlock();
}

/* Exact native89E0 ABI: WDFDEVICE, alert count, alert array. UcmTcpciCx
 * may submit read/write callbacks before the class call returns. Only an
 * alert lease is held here; the transport and lifecycle locks stay free. */
VOID RepairClientAlert(PVOID device,SIZE_T count,PVOID alerts)
{
    PVOID context,controller;
    typedef VOID (*ALERT)(PVOID,PVOID,PVOID,SIZE_T);
    if(!device || !alerts || count==0 || count>12 || !alert_enter())return;
    if(device!=LiveDevice) {alert_leave();return;}
    context=((PFN_WDFOBJECTGETTYPEDCONTEXTWORKER)SkWdfTable[0x650/8])
        (SkWdfGlobals,device,SkContextType);
    if(context) {
        controller=*(PVOID *)((PUCHAR)context+0x80);
        if(controller && controller==LiveController)
            ((ALERT)SkClassAlert)(SkClassGlobals,controller,alerts,count);
    }
    alert_leave();
}

/* Bound to the original D0-exit flush. Stop new transport admissions before
 * flushing work, then the original 118 owner drains without freeing a caller.
 * The original work item's parent and typed context ABI are hash-pinned. */
VOID RepairClientFlush(PWDF_DRIVER_GLOBALS globals,WDFWORKITEM item)
{
    WDFOBJECT parent;
    PVOID context;
    parent=((PFN_WDFWORKITEMGETPARENTOBJECT)SkWdfTable[0x570/8])(globals,item);
    context=((PFN_WDFOBJECTGETTYPEDCONTEXTWORKER)SkWdfTable[0x650/8])
        (globals,parent,SkContextType);
    if(context) {
        *((volatile UCHAR *)context+0xf1)=1;
        KeMemoryBarrier();
    }
    ((PFN_WDFWORKITEMFLUSH)SkWdfTable[0x520/8])(globals,item);
}

/* Both audited close paths run at PASSIVE. An infinite ownership drain must
 * yield the processor; it must never fall through and release a foreign I/O. */
VOID RepairClientYield(ULONG ignored)
{
    LARGE_INTEGER interval;
    UNREFERENCED_PARAMETER(ignored);
    interval.QuadPart=-10000LL;
    (void)KeDelayExecutionThread(KernelMode,FALSE,&interval);
}

/* A private PEP INTERFACE reference does not pin the provider's MMIO mappings.
 * Independent admission/rundown spans PrepareHardware -> ReleaseHardware,
 * rather than class Start/Stop. It must be usable before D0Entry as well.
 * The original driver is a hash-pinned single-controller implementation. */
extern PVOID SkMmioHost,SkMmioClock,SkMmioUsb,SkMmioPlatform;
extern NTSTATUS OriginalPrepareHardware(PVOID,PVOID,PVOID);
extern NTSTATUS OriginalProvider(PVOID);
static volatile LONG64 MappingState=1;
static volatile LONG MappingLock;
static NTSTATUS LastMappingStatus=STATUS_DEVICE_NOT_READY;

static VOID mapping_lock(VOID)
{
    while(InterlockedCompareExchange(&MappingLock,1,0)!=0)pause_one_ms();
}
static VOID mapping_unlock(VOID) { InterlockedExchange(&MappingLock,0); }
static VOID mapping_close(VOID)
{
    InterlockedOr64(&MappingState,1);
    while((InterlockedCompareExchange64(&MappingState,0,0)&~1LL)!=0)pause_one_ms();
}
static BOOLEAN mapping_enter(VOID)
{
    LONG64 old;
    for(;;) {
        old=InterlockedCompareExchange64(&MappingState,0,0);
        if((old&1) || old>MAXLONGLONG-2)return FALSE;
        if(InterlockedCompareExchange64(&MappingState,old+2,old)==old)return TRUE;
    }
}
static VOID mapping_leave(VOID) { InterlockedExchangeAdd64(&MappingState,-2); }
static BOOLEAN mappings_present(VOID)
{
    return SkMmioHost && SkMmioClock && SkMmioUsb && SkMmioPlatform;
}
static VOID unmap_slot(PVOID *slot,SIZE_T size)
{
    PVOID mapping=*slot;
    *slot=NULL;
    if(mapping)MmUnmapIoSpace(mapping,size);
}
static VOID unmap_all(VOID)
{
    /* Exact original2D08 order and lengths. NULL mappings are never unmapped. */
    unmap_slot(&SkMmioClock,0x14000);
    unmap_slot(&SkMmioPlatform,0x200000);
    unmap_slot(&SkMmioUsb,0x200000);
    unmap_slot(&SkMmioHost,0x200000);
}
static PVOID map_region(LONGLONG address,SIZE_T length)
{
    PHYSICAL_ADDRESS physical;
    physical.QuadPart=address;
    return MmMapIoSpaceEx(physical,length,0x204);
}

/* Replaces2BD0 completely; original physical addresses and attributes retained.
 * Only this PASSIVE lifecycle path can publish a complete mapping set. */
VOID RepairMap(VOID)
{
    mapping_lock();
    if(mappings_present() && !(InterlockedCompareExchange64(&MappingState,0,0)&1)) {
        mapping_unlock();return;
    }
    mapping_close();
    unmap_all();
    LastMappingStatus=STATUS_INSUFFICIENT_RESOURCES;
    SkMmioPlatform=map_region(0x100000,0x200000);
    if(!SkMmioPlatform)goto fail;
    SkMmioClock=map_region(0x88e0000,0x14000);
    if(!SkMmioClock)goto fail;
    SkMmioUsb=map_region(0xa600000,0x200000);
    if(!SkMmioUsb)goto fail;
    SkMmioHost=map_region(0xa800000,0x200000);
    if(!SkMmioHost)goto fail;
    LastMappingStatus=STATUS_SUCCESS;
    InterlockedExchange64(&MappingState,0);
    mapping_unlock();return;
fail:
    unmap_all();
    mapping_unlock();
}

/* Replaces2D08 completely, including every old direct/indirect entry to it. */
VOID RepairUnmap(VOID)
{
    InterlockedOr64(&MappingState,1);
    mapping_lock();
    mapping_close();
    LastMappingStatus=STATUS_DEVICE_NOT_READY;
    unmap_all();
    mapping_unlock();
}

NTSTATUS RepairPrepareHardware(PVOID device,PVOID raw,PVOID translated)
{
    PVOID context;
    NTSTATUS status=OriginalPrepareHardware(device,raw,translated);
    if(!NT_SUCCESS(status)) {RepairUnmap();return status;}
    context=((PFN_WDFOBJECTGETTYPEDCONTEXTWORKER)SkWdfTable[0x650/8])
        (SkWdfGlobals,device,SkContextType);
    if(!context || !*(PVOID *)((PUCHAR)context+0x160)) {
        RepairUnmap();return STATUS_INSUFFICIENT_RESOURCES;
    }
    if(LastMappingStatus!=STATUS_SUCCESS ||
       (InterlockedCompareExchange64(&MappingState,0,0)&1))
        return LastMappingStatus!=STATUS_SUCCESS ? LastMappingStatus : STATUS_DEVICE_NOT_READY;
    return status;
}

typedef struct _PROVIDER_PACKET {
    BOOLEAN Enabled;
    UCHAR Reserved[7];
    UNICODE_STRING Name;
} PROVIDER_PACKET;
C_ASSERT(sizeof(PROVIDER_PACKET)==24);

/* Same private INTERFACE ABI as original2E50. No wait/lifecycle lock is held
 * while calling the provider; release can close admission and drain leases. */
NTSTATUS RepairProvider(PVOID input)
{
    const PROVIDER_PACKET *packet=(const PROVIDER_PACKET *)input;
    NTSTATUS status;
    if(!mapping_enter())return STATUS_DEVICE_NOT_READY;
    if(!packet || packet->Enabled>TRUE || !packet->Name.Buffer ||
       packet->Name.Length!=18 || packet->Name.MaximumLength<20) {
        mapping_leave();return STATUS_INVALID_PARAMETER;
    }
    status=OriginalProvider(input);
    mapping_leave();return status;
}
