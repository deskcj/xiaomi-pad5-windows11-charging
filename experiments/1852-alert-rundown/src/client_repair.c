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
