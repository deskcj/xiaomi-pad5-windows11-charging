/* Laboratory2141 policy object, NOT an installable PEP replacement.
 * Bindings below refer to the exact hash-pinned PEP2140 image.
 * Own notification rundown is implemented; external provider MMIO lifetime,
 * PEP unregister/unload, IRQL contract and final PE integration remain open.
 */
#include <ntddk.h>
#include <intrin.h>
typedef struct _PRIVATE_INTERFACE {
    INTERFACE Header;
    PVOID Notify;
} PRIVATE_INTERFACE;
typedef struct _PRIVATE_PACKET {
    BOOLEAN Enabled;
    UCHAR Reserved[7];
    UNICODE_STRING Name;
} PRIVATE_PACKET;
C_ASSERT(sizeof(PRIVATE_INTERFACE)==40);
C_ASSERT(sizeof(PRIVATE_PACKET)==24);

extern PRIVATE_INTERFACE SkPepInterface;
extern PVOID SkPepTarget,SkPepPacket,SkPepPlatform,SkPepControllers;
extern ULONG SkPepMode,SkPepIndex;
extern NTSTATUS OriginalPepNotify(PVOID,PVOID);
extern VOID OriginalPepPower(PVOID,BOOLEAN);
extern VOID OriginalTargetClose(PVOID);
extern VOID OriginalObjectDelete(PVOID);
static volatile LONG NotifyLock;
static volatile LONG64 PowerGate=1;
static BOOLEAN OwnInterface;
static const WCHAR Uri0[]=L"\\_SB.URS0";
static const WCHAR Uri1[]=L"\\_SB.URS1";

static VOID wait_one_ms(VOID)
{
    LARGE_INTEGER interval;
    interval.QuadPart=-10000LL;
    (void)KeDelayExecutionThread(KernelMode,FALSE,&interval);
}
static VOID lock_notifications(VOID)
{
    while(InterlockedCompareExchange(&NotifyLock,1,0)!=0)wait_one_ms();
}
static VOID unlock_notifications(VOID) { InterlockedExchange(&NotifyLock,0); }
static BOOLEAN enter_power(VOID)
{
    LONG64 old;
    for(;;) {
        old=InterlockedCompareExchange64(&PowerGate,0,0);
        if((old&1) || old>MAXLONGLONG-2)return FALSE;
        if(InterlockedCompareExchange64(&PowerGate,old+2,old)==old)return TRUE;
    }
}
static VOID leave_power(VOID) { InterlockedExchangeAdd64(&PowerGate,-2); }
static VOID close_power(VOID)
{
    InterlockedOr64(&PowerGate,1);
    while((InterlockedCompareExchange64(&PowerGate,0,0)&~1LL)!=0)wait_one_ms();
}
static BOOLEAN valid_interface(VOID)
{
    return SkPepInterface.Header.Size==40 && SkPepInterface.Header.Version==1 &&
        SkPepInterface.Header.InterfaceReference &&
        SkPepInterface.Header.InterfaceDereference && SkPepInterface.Notify;
}
static VOID cleanup(VOID)
{
    PVOID target,packet;
    if(OwnInterface) {
        SkPepInterface.Header.InterfaceDereference(SkPepInterface.Header.Context);
        OwnInterface=FALSE;
    }
    RtlZeroMemory(&SkPepInterface,sizeof(SkPepInterface));
    target=SkPepTarget;
    if(target) {
        OriginalTargetClose(target);
        OriginalObjectDelete(target);
        SkPepTarget=NULL;
    }
    packet=SkPepPacket;
    SkPepPacket=NULL;
    if(packet)ExFreePoolWithTag(packet,0x59657071);
}

NTSTATUS RepairPepNotify(PVOID notification,PVOID context)
{
    const GUID *event;
    NTSTATUS status;
    BOOLEAN arrival,removal;
    if(!notification)return STATUS_INVALID_PARAMETER;
    event=(const GUID *)((PUCHAR)notification+4);
    arrival=event->Data1==0xcb3a4004 && event->Data2==0x46f0 && event->Data3==0x11d0 &&
        *(UNALIGNED const ULONG64 *)event->Data4==0x3f05139760008fb0ULL;
    removal=event->Data1==0xcb3a4005 && event->Data2==0x46f0 && event->Data3==0x11d0 &&
        *(UNALIGNED const ULONG64 *)event->Data4==0x3f05139760008fb0ULL;
    if(!arrival && !removal)return OriginalPepNotify(notification,context);
    lock_notifications();
    close_power();
    if(removal) {
        cleanup();unlock_notifications();return STATUS_SUCCESS;
    }
    if(OwnInterface && SkPepTarget && SkPepPacket) {
        InterlockedExchange64(&PowerGate,0);
        unlock_notifications();return STATUS_SUCCESS;
    }
    cleanup();
    status=OriginalPepNotify(notification,context);
    if(NT_SUCCESS(status) && valid_interface())OwnInterface=TRUE;
    if(status!=STATUS_SUCCESS || !OwnInterface || !SkPepTarget || !SkPepPacket) {
        if(status==STATUS_SUCCESS)
            status=SkPepPacket ? STATUS_DEVICE_CONFIGURATION_ERROR : STATUS_INSUFFICIENT_RESOURCES;
        cleanup();unlock_notifications();return status;
    }
    InterlockedExchange64(&PowerGate,0);
    unlock_notifications();return STATUS_SUCCESS;
}

/* Verify the original PEP's current controller path but pass a stable, private
 * URI string to the provider. Shared heap state is never used for packets. */
static PCWSTR current_uri(VOID)
{
    PVOID controller;
    PCWSTR name;
    ULONG i;
    BOOLEAN zero=TRUE,one=TRUE;
    if(!SkPepControllers || SkPepIndex>1)return NULL;
    controller=*(PVOID *)((PUCHAR)SkPepControllers+0x58*SkPepIndex+8);
    if(!controller)return NULL;
    name=*(PCWSTR *)((PUCHAR)controller+8);
    if(!name)return NULL;
    for(i=0;i<RTL_NUMBER_OF(Uri0);i++) {
        zero=(BOOLEAN)(zero && name[i]==Uri0[i]);
        one=(BOOLEAN)(one && name[i]==Uri1[i]);
        if(!zero && !one)return NULL;
    }
    return zero ? Uri0 : Uri1;
}
static VOID notify_provider(BOOLEAN enabled)
{
    PRIVATE_PACKET packet={0};
    PCWSTR name;
    typedef NTSTATUS (*NOTIFY)(PVOID);
    if(!enter_power())return;
    name=current_uri();
    if(name) {
        packet.Enabled=enabled;
        packet.Name.Length=(USHORT)(sizeof(Uri0)-sizeof(WCHAR));
        packet.Name.MaximumLength=(USHORT)sizeof(Uri0);
        packet.Name.Buffer=(PWSTR)name;
        (void)((NOTIFY)SkPepInterface.Notify)(&packet);
    }
    leave_power();
}

VOID RepairPepPower(PVOID device,BOOLEAN enabled)
{
    typedef VOID (*PLATFORM)(PVOID,ULONG,BOOLEAN);
    PLATFORM power;
    if(SkPepMode!=2) {OriginalPepPower(device,enabled);return;}
    if(!SkPepPlatform || !device)return;
    power=*(PLATFORM *)((PUCHAR)device+0x948);
    if(!power)return;
    if(enabled==TRUE)notify_provider(TRUE);
    /* No interface lease is held through platform code, which may initiate
     * a PnP callback. Each provider call acquires its own short lease. */
    power(SkPepPlatform,0,enabled);
    if(enabled==FALSE)notify_provider(FALSE);
}
