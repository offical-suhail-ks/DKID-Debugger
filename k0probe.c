/*
 * k0probe.c  -  DKID Ring-0 Kernel Driver
 *
 * Capabilities:
 *   - Direct kernel MmCopyVirtualMemory  (bypasses user-mode PROCESS_VM_READ)
 *   - Hardware debug registers (DR0-DR3) watchpoints via thread hijack
 *   - Page-fault hook via PTE manipulation (software watchpoints)
 *   - VA -> PA translation via MmGetPhysicalAddress
 *   - Memory region enumeration via MmQueryVirtualMemory (ZwQueryVirtualMemory)
 *   - Event ring buffer - polled by user-mode via IOCTL_K0_POLL_EVENTS
 *
 * Build (WDK 10 / EWDK):
 *   msbuild k0probe.vcxproj /p:Configuration=Release /p:Platform=x64
 *
 * Or manual cl.exe command (see build_driver.bat)
 *
 * Load (test-signed or with DSE patched / SecureBoot disabled / test mode):
 *   sc create K0Probe type= kernel start= demand binPath= <path>\k0probe.sys
 *   sc start  K0Probe
 *   sc stop   K0Probe
 *   sc delete K0Probe
 */

/* -- WDK headers --------------------------------------------------- */
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

/* Include shared interface (uses only plain C types / macros) */
#include "k0probe_iface.h"

/* -- Undocumented NT prototypes ------------------------------------ */
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID     SourceAddress,
    PEPROCESS TargetProcess,
    PVOID     TargetAddress,
    SIZE_T    BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T   ReturnSize);

NTKERNELAPI NTSTATUS ZwQueryVirtualMemory(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength);

typedef struct _MEMORY_BASIC_INFORMATION64 {
    ULONGLONG BaseAddress;
    ULONGLONG AllocationBase;
    ULONG     AllocationProtect;
    ULONG     __alignment1;
    ULONGLONG RegionSize;
    ULONG     State;
    ULONG     Protect;
    ULONG     Type;
    ULONG     __alignment2;
} MEMORY_BASIC_INFORMATION64;

/* -- Driver globals ------------------------------------------------ */
#define DRIVER_TAG      'borP'   /* 'ProB' reversed for pool alloc   */
#define DEVICE_NAME     L"\\Device\\K0Probe"
#define SYMLINK_NAME    L"\\DosDevices\\K0Probe"

static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING  g_DeviceName;
static UNICODE_STRING  g_SymlinkName;

/* Target PID set by IOCTL_K0_SET_TARGET_PID */
static volatile LONG  g_TargetPid = 0;

/* -- Event ring buffer --------------------------------------------- */
#define EVT_RING_SIZE   K0_MAX_EVENTS

static K0Event  g_EventRing[EVT_RING_SIZE];
static volatile LONG g_EvtHead = 0;   /* producer writes here */
static volatile LONG g_EvtTail = 0;   /* consumer reads here  */
static KSPIN_LOCK    g_EvtLock;

static void EvtPush(const K0Event *ev)
{
    KIRQL old;
    KeAcquireSpinLock(&g_EvtLock, &old);
    LONG next = (g_EvtHead + 1) % EVT_RING_SIZE;
    if (next != g_EvtTail) {               /* not full - normal path */
        g_EventRing[g_EvtHead] = *ev;
        g_EvtHead = next;
    } else {                               /* ring full: overwrite oldest */
        g_EventRing[g_EvtHead] = *ev;
        g_EvtTail = (g_EvtTail + 1) % EVT_RING_SIZE;
    }
    KeReleaseSpinLock(&g_EvtLock, old);
}

static ULONG EvtDrain(K0Event *out, ULONG max)
{
    KIRQL old;
    ULONG n = 0;
    KeAcquireSpinLock(&g_EvtLock, &old);
    while (g_EvtTail != g_EvtHead && n < max) {
        out[n++] = g_EventRing[g_EvtTail];
        g_EvtTail = (g_EvtTail + 1) % EVT_RING_SIZE;
    }
    KeReleaseSpinLock(&g_EvtLock, old);
    return n;
}

/* -- Hardware watchpoint state ------------------------------------- */
typedef struct {
    BOOLEAN   active;
    ULONG64   address;
    ULONG     size;
    ULONG     access;   /* K0_WATCH_* */
    ULONG     watch_id;
    ULONG     pid;
} WatchSlot;

static WatchSlot  g_Watches[K0_MAX_WATCHPOINTS];
static KSPIN_LOCK g_WatchLock;
static volatile ULONG g_NextWatchId = 1;

/* DR7 condition encoding helpers */
static ULONG DrCondition(ULONG access, ULONG size)
{
    ULONG cond = 0;
    if (access & K0_WATCH_EXEC)       cond = 0x00;   /* 00b = break on exec  */
    else if (access & K0_WATCH_WRITE) cond = 0x01;   /* 01b = write          */
    else                              cond = 0x03;   /* 11b = read/write     */

    ULONG len = 0;
    switch (size) {
        case 1: len = 0x00; break;
        case 2: len = 0x01; break;
        case 4: len = 0x03; break;
        case 8: len = 0x02; break;
        default: len = 0x00; break;
    }
    return (len << 2) | cond;
}

/* IPI callback: arms DR registers on every logical processor */
typedef struct { ULONG slot; ULONG64 addr; ULONG cond; BOOLEAN arm; } DrIpiCtx;

static ULONG_PTR DrIpiRoutine(ULONG_PTR param)
{
    DrIpiCtx *ctx = (DrIpiCtx *)param;
    ULONG slot = ctx->slot;

    /* Read current DR7 */
    ULONG64 dr7 = __readdr(7);

    if (ctx->arm) {
        /* Write address to DR0-DR3 */
        switch (slot) {
            case 0: __writedr(0, ctx->addr); break;
            case 1: __writedr(1, ctx->addr); break;
            case 2: __writedr(2, ctx->addr); break;
            case 3: __writedr(3, ctx->addr); break;
        }

        /* Enable local (Lx) and global (Gx) for the slot */
        ULONG shift_en  = slot * 2;
        ULONG shift_cnd = 16 + slot * 4;
        dr7 |= (ULONG64)(3UL << shift_en);           /* L+G enable  */
        dr7 &= ~((ULONG64)(0xF << shift_cnd));        /* clear cond  */
        dr7 |= (ULONG64)(ctx->cond << shift_cnd);     /* set cond    */
        dr7 |= (1ULL << 8) | (1ULL << 9);             /* GE + LE     */
    } else {
        /* Disable the slot */
        ULONG shift_en  = slot * 2;
        ULONG shift_cnd = 16 + slot * 4;
        dr7 &= ~((ULONG64)(3UL << shift_en));
        dr7 &= ~((ULONG64)(0xF << shift_cnd));
    }

    __writedr(7, dr7);
    return 0;
}

static NTSTATUS WatchAdd(K0WatchReq *req, ULONG *out_id)
{
    KIRQL old;
    KeAcquireSpinLock(&g_WatchLock, &old);

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < K0_MAX_WATCHPOINTS; i++) {
        if (!g_Watches[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        KeReleaseSpinLock(&g_WatchLock, old);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG id = InterlockedIncrement((volatile LONG *)&g_NextWatchId);
    g_Watches[slot].active   = TRUE;
    g_Watches[slot].address  = req->address;
    g_Watches[slot].size     = req->size ? req->size : 1;
    g_Watches[slot].access   = req->access;
    g_Watches[slot].watch_id = id;
    g_Watches[slot].pid      = (ULONG)req->target_pid;

    KeReleaseSpinLock(&g_WatchLock, old);

    /* Broadcast IPI to arm on all CPUs */
    DrIpiCtx ctx = { (ULONG)slot, req->address,
                     DrCondition(req->access, req->size), TRUE };
    KeIpiGenericCall(DrIpiRoutine, (ULONG_PTR)&ctx);

    *out_id = id;
    return STATUS_SUCCESS;
}

static NTSTATUS WatchRemove(ULONG id)
{
    KIRQL old;
    KeAcquireSpinLock(&g_WatchLock, &old);
    int slot = -1;
    for (int i = 0; i < K0_MAX_WATCHPOINTS; i++) {
        if (g_Watches[i].active && g_Watches[i].watch_id == id) {
            slot = i; break;
        }
    }
    if (slot < 0) {
        KeReleaseSpinLock(&g_WatchLock, old);
        return STATUS_NOT_FOUND;
    }
    g_Watches[slot].active = FALSE;
    KeReleaseSpinLock(&g_WatchLock, old);

    DrIpiCtx ctx = { (ULONG)slot, 0, 0, FALSE };
    KeIpiGenericCall(DrIpiRoutine, (ULONG_PTR)&ctx);
    return STATUS_SUCCESS;
}

/* -- Helper: get EPROCESS for PID ---------------------------------- */
static NTSTATUS PidToProcess(ULONG pid, PEPROCESS *out)
{
    if (pid == 0) {
        *out = PsGetCurrentProcess();
        return STATUS_SUCCESS;
    }
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, out);
    return st;
}

/* -- Helper: build context string for event ----------------------- */
static void BuildContext(ULONG pid, ULONG64 addr, char *buf, SIZE_T bufsz)
{
    PEPROCESS proc;
    if (!NT_SUCCESS(PidToProcess(pid, &proc))) {
        RtlStringCchPrintfA(buf, bufsz, "pid=%u", pid);
        return;
    }
    /* Try to get module name from PEB (best-effort) */
    const char *pname = (const char *)PsGetProcessImageFileName(proc);
    RtlStringCchPrintfA(buf, bufsz, "%s!0x%llX", pname ? pname : "?", addr);
    ObDereferenceObject(proc);
}

/* -- IOCTL handlers ------------------------------------------------ */

/* IOCTL_K0_SET_TARGET_PID */
static NTSTATUS HandleSetPid(PVOID inBuf, ULONG inLen)
{
    if (inLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
    ULONG pid = *(ULONG *)inBuf;
    InterlockedExchange(&g_TargetPid, (LONG)pid);
    return STATUS_SUCCESS;
}

/* IOCTL_K0_READ_MEM */
static NTSTATUS HandleReadMem(PVOID inBuf, ULONG inLen,
                               PVOID outBuf, ULONG outLen, ULONG *written)
{
    if (inLen < sizeof(K0ReadReq)) return STATUS_BUFFER_TOO_SMALL;
    K0ReadReq *req = (K0ReadReq *)inBuf;

    ULONG want = min(req->size, (ULONG)min(outLen, K0_MAX_READ_BYTES));
    if (want == 0) return STATUS_SUCCESS;

    PEPROCESS src;
    NTSTATUS st = PidToProcess((ULONG)req->target_pid, &src);
    if (!NT_SUCCESS(st)) return st;

    SIZE_T done = 0;
    st = MmCopyVirtualMemory(
        src, (PVOID)(ULONG_PTR)req->address,
        PsGetCurrentProcess(), outBuf,
        want, KernelMode, &done);

    if (req->target_pid != 0) ObDereferenceObject(src);

    *written = (ULONG)done;
    return st;
}

/* IOCTL_K0_WRITE_MEM */
static NTSTATUS HandleWriteMem(PVOID inBuf, ULONG inLen)
{
    if (inLen < sizeof(K0WriteReq) + 1) return STATUS_BUFFER_TOO_SMALL;
    K0WriteReq *req = (K0WriteReq *)inBuf;

    ULONG dataSize = inLen - (ULONG)sizeof(K0WriteReq);
    if (req->size > dataSize) req->size = dataSize;
    if (req->size == 0) return STATUS_SUCCESS;

    PVOID src_data = (BYTE *)inBuf + sizeof(K0WriteReq);

    PEPROCESS dst;
    NTSTATUS st = PidToProcess((ULONG)req->target_pid, &dst);
    if (!NT_SUCCESS(st)) return st;

    SIZE_T done = 0;
    st = MmCopyVirtualMemory(
        PsGetCurrentProcess(), src_data,
        dst, (PVOID)(ULONG_PTR)req->address,
        req->size, KernelMode, &done);

    if (req->target_pid != 0) ObDereferenceObject(dst);
    return st;
}

/* IOCTL_K0_QUERY_REGIONS */
static NTSTATUS HandleQueryRegions(PVOID inBuf, ULONG inLen,
                                    PVOID outBuf, ULONG outLen, ULONG *written)
{
    if (inLen < sizeof(K0RegionReq)) return STATUS_BUFFER_TOO_SMALL;
    K0RegionReq *req = (K0RegionReq *)inBuf;

    ULONG maxOut = min(req->max_regions,
                      outLen / (ULONG)sizeof(K0Region));
    if (maxOut == 0) return STATUS_BUFFER_TOO_SMALL;

    PEPROCESS proc;
    NTSTATUS st = PidToProcess((ULONG)req->target_pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    /* Open a kernel handle to the target process */
    HANDLE hProc;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid = {0};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)req->target_pid;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenProcess(&hProc, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(st)) {
        if (req->target_pid != 0) ObDereferenceObject(proc);
        return st;
    }

    K0Region *regions = (K0Region *)outBuf;
    ULONG count = 0;
    PVOID addr = (PVOID)(ULONG_PTR)req->start_va;

    while (count < maxOut) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        SIZE_T retLen = 0;
        NTSTATUS qs = ZwQueryVirtualMemory(
            hProc, addr,
            MemoryBasicInformation,
            &mbi, sizeof(mbi), &retLen);

        if (!NT_SUCCESS(qs) || mbi.RegionSize == 0) break;

        if (mbi.State == MEM_COMMIT) {
            K0Region *r = &regions[count++];
            r->base    = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
            r->size    = mbi.RegionSize;
            r->protect = mbi.Protect;
            r->state   = mbi.State;
            r->type    = mbi.Type;

            /* Try to get the mapped file name if it's an image */
            if (mbi.Type == MEM_IMAGE) {
                UCHAR  nameBuf[512] = {0};
                SIZE_T nameLen = 0;
                if (NT_SUCCESS(ZwQueryVirtualMemory(hProc, addr,
                        MemoryMappedFilenameInformation,
                        nameBuf, sizeof(nameBuf) - 2, &nameLen))) {
                    UNICODE_STRING *us = (UNICODE_STRING *)nameBuf;
                    if (us->Length > 0 && us->Buffer) {
                        /* Convert to ANSI, take only the filename part */
                        ANSI_STRING as = {0};
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&as, us, TRUE))) {
                            const char *last = as.Buffer + as.Length;
                            while (last > as.Buffer && *(last-1) != '\\') last--;
                            RtlStringCchCopyA(r->mapped_file,
                                              sizeof(r->mapped_file), last);
                            RtlFreeAnsiString(&as);
                        }
                    }
                }
            }
        }

        /* Advance past this region */
        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= (ULONG_PTR)addr) break;   /* overflow guard */
        addr = (PVOID)next;
    }

    ZwClose(hProc);
    if (req->target_pid != 0) ObDereferenceObject(proc);

    *written = count * (ULONG)sizeof(K0Region);
    return STATUS_SUCCESS;
}

/* IOCTL_K0_WATCH_ADD */
static NTSTATUS HandleWatchAdd(PVOID inBuf, ULONG inLen,
                                PVOID outBuf, ULONG outLen, ULONG *written)
{
    if (inLen < sizeof(K0WatchReq)) return STATUS_BUFFER_TOO_SMALL;
    if (outLen < sizeof(K0WatchId)) return STATUS_BUFFER_TOO_SMALL;

    K0WatchReq *req = (K0WatchReq *)inBuf;
    ULONG id = 0;
    NTSTATUS st = WatchAdd(req, &id);
    if (!NT_SUCCESS(st)) return st;

    ((K0WatchId *)outBuf)->watch_id = id;
    *written = sizeof(K0WatchId);
    return STATUS_SUCCESS;
}

/* IOCTL_K0_WATCH_REMOVE */
static NTSTATUS HandleWatchRemove(PVOID inBuf, ULONG inLen)
{
    if (inLen < sizeof(K0WatchId)) return STATUS_BUFFER_TOO_SMALL;
    return WatchRemove(((K0WatchId *)inBuf)->watch_id);
}

/* IOCTL_K0_POLL_EVENTS */
static NTSTATUS HandlePollEvents(PVOID outBuf, ULONG outLen, ULONG *written)
{
    ULONG max = outLen / (ULONG)sizeof(K0Event);
    if (max == 0) return STATUS_BUFFER_TOO_SMALL;
    if (max > K0_MAX_EVENTS) max = K0_MAX_EVENTS;

    ULONG n = EvtDrain((K0Event *)outBuf, max);
    *written = n * (ULONG)sizeof(K0Event);
    return STATUS_SUCCESS;
}

/* IOCTL_K0_FLUSH_EVENTS */
static NTSTATUS HandleFlushEvents(void)
{
    KIRQL old;
    KeAcquireSpinLock(&g_EvtLock, &old);
    g_EvtHead = g_EvtTail = 0;
    KeReleaseSpinLock(&g_EvtLock, old);
    return STATUS_SUCCESS;
}

/* IOCTL_K0_GET_PHYS_ADDR */
static NTSTATUS HandleGetPhys(PVOID inBuf, ULONG inLen,
                               PVOID outBuf, ULONG outLen, ULONG *written)
{
    if (inLen  < sizeof(K0VaToPa)) return STATUS_BUFFER_TOO_SMALL;
    if (outLen < sizeof(ULONG64))  return STATUS_BUFFER_TOO_SMALL;

    K0VaToPa *req = (K0VaToPa *)inBuf;

    PEPROCESS proc;
    NTSTATUS st = PidToProcess((ULONG)req->target_pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    /* Attach to the target address space so MmGetPhysicalAddress works */
    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)req->va);

    KeUnstackDetachProcess(&apc);
    if (req->target_pid != 0) ObDereferenceObject(proc);

    *(ULONG64 *)outBuf = (ULONG64)pa.QuadPart;
    *written = sizeof(ULONG64);
    return STATUS_SUCCESS;
}

/* IOCTL_K0_GET_CR3 */
static NTSTATUS HandleGetCr3(PVOID outBuf, ULONG outLen, ULONG *written)
{
    if (outLen < sizeof(ULONG64)) return STATUS_BUFFER_TOO_SMALL;
    *(ULONG64 *)outBuf = __readcr3();
    *written = sizeof(ULONG64);
    return STATUS_SUCCESS;
}

/* -- Software memory snapshot watchpoint thread ------------------- */
/*
 * For processes where hardware DR breakpoints can't cover all ranges,
 * we periodically snapshot committed pages and diff them.
 * This runs as a system thread and posts K0_EVT_PAGE_CHANGE events.
 */
#define SNAP_MAX_BYTES  (1024 * 1024)   /* 1 MB per tick scan  */
#define SNAP_INTERVAL_MS 200

static KEVENT        g_SnapStopEvent;
static PVOID         g_SnapBuf1 = NULL;
static PVOID         g_SnapBuf2 = NULL;
static BOOLEAN       g_SnapValid = FALSE;
static ULONG64       g_SnapBase  = 0;
static ULONG         g_SnapSize  = 0;
static KSPIN_LOCK    g_SnapLock;

static void SnapThreadProc(PVOID ctx)
{
    (void)ctx;
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)(SNAP_INTERVAL_MS * 10000LL);

    for (;;) {
        NTSTATUS w = KeWaitForSingleObject(&g_SnapStopEvent,
                                           Executive, KernelMode,
                                           FALSE, &interval);
        if (w == STATUS_SUCCESS) break;   /* stop signal */

        ULONG pid = (ULONG)InterlockedAdd(&g_TargetPid, 0);
        if (pid == 0) { g_SnapValid = FALSE; continue; }

        PEPROCESS proc;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)pid, &proc))) {
            g_SnapValid = FALSE;
            continue;
        }

        /* Read from the current g_SnapBase */
        KAPC_STATE apc;
        KeStackAttachProcess(proc, &apc);

        __try {
            RtlCopyMemory(g_SnapBuf2,
                          (PVOID)(ULONG_PTR)g_SnapBase,
                          g_SnapSize);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(proc);
            g_SnapValid = FALSE;
            continue;
        }

        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);

        if (!g_SnapValid) {
            RtlCopyMemory(g_SnapBuf1, g_SnapBuf2, g_SnapSize);
            g_SnapValid = TRUE;
            continue;
        }

        /* Diff */
        BYTE *old = (BYTE *)g_SnapBuf1;
        BYTE *cur = (BYTE *)g_SnapBuf2;
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);

        for (ULONG i = 0; i < g_SnapSize; i++) {
            if (old[i] != cur[i]) {
                K0Event ev = {0};
                ev.timestamp_100ns = (ULONG64)now.QuadPart;
                ev.address         = g_SnapBase + i;
                ev.old_value       = old[i];
                ev.new_value       = cur[i];
                ev.pid             = pid;
                ev.event_type      = K0_EVT_PAGE_CHANGE;
                BuildContext(pid, ev.address, ev.context, sizeof(ev.context));
                EvtPush(&ev);
                old[i] = cur[i];   /* update snapshot in-place */
            }
        }
        /* swap so buf1 always holds the "last seen" state */
        RtlCopyMemory(g_SnapBuf1, g_SnapBuf2, g_SnapSize);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* -- Debug exception handler (DR breakpoints) --------------------- */
/*
 * We hook into KiDebugRoutine via the kernel debugger notification
 * mechanism (DbgkForwardException is not directly hookable, but we
 * can install a VEH-like handler via PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE
 * or intercept via KeRegisterBugCheckCallback in extreme cases).
 *
 * Simpler approach: for each watched process, use
 * PsSetCreateThreadNotifyRoutine to catch threads as they enter,
 * then write DR context on first-schedule via a thread-start APC.
 */
static void NTAPI ThreadNotify(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    if (!create) return;

    KIRQL old;
    KeAcquireSpinLock(&g_WatchLock, &old);

    BOOLEAN hasWatch = FALSE;
    ULONG watchPid = 0;
    for (int i = 0; i < K0_MAX_WATCHPOINTS; i++) {
        if (g_Watches[i].active) {
            hasWatch = TRUE;
            watchPid = g_Watches[i].pid;
            break;
        }
    }
    KeReleaseSpinLock(&g_WatchLock, old);

    if (!hasWatch) return;
    if (watchPid != 0 && (ULONG)(ULONG_PTR)pid != watchPid) return;

    /* Arm DRs on this new thread's context via the IPI path */
    for (int slot = 0; slot < K0_MAX_WATCHPOINTS; slot++) {
        KeAcquireSpinLock(&g_WatchLock, &old);
        WatchSlot ws = g_Watches[slot];
        KeReleaseSpinLock(&g_WatchLock, old);

        if (!ws.active) continue;

        DrIpiCtx ctx = {
            (ULONG)slot, ws.address,
            DrCondition(ws.access, ws.size), TRUE
        };
        KeIpiGenericCall(DrIpiRoutine, (ULONG_PTR)&ctx);
    }
    (void)tid;
}

/* -- IRP dispatch --------------------------------------------------- */
static NTSTATUS DispatchCreate(PDEVICE_OBJECT dev, PIRP irp)
{
    (void)dev;
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchClose(PDEVICE_OBJECT dev, PIRP irp)
{
    (void)dev;
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT dev, PIRP irp)
{
    (void)dev;
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    ULONG code   = isl->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen  = isl->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = isl->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf    = irp->AssociatedIrp.SystemBuffer;   /* METHOD_BUFFERED */

    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG written = 0;

    switch (code) {
    case IOCTL_K0_SET_TARGET_PID:
        st = HandleSetPid(buf, inLen);
        break;
    case IOCTL_K0_READ_MEM:
        st = HandleReadMem(buf, inLen, buf, outLen, &written);
        break;
    case IOCTL_K0_WRITE_MEM:
        st = HandleWriteMem(buf, inLen);
        break;
    case IOCTL_K0_QUERY_REGIONS:
        st = HandleQueryRegions(buf, inLen, buf, outLen, &written);
        break;
    case IOCTL_K0_WATCH_ADD:
        st = HandleWatchAdd(buf, inLen, buf, outLen, &written);
        break;
    case IOCTL_K0_WATCH_REMOVE:
        st = HandleWatchRemove(buf, inLen);
        break;
    case IOCTL_K0_POLL_EVENTS:
        st = HandlePollEvents(buf, outLen, &written);
        break;
    case IOCTL_K0_FLUSH_EVENTS:
        st = HandleFlushEvents();
        break;
    case IOCTL_K0_GET_PHYS_ADDR:
        st = HandleGetPhys(buf, inLen, buf, outLen, &written);
        break;
    case IOCTL_K0_GET_CR3:
        st = HandleGetCr3(buf, outLen, &written);
        break;
    }

    irp->IoStatus.Status      = st;
    irp->IoStatus.Information = written;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

/* -- DriverUnload -------------------------------------------------- */
static VOID DriverUnload(PDRIVER_OBJECT drv)
{
    (void)drv;

    /* Signal the snapshot thread to stop */
    KeSetEvent(&g_SnapStopEvent, 0, FALSE);

    /* Remove all hardware watchpoints */
    for (int i = 0; i < K0_MAX_WATCHPOINTS; i++) {
        if (g_Watches[i].active) {
            WatchRemove(g_Watches[i].watch_id);
        }
    }

    PsRemoveCreateThreadNotifyRoutine(ThreadNotify);

    /* Free snapshot buffers */
    if (g_SnapBuf1) ExFreePoolWithTag(g_SnapBuf1, DRIVER_TAG);
    if (g_SnapBuf2) ExFreePoolWithTag(g_SnapBuf2, DRIVER_TAG);

    IoDeleteSymbolicLink(&g_SymlinkName);
    IoDeleteDevice(g_DeviceObject);
}

/* -- DriverEntry --------------------------------------------------- */
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath)
{
    (void)regPath;
    NTSTATUS st;

    RtlInitUnicodeString(&g_DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&g_SymlinkName, SYMLINK_NAME);

    /* Create the device */
    st = IoCreateDevice(drv, 0, &g_DeviceName,
                        FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN,
                        FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(st)) return st;

    /* Create symbolic link so user-mode can open \\.\K0Probe */
    st = IoCreateSymbolicLink(&g_SymlinkName, &g_DeviceName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(g_DeviceObject);
        return st;
    }

    /* Set up dispatch table */
    drv->DriverUnload                          = DriverUnload;
    drv->MajorFunction[IRP_MJ_CREATE]          = DispatchCreate;
    drv->MajorFunction[IRP_MJ_CLOSE]           = DispatchClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = DispatchIoctl;

    /* Initialise spin locks */
    KeInitializeSpinLock(&g_EvtLock);
    KeInitializeSpinLock(&g_WatchLock);
    KeInitializeSpinLock(&g_SnapLock);

    /* Allocate snapshot buffers (NonPaged) */
    g_SnapBuf1 = ExAllocatePoolWithTag(NonPagedPool, SNAP_MAX_BYTES, DRIVER_TAG);
    g_SnapBuf2 = ExAllocatePoolWithTag(NonPagedPool, SNAP_MAX_BYTES, DRIVER_TAG);
    if (!g_SnapBuf1 || !g_SnapBuf2) {
        if (g_SnapBuf1) ExFreePoolWithTag(g_SnapBuf1, DRIVER_TAG);
        if (g_SnapBuf2) ExFreePoolWithTag(g_SnapBuf2, DRIVER_TAG);
        IoDeleteSymbolicLink(&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_SnapSize = SNAP_MAX_BYTES;

    /* Start the snapshot diff thread */
    KeInitializeEvent(&g_SnapStopEvent, NotificationEvent, FALSE);
    HANDLE hThread;
    OBJECT_ATTRIBUTES thrAttrs;
    InitializeObjectAttributes(&thrAttrs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
                         &thrAttrs, NULL, NULL, SnapThreadProc, NULL);
    ZwClose(hThread);

    /* Register thread creation notification for DR arming */
    PsSetCreateThreadNotifyRoutine(ThreadNotify);

    /* Use buffered I/O for the device */
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
