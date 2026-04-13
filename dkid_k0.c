/*
 * dkid_k0.c  -  User-mode bridge to the K0Probe kernel driver
 *
 * Opens \\.\K0Probe, issues IOCTLs, and exposes a clean API to the
 * rest of DKID.  Falls back gracefully to user-mode RPM if the
 * driver is not loaded.
 *
 * Public API (declared in dkid.h):
 *   bool   K0Init(void)
 *   void   K0Shutdown(void)
 *   bool   K0IsAvailable(void)
 *   bool   K0SetTarget(DWORD pid)
 *   bool   K0ReadMem(DWORD pid, UINT64 addr, void *buf, DWORD size)
 *   bool   K0WriteMem(DWORD pid, UINT64 addr, const void *buf, DWORD size)
 *   int    K0QueryRegions(DWORD pid, UINT64 start, K0Region *out, int max)
 *   bool   K0WatchAdd(DWORD pid, UINT64 addr, DWORD size, DWORD access, DWORD *id)
 *   bool   K0WatchRemove(DWORD id)
 *   int    K0PollEvents(K0Event *out, int max)
 *   void   K0FlushEvents(void)
 *   bool   K0GetPhysAddr(DWORD pid, UINT64 va, UINT64 *pa)
 *   bool   K0GetCR3(UINT64 *cr3)
 *   void   K0SetSnapBase(UINT64 base, DWORD size)  -- configure snap region
 */
#include "dkid.h"
#include "k0probe_iface.h"

/* -- Internal state ----------------------------------------------- */
static HANDLE g_K0Dev    = INVALID_HANDLE_VALUE;
static bool   g_K0Ready  = false;

/* -- Internal helper ----------------------------------------------- */
static bool K0Ioctl(DWORD code,
                    const void *inBuf,  DWORD inLen,
                    void       *outBuf, DWORD outLen,
                    DWORD      *pReturned)
{
    if (g_K0Dev == INVALID_HANDLE_VALUE) return false;
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(g_K0Dev, code,
                              (LPVOID)inBuf, inLen,
                              outBuf, outLen,
                              &ret, NULL);
    if (pReturned) *pReturned = ret;
    return ok != 0;
}

/* -- Lifecycle ----------------------------------------------------- */
bool K0Init(void)
{
    if (g_K0Ready) return true;

    g_K0Dev = CreateFileA(
        K0PROBE_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_K0Dev == INVALID_HANDLE_VALUE) {
        Log(IDA_YELLOW, "[K0] Driver not loaded - using user-mode fallback"
                        "  (run as Admin, then: sc start K0Probe)");
        return false;
    }

    g_K0Ready = true;
    Log(IDA_GREEN, "[K0] Ring-0 driver connected  (K0Probe v3.0)");
    return true;
}

void K0Shutdown(void)
{
    if (g_K0Dev != INVALID_HANDLE_VALUE) {
        CloseHandle(g_K0Dev);
        g_K0Dev  = INVALID_HANDLE_VALUE;
        g_K0Ready = false;
    }
}

bool K0IsAvailable(void) { return g_K0Ready; }

/* -- Target PID ---------------------------------------------------- */
bool K0SetTarget(DWORD pid)
{
    return K0Ioctl(IOCTL_K0_SET_TARGET_PID,
                   &pid, sizeof(pid), NULL, 0, NULL);
}

/* -- Memory read --------------------------------------------------- */
bool K0ReadMem(DWORD pid, UINT64 addr, void *buf, DWORD size)
{
    if (!g_K0Ready) {
        /* Fall back to user-mode ReadProcessMemory */
        if (!g_target) return false;
        SIZE_T got = 0;
        return ReadProcessMemory(g_target,
                                 (LPCVOID)(uintptr_t)addr,
                                 buf, size, &got) && got > 0;
    }

    /* May need multiple IOCTLs for large reads */
    DWORD offset = 0;
    while (offset < size) {
        DWORD chunk = min(size - offset, K0_MAX_READ_BYTES);

        /* Build request in a stack buffer or heap for large chunks */
        K0ReadReq req;
        req.target_pid = pid;
        req.address    = addr + offset;
        req.size       = chunk;
        req.flags      = 0;

        DWORD returned = 0;
        BOOL ok = DeviceIoControl(g_K0Dev, IOCTL_K0_READ_MEM,
                                  &req, sizeof(req),
                                  (BYTE*)buf + offset, chunk,
                                  &returned, NULL);
        if (!ok || returned == 0) return false;
        offset += returned;
    }
    return true;
}

/* -- Memory write -------------------------------------------------- */
bool K0WriteMem(DWORD pid, UINT64 addr, const void *data, DWORD size)
{
    if (!g_K0Ready) return false;
    if (size > K0_MAX_READ_BYTES) return false;

    /* Allocate combined request + data buffer */
    DWORD totalIn = (DWORD)sizeof(K0WriteReq) + size;
    BYTE *buf = (BYTE*)malloc(totalIn);
    if (!buf) return false;

    K0WriteReq *req = (K0WriteReq*)buf;
    req->target_pid = pid;
    req->address    = addr;
    req->size       = size;
    req->flags      = 0;
    memcpy(buf + sizeof(K0WriteReq), data, size);

    bool ok = K0Ioctl(IOCTL_K0_WRITE_MEM, buf, totalIn, NULL, 0, NULL);
    free(buf);
    return ok;
}

/* -- Region query -------------------------------------------------- */
int K0QueryRegions(DWORD pid, UINT64 start, K0Region *out, int max)
{
    if (!g_K0Ready || max <= 0) return 0;

    K0RegionReq req;
    req.target_pid  = pid;
    req.start_va    = start;
    req.max_regions = (DWORD)min(max, K0_MAX_REGIONS);
    req.flags       = 0;

    DWORD returned = 0;
    if (!K0Ioctl(IOCTL_K0_QUERY_REGIONS,
                 &req, sizeof(req),
                 out, (DWORD)(sizeof(K0Region) * (DWORD)max),
                 &returned))
        return 0;

    return (int)(returned / sizeof(K0Region));
}

/* -- Hardware watchpoints ------------------------------------------- */
bool K0WatchAdd(DWORD pid, UINT64 addr, DWORD size, DWORD access, DWORD *id)
{
    if (!g_K0Ready) return false;

    K0WatchReq req;
    req.target_pid = pid;
    req.address    = addr;
    req.size       = size;
    req.access     = access;

    K0WatchId out = {0};
    DWORD returned = 0;
    if (!K0Ioctl(IOCTL_K0_WATCH_ADD,
                 &req, sizeof(req),
                 &out, sizeof(out), &returned))
        return false;

    if (id) *id = out.watch_id;
    Log(IDA_ACCENT2, "[K0] Watchpoint #%u  0x%016llX  sz=%u  acc=0x%X",
        out.watch_id, (unsigned long long)addr, size, access);
    return true;
}

bool K0WatchRemove(DWORD id)
{
    if (!g_K0Ready) return false;
    K0WatchId req = { id, 0 };
    bool ok = K0Ioctl(IOCTL_K0_WATCH_REMOVE,
                      &req, sizeof(req), NULL, 0, NULL);
    if (ok) Log(IDA_YELLOW, "[K0] Watchpoint #%u removed", id);
    return ok;
}

/* -- Event poll ---------------------------------------------------- */
int K0PollEvents(K0Event *out, int max)
{
    if (!g_K0Ready || max <= 0) return 0;
    DWORD returned = 0;
    if (!K0Ioctl(IOCTL_K0_POLL_EVENTS,
                 NULL, 0,
                 out, (DWORD)(sizeof(K0Event) * (DWORD)max),
                 &returned))
        return 0;
    return (int)(returned / sizeof(K0Event));
}

void K0FlushEvents(void)
{
    K0Ioctl(IOCTL_K0_FLUSH_EVENTS, NULL, 0, NULL, 0, NULL);
}

/* -- Physical address translation ---------------------------------- */
bool K0GetPhysAddr(DWORD pid, UINT64 va, UINT64 *pa)
{
    if (!g_K0Ready || !pa) return false;
    K0VaToPa req = { pid, va };
    DWORD returned = 0;
    return K0Ioctl(IOCTL_K0_GET_PHYS_ADDR,
                   &req, sizeof(req),
                   pa, sizeof(*pa), &returned)
           && returned == sizeof(*pa);
}

/* -- CR3 read ------------------------------------------------------ */
bool K0GetCR3(UINT64 *cr3)
{
    if (!g_K0Ready || !cr3) return false;
    DWORD returned = 0;
    return K0Ioctl(IOCTL_K0_GET_CR3,
                   NULL, 0,
                   cr3, sizeof(*cr3), &returned)
           && returned == sizeof(*cr3);
}
