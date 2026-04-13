/*
 * dkid_memlive.c  -  Live memory debugging (Ring-0 kernel backend)
 *
 * When K0Probe driver is loaded:
 *   - Memory reads use MmCopyVirtualMemory (kernel, no PROCESS_VM_READ)
 *   - Hardware debug registers (DR0-DR3) provide true watchpoints
 *   - The kernel's snapshot diff thread posts K0_EVT_PAGE_CHANGE events
 *   - VA->PA translation and CR3 display are available
 *
 * When the driver is NOT loaded:
 *   - Falls back to user-mode ReadProcessMemory + polling snapshot diff
 */
#include "dkid.h"
#include "k0probe_iface.h"

/* -- Snapshot (user-mode fallback) -------------------------------- */
#define MEM_SNAPSHOT_MAX (256 * 1024)

static BYTE   g_snap[MEM_SNAPSHOT_MAX];
static BYTE   g_curr[MEM_SNAPSHOT_MAX];
static DWORD  g_snap_size  = 0;
static UINT64 g_snap_base  = 0;
static bool   g_snap_valid = false;

/* -- Kernel event drain buffer ------------------------------------- */
#define K0_DRAIN_MAX 512
static K0Event g_k0_drain[K0_DRAIN_MAX];

/* -- Active hardware watchpoints (user-visible) -------------------- */
#define MAX_UI_WATCHES 4
typedef struct LiveWatch {
    bool   active;
    UINT64 addr;
    DWORD  size;
    DWORD  access;
    DWORD  k0_id;
    char   label[64];
} LiveWatch;

static LiveWatch g_watches[MAX_UI_WATCHES];
static int       g_watch_count = 0;

LiveWatch *MemLiveGetWatches(int *count)
{
    *count = g_watch_count;
    return g_watches;
}

/* -- Event push ---------------------------------------------------- */
static void PushEvent(UINT64 addr, BYTE oldv, BYTE newv,
                      DWORD type, DWORD watch_id, const char *ctx_str)
{
    EnterCriticalSection(&g_mem_cs);
    if (g_mem_event_count >= MAX_MEM_EVENTS) {
        memmove(&g_mem_events[0], &g_mem_events[1],
                sizeof(g_mem_events[0]) * (MAX_MEM_EVENTS - 1));
        g_mem_event_count = MAX_MEM_EVENTS - 1;
    }
    MemEvent *ev   = &g_mem_events[g_mem_event_count++];
    ev->tick       = GetTickCount();
    ev->addr       = addr;
    ev->oldv       = oldv;
    ev->newv       = newv;
    ev->event_type = type;
    ev->watch_id   = watch_id;
    if (ctx_str)
        strncpy(ev->context, ctx_str, sizeof(ev->context) - 1);
    else
        ev->context[0] = 0;
    LeaveCriticalSection(&g_mem_cs);
}

/* -- Public lifecycle ---------------------------------------------- */
void MemLiveClear(void)
{
    EnterCriticalSection(&g_mem_cs);
    g_mem_event_count = 0;
    LeaveCriticalSection(&g_mem_cs);
}

void MemLiveReset(void)
{
    g_snap_valid = false;
    g_snap_size  = 0;
    g_snap_base  = 0;
    MemLiveClear();
    if (K0IsAvailable()) {
        for (int i = 0; i < MAX_UI_WATCHES; i++) {
            if (g_watches[i].active) {
                K0WatchRemove(g_watches[i].k0_id);
                g_watches[i].active = false;
            }
        }
        g_watch_count = 0;
        K0FlushEvents();
    }
}

/* -- Watchpoint management ----------------------------------------- */
bool MemLiveWatchAdd(UINT64 addr, DWORD size, DWORD access, const char *label)
{
    int slot = -1;
    for (int i = 0; i < MAX_UI_WATCHES; i++)
        if (!g_watches[i].active) { slot = i; break; }
    if (slot < 0) {
        Log(IDA_RED, "[K0] No free watchpoint slots (max %d)", MAX_UI_WATCHES);
        return false;
    }
    DWORD k0id = 0;
    if (K0IsAvailable()) {
        if (!K0WatchAdd(g_target_pid, addr, size, access, &k0id)) {
            Log(IDA_RED, "[K0] WatchAdd failed for 0x%llX", (unsigned long long)addr);
            return false;
        }
    } else {
        Log(IDA_YELLOW, "[K0] Driver not loaded - watchpoint recorded but not armed in HW");
    }
    g_watches[slot].active = true;
    g_watches[slot].addr   = addr;
    g_watches[slot].size   = size;
    g_watches[slot].access = access;
    g_watches[slot].k0_id  = k0id;
    strncpy(g_watches[slot].label, label ? label : "watch",
            sizeof(g_watches[slot].label) - 1);
    if (slot >= g_watch_count) g_watch_count = slot + 1;
    Log(IDA_GREEN, "[K0] Watch[%d] #%u  0x%016llX  sz=%u  %s%s%s",
        slot, k0id, (unsigned long long)addr, size,
        (access & K0_WATCH_READ)  ? "R" : "",
        (access & K0_WATCH_WRITE) ? "W" : "",
        (access & K0_WATCH_EXEC)  ? "X" : "");
    return true;
}

bool MemLiveWatchRemove(int slot)
{
    if (slot < 0 || slot >= MAX_UI_WATCHES || !g_watches[slot].active)
        return false;
    if (K0IsAvailable() && g_watches[slot].k0_id)
        K0WatchRemove(g_watches[slot].k0_id);
    g_watches[slot].active = false;
    Log(IDA_YELLOW, "[K0] Watch[%d] removed", slot);
    g_watch_count = 0;
    for (int i = MAX_UI_WATCHES - 1; i >= 0; i--)
        if (g_watches[i].active) { g_watch_count = i + 1; break; }
    return true;
}

/* -- Main tick ----------------------------------------------------- */
void MemLiveTick(void)
{
    if (!g_mem_live_enabled) return;
    if (!g_attached || !g_target || !g_dll_base || g_dll_size == 0) {
        MemLiveReset();
        return;
    }

    /* Path A: kernel driver */
    if (K0IsAvailable()) {
        int n = K0PollEvents(g_k0_drain, K0_DRAIN_MAX);
        for (int i = 0; i < n; i++) {
            K0Event *ke = &g_k0_drain[i];
            if (ke->pid != 0 && ke->pid != g_target_pid) continue;
            BYTE oldv = (BYTE)(ke->old_value & 0xFF);
            BYTE newv = (BYTE)(ke->new_value & 0xFF);
            PushEvent(ke->address, oldv, newv,
                      ke->event_type, ke->watch_id,
                      ke->context[0] ? ke->context : NULL);
        }
        return;
    }

    /* Path B: user-mode fallback */
    DWORD want = g_dll_size;
    if (want > MEM_SNAPSHOT_MAX) want = MEM_SNAPSHOT_MAX;
    if (want == 0) return;
    SIZE_T got = 0;
    if (!ReadProcessMemory(g_target, (LPCVOID)(uintptr_t)g_dll_base,
                           g_curr, want, &got) || got == 0) return;
    DWORD take = (DWORD)got;
    if (!g_snap_valid || g_snap_base != g_dll_base || g_snap_size != take) {
        memcpy(g_snap, g_curr, take);
        g_snap_size  = take;
        g_snap_base  = g_dll_base;
        g_snap_valid = true;
        return;
    }
    for (DWORD i = 0; i < take; i++) {
        if (g_snap[i] != g_curr[i]) {
            PushEvent(g_snap_base + i, g_snap[i], g_curr[i],
                      K0_EVT_PAGE_CHANGE, 0, NULL);
            g_snap[i] = g_curr[i];
        }
    }
}
