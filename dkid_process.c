/* dkid_process.c - process/module management */
#include "dkid.h"

/* -- ProcRefresh --------------------------------------------------- */
void ProcRefresh(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Log(IDA_YELLOW, "[!] Toolhelp snapshot failed (%lu), trying PSAPI fallback", (unsigned long)err);

        /* Fallback: enumerate PIDs via PSAPI and resolve image names where possible. */
        DWORD pids[8192] = {0};
        DWORD needed = 0;
        g_proc_count = 0;

        if (!EnumProcesses(pids, sizeof(pids), &needed)) {
            Log(IDA_RED, "[!] EnumProcesses failed (%lu)", (unsigned long)GetLastError());
            g_proc_sel = -1;
            snprintf(g_status, sizeof(g_status), "Processes: 0");
            return;
        }

        int count = (int)(needed / sizeof(DWORD));
        for (int i = 0; i < count; i++) {
            DWORD pid = pids[i];
            if (pid == 0 || pid == 4) continue;
            if (g_proc_count >= 4096) break;

            g_procs[g_proc_count].pid = pid;
            strncpy(g_procs[g_proc_count].name, "<unknown>", MAX_PATH - 1);

            HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (p) {
                HMODULE mod = NULL;
                DWORD cbNeeded = 0;
                if (EnumProcessModulesEx(p, &mod, sizeof(mod), &cbNeeded, LIST_MODULES_ALL) && mod) {
                    GetModuleBaseNameA(p, mod, g_procs[g_proc_count].name, MAX_PATH - 1);
                }
                CloseHandle(p);
            }
            g_proc_count++;
        }

        for (int i=0;i<g_proc_count-1;i++)
            for (int j=i+1;j<g_proc_count;j++)
                if (_stricmp(g_procs[i].name,g_procs[j].name)>0) {
                    ProcInfo tmp=g_procs[i]; g_procs[i]=g_procs[j]; g_procs[j]=tmp;
                }

        g_proc_sel = (g_proc_count > 0) ? 0 : -1;
        snprintf(g_status, sizeof(g_status), "Processes: %d", g_proc_count);
        Log(IDA_TEXT2, "[i] Refreshed (fallback): %d processes", g_proc_count);
        return;
    }

    g_proc_count = 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) do {
        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
        g_procs[g_proc_count].pid = pe.th32ProcessID;
        strncpy(g_procs[g_proc_count].name, pe.szExeFile, MAX_PATH-1);
        if (++g_proc_count >= 4096) break;
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);

    /* sort by name */
    for (int i=0;i<g_proc_count-1;i++)
        for (int j=i+1;j<g_proc_count;j++)
            if (_stricmp(g_procs[i].name,g_procs[j].name)>0) {
                ProcInfo tmp=g_procs[i]; g_procs[i]=g_procs[j]; g_procs[j]=tmp;
            }

    /* Keep attach UX simple: select the first entry after every refresh. */
    g_proc_sel = (g_proc_count > 0) ? 0 : -1;

    snprintf(g_status, sizeof(g_status), "Processes: %d", g_proc_count);
    Log(IDA_TEXT2, "[i] Refreshed: %d processes", g_proc_count);
}

/* -- ProcAttach ---------------------------------------------------- */
void ProcAttach(DWORD pid)
{
    ProcDetach();

    g_target_pid = pid;
    for (int i = 0; i < g_proc_count; i++)
        if (g_procs[i].pid == pid) {
            strncpy(g_target_name, g_procs[i].name, MAX_PATH-1);
            break;
        }

    g_target = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
        FALSE, pid);

    if (!g_target) {
        Log(IDA_RED, "[!] OpenProcess failed for PID %lu - run as Administrator",
            (unsigned long)pid);
        g_target_pid = 0;
        return;
    }

    g_attached = true;
    Log(IDA_GREEN, "[+] Attached: %s  [PID %lu]",
        g_target_name, (unsigned long)pid);
    snprintf(g_status, sizeof(g_status),
             "Attached: %s [PID %lu]", g_target_name, (unsigned long)pid);

    /* Inform the ring-0 driver which process is our target */
    if (K0IsAvailable()) {
        K0SetTarget(pid);
        UINT64 cr3 = 0;
        if (K0GetCR3(&cr3))
            Log(IDA_ACCENT2, "[K0] CR3=0x%016llX  (kernel PD of current process)",
                (unsigned long long)cr3);
    }

    ModRefresh();
    if (g_mod_count > 0) ModAnalyze(0);

    /* auto-scan AES */
    AESScanLaunch();
}

/* -- ProcDetach ---------------------------------------------------- */
void ProcDetach(void)
{
    if (g_target) {
        CloseHandle(g_target);
        g_target = NULL;
    }
    /* Tell the kernel driver to stop tracking */
    if (K0IsAvailable()) K0SetTarget(0);
    g_attached    = false;
    g_dll_base    = 0;
    g_dll_size    = 0;
    g_dll_name[0] = 0;
    g_target_pid  = 0;
    g_target_name[0] = 0;
    g_mod_count   = 0;
    g_mod_sel     = -1;
    g_sec_count   = 0;
    g_imp_count   = 0;
    g_exp_count   = 0;
    g_disasm_count = 0;
    MemLiveReset();
    HexFree();
    strncpy(g_status,"Detached",sizeof(g_status));
    Log(IDA_YELLOW, "[*] Detached");
}

static void ModRefreshCore(bool noisy)
{
    if (!g_target) return;

    UINT64 prev_base = g_dll_base;
    HMODULE mods[MAX_MODULES];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(g_target, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return;

    g_mod_count = (int)(needed / sizeof(HMODULE));
    if (g_mod_count > MAX_MODULES) g_mod_count = MAX_MODULES;

    for (int i = 0; i < g_mod_count; i++) {
        MODULEINFO mi = {0};
        GetModuleInformation(g_target, mods[i], &mi, sizeof(mi));
        g_mods[i].h    = mods[i];
        g_mods[i].base = (UINT64)(uintptr_t)mods[i];
        g_mods[i].size = mi.SizeOfImage;
        GetModuleBaseNameA(g_target, mods[i], g_mods[i].name, MAX_PATH-1);
    }

    /* Keep selected module stable across live refreshes. */
    int keep_idx = -1;
    if (prev_base) {
        for (int i = 0; i < g_mod_count; i++) {
            if (g_mods[i].base == prev_base) { keep_idx = i; break; }
        }
    }
    if (keep_idx < 0 && g_mod_count > 0) keep_idx = 0;

    g_mod_sel = keep_idx;
    if (keep_idx >= 0) {
        g_dll_base = g_mods[keep_idx].base;
        g_dll_size = g_mods[keep_idx].size;
        strncpy(g_dll_name, g_mods[keep_idx].name, MAX_PATH - 1);
    }

    if (noisy) Log(IDA_TEXT2, "[i] %d modules loaded", g_mod_count);
}

/* -- ModRefresh ---------------------------------------------------- */
void ModRefresh(void)
{
    ModRefreshCore(true);
}

void ModRefreshLive(void)
{
    ModRefreshCore(false);
}

/* -- ModAnalyze ---------------------------------------------------- */
void ModAnalyze(int idx)
{
    if (idx < 0 || idx >= g_mod_count) return;
    g_dll_base = g_mods[idx].base;
    g_dll_size = g_mods[idx].size;
    strncpy(g_dll_name, g_mods[idx].name, MAX_PATH-1);

    Log(IDA_ACCENT, "-- Module: %s  base=0x%llX  size=0x%lX --",
        g_dll_name, (unsigned long long)g_dll_base, (unsigned long)g_dll_size);

    PEAnalyze();
    HexLoad(g_dll_base, min(g_dll_size, 4096));
    MemLiveReset();
    snprintf(g_status, sizeof(g_status), "%s | base: 0x%llX | %lu KB",
             g_dll_name, (unsigned long long)g_dll_base,
             (unsigned long)(g_dll_size/1024));
}
