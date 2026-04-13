/* dkid_strings.c - find printable ASCII/UTF-16 strings in process memory */
#include "dkid.h"

#define MIN_STR_LEN 5

static DWORD WINAPI StringThread(LPVOID param)
{
    HANDLE proc = (HANDLE)param;
    int found = 0;

    Log(IDA_ACCENT, "+=== Strings scan started ===");

    SYSTEM_INFO si={0}; GetSystemInfo(&si);
    UINT64 amin=(UINT64)(uintptr_t)si.lpMinimumApplicationAddress;
    UINT64 amax=(UINT64)(uintptr_t)si.lpMaximumApplicationAddress;

    EnterCriticalSection(&g_str_cs);
    g_str_count = 0;
    LeaveCriticalSection(&g_str_cs);

    SIZE_T bsz = 256*1024;
    BYTE *buf = (BYTE*)malloc(bsz);
    if (!buf) goto done;

    UINT64 addr = amin;
    while (addr < amax) {
        MEMORY_BASIC_INFORMATION mbi={0};
        if (!VirtualQueryEx(proc,(LPCVOID)(uintptr_t)addr,&mbi,sizeof(mbi))) break;
        if (!mbi.RegionSize) break;

        DWORD raw = mbi.Protect & ~(PAGE_GUARD|PAGE_NOCACHE|PAGE_WRITECOMBINE);
        bool readable = mbi.State==MEM_COMMIT && (
            raw==PAGE_READONLY||raw==PAGE_READWRITE||
            raw==PAGE_EXECUTE_READ||raw==PAGE_EXECUTE_READWRITE);

        if (readable && mbi.RegionSize <= 8*1024*1024) {
            UINT64 rb = (UINT64)(uintptr_t)mbi.BaseAddress;
            SIZE_T to  = mbi.RegionSize < bsz ? mbi.RegionSize : bsz;
            SIZE_T got = 0;
            if (ReadProcessMemory(proc,(LPCVOID)(uintptr_t)rb, buf, to, &got) && got > 0) {

                /* ASCII strings */
                SIZE_T i = 0;
                while (i < got) {
                    if (buf[i] >= 0x20 && buf[i] < 0x7F) {
                        SIZE_T j = i;
                        while (j < got && buf[j] >= 0x20 && buf[j] < 0x7F) j++;
                        SIZE_T slen = j - i;
                        if (slen >= MIN_STR_LEN) {
                            EnterCriticalSection(&g_str_cs);
                            if (g_str_count < MAX_STRINGS) {
                                FoundString *fs = &g_strings[g_str_count++];
                                fs->addr = rb + i;
                                fs->wide = false;
                                SIZE_T cp = slen < 255 ? slen : 255;
                                memcpy(fs->text, buf+i, cp);
                                fs->text[cp] = 0;
                                fs->len = (int)cp;
                                found++;
                            }
                            LeaveCriticalSection(&g_str_cs);
                        }
                        i = j;
                    } else {
                        i++;
                    }
                }

                /* UTF-16LE strings */
                i = 0;
                while (i + 2 <= got) {
                    WCHAR *wp = (WCHAR*)(buf + i);
                    if (*wp >= 0x0020 && *wp < 0x007F) {
                        SIZE_T j = i;
                        while (j + 2 <= got) {
                            WCHAR c = *(WCHAR*)(buf+j);
                            if (c < 0x0020 || c >= 0x007F) break;
                            j += 2;
                        }
                        SIZE_T wlen = (j - i) / 2;
                        if (wlen >= MIN_STR_LEN) {
                            EnterCriticalSection(&g_str_cs);
                            if (g_str_count < MAX_STRINGS) {
                                FoundString *fs = &g_strings[g_str_count++];
                                fs->addr = rb + i;
                                fs->wide = true;
                                SIZE_T cp = wlen < 127 ? wlen : 127;
                                for (SIZE_T k=0; k<cp; k++)
                                    fs->text[k] = (char)((WCHAR*)(buf+i))[k];
                                fs->text[cp] = 0;
                                fs->len = (int)cp;
                                found++;
                            }
                            LeaveCriticalSection(&g_str_cs);
                        }
                        i = j;
                    } else {
                        i += 2;
                    }
                }
            }
        }
        addr = (UINT64)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    free(buf);
done:
    g_str_scan_running = false;
    Log(g_str_count ? IDA_GREEN : IDA_YELLOW,
        "+=== Strings scan done: %d strings", found);
    return 0;
}

void StringsScanLaunch(void)
{
    if (!g_target) { Log(IDA_RED,"[!] No process attached"); return; }
    if (g_str_scan_running) { Log(IDA_YELLOW,"[!] Strings scan already running"); return; }
    g_str_scan_running = true;
    HANDLE th = CreateThread(NULL, 0, StringThread, (LPVOID)g_target, 0, NULL);
    if (th) CloseHandle(th);
    else    g_str_scan_running = false;
}
