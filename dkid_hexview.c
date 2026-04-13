/* dkid_hexview.c - hex view state: load bytes from target process */
#include "dkid.h"

void HexLoad(UINT64 addr, SIZE_T size)
{
    if (!g_target) return;
    if (size == 0 || size > 4*1024*1024) size = 4096;

    HexFree();
    g_hex.data = (BYTE*)malloc(size);
    if (!g_hex.data) return;

    SIZE_T got = 0;
    ReadProcessMemory(g_target, (LPCVOID)(uintptr_t)addr, g_hex.data, size, &got);

    g_hex.base      = addr;
    g_hex.size      = got;
    g_hex.loaded    = (got > 0);
    g_hex.cursor    = 0;
    g_hex.sel_start = 0;
    g_hex.sel_end   = 0;

    if (got) {
        Log(IDA_TEXT2, "[hex] Loaded 0x%llX  sz=0x%llX",
            (unsigned long long)addr, (unsigned long long)got);
        g_main_tab = 1;   /* switch to hex view */
    } else {
        Log(IDA_RED,"[hex] ReadProcessMemory failed at 0x%llX",(unsigned long long)addr);
    }
}

void HexFree(void)
{
    free(g_hex.data);
    memset(&g_hex, 0, sizeof(g_hex));
}
