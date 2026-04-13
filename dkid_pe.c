/* dkid_pe.c - PE header analysis: sections, imports, exports */
#include "dkid.h"

/* -- helpers ------------------------------------------------------- */
static bool rpm(LPCVOID addr, void *buf, SIZE_T sz)
{
    SIZE_T got = 0;
    return ReadProcessMemory(g_target, addr, buf, sz, &got) && got > 0;
}

static const char *prot_str(DWORD p)
{
    p &= ~(PAGE_GUARD|PAGE_NOCACHE|PAGE_WRITECOMBINE);
    switch (p) {
    case PAGE_READONLY:          return "R  ";
    case PAGE_READWRITE:         return "RW ";
    case PAGE_WRITECOPY:         return "WC ";
    case PAGE_EXECUTE:           return "  X";
    case PAGE_EXECUTE_READ:      return "R X";
    case PAGE_EXECUTE_READWRITE: return "RWX";
    case PAGE_EXECUTE_WRITECOPY: return "WCX";
    case PAGE_NOACCESS:          return "---";
    default:                     return "???";
    }
}

/* -- PEAnalyze ----------------------------------------------------- */
void PEAnalyze(void)
{
    if (!g_target || !g_dll_base) return;

    g_sec_count = 0;
    g_imp_count = 0;
    g_exp_count = 0;

    SIZE_T rd = 0;

    /* DOS header */
    IMAGE_DOS_HEADER dos = {0};
    if (!rpm((LPCVOID)(uintptr_t)g_dll_base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        Log(IDA_RED,"[!] Invalid DOS signature");
        return;
    }

    /* NT headers */
    IMAGE_NT_HEADERS64 nth = {0};
    if (!rpm((LPCVOID)(uintptr_t)(g_dll_base+dos.e_lfanew), &nth, sizeof(nth))) {
        Log(IDA_RED,"[!] Cannot read NT headers"); return;
    }
    if (nth.Signature != IMAGE_NT_SIGNATURE) {
        Log(IDA_RED,"[!] Invalid PE signature"); return;
    }

    bool is64 = nth.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    Log(IDA_ACCENT2, "[PE] %s  Machine=0x%04X  %s  EP=0x%llX",
        g_dll_name,
        nth.FileHeader.Machine,
        is64 ? "x64" : "x86",
        (unsigned long long)(g_dll_base + nth.OptionalHeader.AddressOfEntryPoint));

    /* -- sections --------------------------------------------------- */
    UINT64 sh_base = g_dll_base + dos.e_lfanew + sizeof(nth);
    int ns = nth.FileHeader.NumberOfSections;
    if (ns > 64) ns = 64;

    for (int i = 0; i < ns; i++) {
        IMAGE_SECTION_HEADER sh = {0};
        if (!rpm((LPCVOID)(uintptr_t)(sh_base + i*sizeof(sh)), &sh, sizeof(sh))) break;
        SectionEntry *se = &g_sections[g_sec_count++];
        memset(se->name, 0, sizeof(se->name));
        memcpy(se->name, sh.Name, 8);
        se->va    = g_dll_base + sh.VirtualAddress;
        se->raw   = sh.PointerToRawData;
        se->vsize = sh.Misc.VirtualSize;
        se->chars = sh.Characteristics;
    }
    Log(IDA_TEXT2, "[PE] %d sections", g_sec_count);

    /* -- exports ---------------------------------------------------- */
    IMAGE_DATA_DIRECTORY *exp_dir =
        &nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->VirtualAddress) {
        IMAGE_EXPORT_DIRECTORY ed = {0};
        UINT64 exp_va = g_dll_base + exp_dir->VirtualAddress;
        if (rpm((LPCVOID)(uintptr_t)exp_va, &ed, sizeof(ed))) {
            DWORD *names  = (DWORD*)malloc(ed.NumberOfNames * 4);
            WORD  *ords   = (WORD *)malloc(ed.NumberOfNames * 2);
            DWORD *funcs  = (DWORD*)malloc(ed.NumberOfFunctions * 4);
            if (names&&ords&&funcs) {
                rpm((LPCVOID)(uintptr_t)(g_dll_base+ed.AddressOfNames),       names, ed.NumberOfNames*4);
                rpm((LPCVOID)(uintptr_t)(g_dll_base+ed.AddressOfNameOrdinals), ords,  ed.NumberOfNames*2);
                rpm((LPCVOID)(uintptr_t)(g_dll_base+ed.AddressOfFunctions),    funcs, ed.NumberOfFunctions*4);
                for (DWORD i = 0; i < ed.NumberOfNames && g_exp_count < 4095; i++) {
                    ExportEntry *e = &g_exports[g_exp_count++];
                    e->ordinal = ed.Base + ords[i];
                    e->va      = g_dll_base + funcs[ords[i]];
                    char tmp[256] = {0};
                    rpm((LPCVOID)(uintptr_t)(g_dll_base+names[i]), tmp, 127);
                    strncpy(e->name, tmp, 127);
                }
            }
            free(names); free(ords); free(funcs);
        }
        Log(IDA_TEXT2, "[PE] %d exports", g_exp_count);
    }

    /* -- imports ---------------------------------------------------- */
    IMAGE_DATA_DIRECTORY *imp_dir =
        &nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir->VirtualAddress) {
        UINT64 id_va = g_dll_base + imp_dir->VirtualAddress;
        for (;;) {
            IMAGE_IMPORT_DESCRIPTOR iid = {0};
            if (!rpm((LPCVOID)(uintptr_t)id_va, &iid, sizeof(iid))) break;
            if (!iid.OriginalFirstThunk && !iid.Name) break;

            char dll_name[MAX_PATH] = {0};
            rpm((LPCVOID)(uintptr_t)(g_dll_base+iid.Name), dll_name, MAX_PATH-1);

            UINT64 thunk_va = g_dll_base + iid.OriginalFirstThunk;
            UINT64 iat_va   = g_dll_base + iid.FirstThunk;
            for (;;) {
                UINT64 thunk = 0;
                if (!rpm((LPCVOID)(uintptr_t)thunk_va, &thunk, 8)) break;
                if (!thunk) break;
                if (g_imp_count >= MAX_IAT) break;

                ImportEntry *ie = &g_imports[g_imp_count++];
                strncpy(ie->dll, dll_name, MAX_PATH-1);
                ie->iat_va = iat_va;

                if (thunk & 0x8000000000000000ULL) {
                    /* ordinal import */
                    snprintf(ie->name, 128, "ord%llu", (unsigned long long)(thunk & 0xFFFF));
                } else {
                    /* named */
                    char n[128] = {0};
                    rpm((LPCVOID)(uintptr_t)(g_dll_base + (thunk & 0x7FFFFFFF) + 2), n, 127);
                    strncpy(ie->name, n, 127);
                }
                ie->va = iat_va;
                thunk_va += 8; iat_va += 8;
            }
            id_va += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
        Log(IDA_TEXT2, "[PE] %d imports from IAT", g_imp_count);
    }
}

/* -- PEDumpLog ----------------------------------------------------- */
void PEDumpLog(void)
{
    PEAnalyze();
    Log(IDA_ACCENT2,"== PE Analysis: %s ==", g_dll_name);
    Log(IDA_TEXT2,  "  Base:     0x%016llX", (unsigned long long)g_dll_base);
    Log(IDA_TEXT2,  "  Size:     0x%08lX (%lu KB)",
        (unsigned long)g_dll_size, (unsigned long)(g_dll_size/1024));
    Log(IDA_TEXT2,  "  Sections: %d", g_sec_count);
    for (int i = 0; i < g_sec_count; i++)
        Log(IDA_TEXT3, "    %-8s  VA=0x%llX  VSize=0x%lX  Chars=0x%08lX",
            g_sections[i].name,
            (unsigned long long)g_sections[i].va,
            (unsigned long)g_sections[i].vsize,
            (unsigned long)g_sections[i].chars);
    Log(IDA_TEXT2,"  Exports: %d", g_exp_count);
    Log(IDA_TEXT2,"  Imports: %d", g_imp_count);

    /* memory map */
    Log(IDA_ACCENT2,"-- Memory Map --");
    SYSTEM_INFO si={0}; GetSystemInfo(&si);
    UINT64 addr=(UINT64)(uintptr_t)si.lpMinimumApplicationAddress;
    UINT64 amax=(UINT64)(uintptr_t)si.lpMaximumApplicationAddress;
    int regions=0;
    while(addr<amax && regions<64){
        MEMORY_BASIC_INFORMATION mbi={0};
        if(!VirtualQueryEx(g_target,(LPCVOID)(uintptr_t)addr,&mbi,sizeof(mbi)))break;
        if(!mbi.RegionSize)break;
        if(mbi.State==MEM_COMMIT){
            const char *type=mbi.Type==MEM_IMAGE?"IMG":mbi.Type==MEM_MAPPED?"MAP":"PRV";
            Log(IDA_TEXT2,"  0x%016llX  %6lluK  %s  %s",
                (unsigned long long)mbi.BaseAddress,
                (unsigned long long)(mbi.RegionSize/1024),
                type, prot_str(mbi.Protect));
            regions++;
        }
        addr=(UINT64)(uintptr_t)mbi.BaseAddress+mbi.RegionSize;
    }
    if(regions==64) Log(IDA_TEXT2,"  ... (truncated)");
}
