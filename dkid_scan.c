/*
 * dkid_scan.c - AES-256 key candidate scanner
 * Auto-launched on process attach; runs in a background thread.
 */
#include "dkid.h"

/* -- CalcEntropy --------------------------------------------------- */
double CalcEntropy(const BYTE *d, int n)
{
    if (!d || n <= 0) return 0.0;
    int f[256] = {0};
    for (int i = 0; i < n; i++) f[d[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++)
        if (f[i] > 0) { double p=(double)f[i]/n; e -= p*log(p)/log(2.0); }
    return e;
}

/* -- IsKeyLike ----------------------------------------------------- */
bool IsKeyLike(const BYTE *d)
{
    if (!d) return false;
    int seen[256]={0}, unique=0, printable=0, zeros=0;
    for (int i = 0; i < KEY_SIZE; i++) {
        if (!seen[d[i]]) { seen[d[i]]=1; unique++; }
        if (d[i] >= 0x20 && d[i] < 0x7F) printable++;
        if (d[i] == 0) zeros++;
    }
    if (zeros > 6 || unique < MIN_UNIQUE || printable > 28) return false;
    return CalcEntropy(d, KEY_SIZE) >= MIN_ENTROPY;
}

/* -- scan thread --------------------------------------------------- */
static DWORD WINAPI ScanThread(LPVOID param)
{
    HANDLE proc = (HANDLE)param;
    int hits = 0;
    UINT64 bytes_scanned = 0;

    Log(IDA_ACCENT, "+=== AES-256 Key Scan started ===");

    SYSTEM_INFO si = {0}; GetSystemInfo(&si);
    UINT64 amin = (UINT64)(uintptr_t)si.lpMinimumApplicationAddress;
    UINT64 amax = (UINT64)(uintptr_t)si.lpMaximumApplicationAddress;

    SIZE_T bsz = 256*1024;
    BYTE *buf  = (BYTE*)malloc(bsz + KEY_SIZE);
    if (!buf) goto done;

    BYTE overlap[KEY_SIZE] = {0};
    int  ov_len = 0;
    UINT64 addr = amin;

    while (addr < amax) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        if (!VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) break;
        if (!mbi.RegionSize) break;

        DWORD raw = mbi.Protect & ~(PAGE_GUARD|PAGE_NOCACHE|PAGE_WRITECOMBINE);
        bool readable = (mbi.State == MEM_COMMIT) && (
            raw == PAGE_READONLY || raw == PAGE_READWRITE ||
            raw == PAGE_EXECUTE_READ || raw == PAGE_EXECUTE_READWRITE);

        if (readable) {
            UINT64 rb = (UINT64)(uintptr_t)mbi.BaseAddress;
            ov_len = 0;
            const char *type_s = mbi.Type==MEM_IMAGE?"IMG":mbi.Type==MEM_MAPPED?"MAP":"PRV";

            for (UINT64 off = 0; off < mbi.RegionSize; off += bsz) {
                SIZE_T chunk = bsz;
                if (off + chunk > mbi.RegionSize) chunk = mbi.RegionSize - off;

                memcpy(buf, overlap, ov_len);
                SIZE_T got = 0;
                if (!ReadProcessMemory(proc, (LPCVOID)(uintptr_t)(rb+off),
                                       buf+ov_len, chunk, &got) || !got) {
                    ov_len = 0; continue;
                }
                SIZE_T total = got + ov_len;
                bytes_scanned += got;

                for (SIZE_T i = 0; i + KEY_SIZE <= total; i++) {
                    if (!IsKeyLike(buf+i)) continue;

                    double e   = CalcEntropy(buf+i, KEY_SIZE);
                    UINT64 ka  = rb + off + i - ov_len;
                    char note[96];
                    snprintf(note, 96, "[%s @ 0x%llX + 0x%llX]",
                             type_s, (unsigned long long)rb,
                             (unsigned long long)(off + i - ov_len));

                    /* hex lines */
                    char h1[64]="", h2[64]="";
                    for(int j=0;j<16;j++){char h[4];snprintf(h,4,"%02X ",buf[i+j]);strcat(h1,h);}
                    for(int j=16;j<32;j++){char h[4];snprintf(h,4,"%02X ",buf[i+j]);strcat(h2,h);}

                    struct nk_color col = (mbi.Type==MEM_IMAGE) ? IDA_GREEN :
                                         (mbi.Type==MEM_PRIVATE)? IDA_YELLOW : IDA_CYAN;

                    Log(col, "  [KEY#%d] 0x%016llX  e=%.3f  %s",
                        hits+1, (unsigned long long)ka, e, note);
                    Log(col, "          %s", h1);
                    Log(col, "          %s", h2);

                    EnterCriticalSection(&g_aes_cs);
                    if (g_aes_count < MAX_AES_KEYS) {
                        AesKey *k  = &g_aes_keys[g_aes_count++];
                        k->addr    = ka;
                        k->entropy = e;
                        memcpy(k->bytes, buf+i, KEY_SIZE);
                        strncpy(k->note, note, 95);
                    }
                    LeaveCriticalSection(&g_aes_cs);

                    hits++;
                    i += KEY_SIZE - 1;
                }

                /* keep tail for cross-chunk candidates */
                ov_len = (total >= (SIZE_T)(KEY_SIZE-1)) ? (KEY_SIZE-1) : (int)total;
                memcpy(overlap, buf + total - ov_len, ov_len);
            }
        }

        addr = (UINT64)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    free(buf);
done:
    g_scan_running = false;
    struct nk_color col = hits ? IDA_GREEN : IDA_YELLOW;
    Log(col, "+=== AES Scan done: %d candidates  (%.1f MB scanned)",
        hits, (double)bytes_scanned / (1024.0*1024.0));
    return 0;
}

/* -- AESScanLaunch ------------------------------------------------- */
void AESScanLaunch(void)
{
    if (!g_target) {
        Log(IDA_RED,"[!] No process attached");
        return;
    }
    if (g_scan_running) {
        Log(IDA_YELLOW,"[!] Scan already running");
        return;
    }

    /* reset results */
    EnterCriticalSection(&g_aes_cs);
    g_aes_count = 0;
    LeaveCriticalSection(&g_aes_cs);

    g_scan_running = true;
    HANDLE th = CreateThread(NULL, 0, ScanThread, (LPVOID)g_target, 0, NULL);
    if (th) CloseHandle(th);
    else    g_scan_running = false;
}
