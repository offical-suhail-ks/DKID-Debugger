/*
 * DKID v3.0 - Advanced Memory Analysis Tool
 * IDA Pro-style UI via Nuklear (pure C, GDI backend)
 *
 * BUILD:
 *   gcc nk_impl.c dkid_main.c dkid_globals.c dkid_ui.c
 *       dkid_disasm.c dkid_pe.c dkid_process.c dkid_scan.c
 *       dkid_strings.c dkid_plugin.c dkid_hexview.c dkid_log.c
 *       -o dkid.exe -lpsapi -ldbghelp -lgdi32 -luser32 -lkernel32
 *       -lcomctl32 -lole32 -mwindows -O2 -m64 -std=c11 -lm
 *       -Wno-unknown-pragmas -Wno-stringop-truncation
 *
 * REQUIRES: nuklear.h  (github.com/Immediate-Mode-UI/Nuklear - single header)
 *           Place nuklear.h in this directory before compiling.
 *
 * PLUGINS: compile your DLL exporting:
 *   int  plugin_init(struct PluginAPI *api);   // required
 *   void plugin_exit(void);                    // required
 *   void plugin_draw(struct nk_context *ctx);  // optional - adds bottom tab
 */
#pragma once
#ifndef IDAPROBE_H
#define IDAPROBE_H

#define _WIN32_WINNT 0x0A00
#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <windowsx.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

#include "k0probe_iface.h"
#include <winhttp.h>

/* -- nuklear ------------------------------------------------------- */
#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#include "nuklear.h"

/* -- constants ----------------------------------------------------- */
#define APP_NAME        "DKID"
#define APP_VERSION     "3.0"
#define APP_CLASS       "DKIDV30"
#define MAX_MODULES     512
#define MAX_IAT         8192
#define MAX_AES_KEYS    512
#define MAX_STRINGS     4096
#define MAX_LOG_LINES   32768
#define KEY_SIZE        32
#define MIN_ENTROPY     6.5
#define MIN_UNIQUE      18
#define MAX_DISASM_LINES 8192
#define MAX_PLUGINS     16
#define MAX_MEM_EVENTS  2048
#define POLL_MS         200

/* -- IDA color palette --------------------------------------------- */
/* Stored as nk_color for direct Nuklear use */
#define IDA_BG          nk_rgba(0x1E,0x1E,0x1E,0xFF)
#define IDA_BG2         nk_rgba(0x25,0x25,0x26,0xFF)
#define IDA_BG3         nk_rgba(0x2D,0x2D,0x30,0xFF)
#define IDA_BORDER      nk_rgba(0x3F,0x3F,0x46,0xFF)
#define IDA_TEXT        nk_rgba(0xDC,0xDC,0xDC,0xFF)
#define IDA_TEXT2       nk_rgba(0x9D,0x9D,0x9D,0xFF)
#define IDA_ADDR        nk_rgba(0xB8,0xD7,0xA3,0xFF)   /* light green */
#define IDA_MNEM        nk_rgba(0x56,0x9C,0xD6,0xFF)   /* blue */
#define IDA_REG         nk_rgba(0x9C,0xDC,0xFE,0xFF)   /* light blue */
#define IDA_IMM         nk_rgba(0xB5,0xCE,0xA8,0xFF)   /* pale green */
#define IDA_HEX_BYTES   nk_rgba(0xCE,0x91,0x78,0xFF)   /* orange */
#define IDA_STR         nk_rgba(0xCE,0x91,0x78,0xFF)   /* orange */
#define IDA_COMMENT     nk_rgba(0x6A,0x99,0x55,0xFF)   /* dark green */
#define IDA_ACCENT      nk_rgba(0x00,0x7A,0xCC,0xFF)   /* blue accent */
#define IDA_ACCENT2     nk_rgba(0x00,0xA8,0xFF,0xFF)   /* brighter blue accent */
#define IDA_TEXT3       nk_rgba(0x7A,0x9F,0xBF,0xFF)   /* muted blue-grey text */
#define IDA_GREEN       nk_rgba(0x4E,0xC9,0x7E,0xFF)
#define IDA_RED         nk_rgba(0xF4,0x47,0x47,0xFF)
#define IDA_YELLOW      nk_rgba(0xDC,0xDC,0x4A,0xFF)
#define IDA_CYAN        nk_rgba(0x4E,0xC9,0xC9,0xFF)
#define IDA_SEL         nk_rgba(0x26,0x4F,0x78,0xFF)

/* -- types --------------------------------------------------------- */
typedef struct { DWORD pid; char name[MAX_PATH]; } ProcInfo;
typedef struct { HMODULE h; UINT64 base; DWORD size; char name[MAX_PATH]; } ModInfo;
typedef struct { UINT64 va; UINT64 orig; } IATEntry;

typedef struct {
    UINT64  addr;
    BYTE    bytes[KEY_SIZE];
    double  entropy;
    char    note[96];
} AesKey;

typedef struct {
    UINT64  addr;
    char    text[256];
    int     len;
    bool    wide;
} FoundString;

typedef struct {
    char    name[128];
    char    dll[MAX_PATH];
    UINT64  va;
    UINT64  iat_va;
} ImportEntry;

typedef struct {
    char    name[128];
    UINT64  va;
    DWORD   ordinal;
} ExportEntry;

typedef struct {
    char    name[16];
    UINT64  va;
    DWORD   raw;
    DWORD   vsize;
    DWORD   chars;
} SectionEntry;

/* Disassembly line */
typedef struct {
    UINT64  addr;
    BYTE    raw[16];
    int     raw_len;
    char    mnem[32];
    char    operands[96];
    char    comment[64];
    bool    is_call, is_jmp, is_ret;
    struct nk_color addr_color;
    struct nk_color mnem_color;
    struct nk_color op_color;
} DisasmLine;

/* Log line */
typedef struct { char text[512]; struct nk_color color; } LogLine;

/* Hex view state */
typedef struct {
    UINT64  base;
    BYTE   *data;
    SIZE_T  size;
    SIZE_T  cursor;
    SIZE_T  sel_start, sel_end;
    bool    loaded;
} HexView;

/* -- Plugin API (exported to plugin DLLs) --------------------------- */
struct PluginAPI;
typedef struct PluginAPI {
    int     version;                            /* API version = 1 */
    void  (*log)(const char *fmt, ...);         /* write to output log */
    HANDLE (*get_target)(void);                 /* current target HANDLE */
    DWORD  (*get_target_pid)(void);
    int    (*read_mem)(UINT64 addr, void *buf, int size); /* 1=ok */
    void   (*get_aes_keys)(AesKey **out, int *count);
    void   (*get_strings)(FoundString **out, int *count);
    /* add a named tab to the bottom panel (draw called each frame) */
    void   (*add_tab)(const char *name, void (*draw)(struct nk_context *));
} PluginAPI;

typedef struct {
    HMODULE     dll;
    char        name[64];
    char        path[MAX_PATH];
    int       (*fn_init)(PluginAPI *);
    void      (*fn_exit)(void);
    void      (*fn_draw)(struct nk_context *);  /* NULL if unused */
    bool        loaded;
} Plugin;

/* Extra panel added by a plugin */
typedef struct {
    char  name[64];
    void (*draw)(struct nk_context *);
} ExtraPanel;

typedef struct LiveWatch LiveWatch;

typedef struct {
    DWORD   tick;
    UINT64  addr;
    BYTE    oldv;
    BYTE    newv;
    DWORD   event_type;    /* K0_EVT_* flags (0 = user-mode diff)   */
    DWORD   watch_id;      /* hardware watchpoint ID (0 = snapshot) */
    char    context[64];   /* "module!0xADDR" from kernel           */
} MemEvent;

/* -- global extern declarations ------------------------------------ */
extern ProcInfo      g_procs[];       extern int g_proc_count;
extern ModInfo       g_mods[];        extern int g_mod_count;
extern IATEntry      g_iat[];         extern int g_iat_count;

extern AesKey        g_aes_keys[];    extern int g_aes_count;
extern CRITICAL_SECTION g_aes_cs;

extern FoundString   g_strings[];     extern int g_str_count;
extern CRITICAL_SECTION g_str_cs;

extern ImportEntry   g_imports[];     extern int g_imp_count;
extern ExportEntry   g_exports[];     extern int g_exp_count;
extern SectionEntry  g_sections[];    extern int g_sec_count;

extern DisasmLine    g_disasm[];      extern int g_disasm_count;
extern int           g_disasm_sel;    /* selected line index */
extern CRITICAL_SECTION g_disasm_cs;

extern LogLine      *g_log_lines;     extern int g_log_count;
extern int           g_log_cap;
extern CRITICAL_SECTION g_log_cs;

extern HexView       g_hex;

extern HANDLE        g_target;
extern DWORD         g_target_pid;
extern char          g_target_name[MAX_PATH];
extern UINT64        g_dll_base;
extern DWORD         g_dll_size;
extern char          g_dll_name[MAX_PATH];
extern bool          g_attached;
extern bool          g_scan_running;
extern bool          g_str_scan_running;
extern char          g_status[256];

extern Plugin        g_plugins[];     extern int g_plugin_count;
extern ExtraPanel    g_extra_panels[]; extern int g_extra_panel_count;
extern PluginAPI     g_plugin_api;

/* UI state */
extern int  g_sidebar_tab;    /* 0=Procs 1=Mods 2=Sections 3=Imports 4=Exports */
extern int  g_main_tab;       /* 0=Disasm 1=Hex 2=Settings */
extern int  g_bot_tab;        /* 0=Log 1=AES 2=Strings 3=Cleaned Disassembly 4=Live Memory 5=plugin... */
extern int  g_sidebar_w;
extern int  g_bottom_h;
extern char g_jump_buf[32];   /* goto-address edit */
extern char g_search_buf[128];
extern int  g_proc_sel;
extern int  g_mod_sel;
extern float g_disasm_scroll;
extern float g_hex_scroll;

extern char g_clean_disasm_text[131072];
extern char g_clean_disasm_status[256];
extern bool g_clean_disasm_running;
extern CRITICAL_SECTION g_clean_disasm_cs;

extern MemEvent g_mem_events[MAX_MEM_EVENTS];
extern int g_mem_event_count;
extern bool g_mem_live_enabled;
extern CRITICAL_SECTION g_mem_cs;

/* -- function prototypes ------------------------------------------- */
/* dkid_ui.c */
void UIBuild(struct nk_context *ctx, int W, int H);
void UISetTheme(struct nk_context *ctx);

/* dkid_process.c */
void ProcRefresh(void);
void ProcAttach(DWORD pid);
void ProcDetach(void);
void ModRefresh(void);
void ModRefreshLive(void);
void ModAnalyze(int idx);

/* dkid_disasm.c */
int  DisasmBuffer(const BYTE *code, int code_len, UINT64 base_addr,
                  DisasmLine *out, int max_lines);
void DisasmRefresh(void);   /* (re)disassemble current module .text */
void DisasmRefreshLive(void);

/* dkid_pe.c */
void PEAnalyze(void);       /* fills imports, exports, sections */
void PEDumpLog(void);       /* write PE details to log */

/* dkid_scan.c */
void AESScanLaunch(void);   /* background thread; auto-called on attach */
double CalcEntropy(const BYTE *d, int n);
bool IsKeyLike(const BYTE *d);

/* dkid_strings.c */
void StringsScanLaunch(void); /* background thread */

/* dkid_hexview.c */
void HexLoad(UINT64 addr, SIZE_T size); /* read from target process */
void HexFree(void);

/* dkid_plugin.c */
void PluginInit(void);          /* scan ./plugins/ and load all DLLs */
void PluginShutdown(void);
void PluginLoadFile(const char *path);

/* dkid_log.c */
void Log(struct nk_color col, const char *fmt, ...);
void LogClear(void);
void LogSave(const char *path);

/* dkid_ai.c */
void CleanDisasmRequest(void);
bool AIReadConfiguredKey(char *out, int out_sz);
bool AISaveConfiguredKey(const char *input, char *status, int status_sz);
bool AIClearConfiguredKey(char *status, int status_sz);

/* dkid_memlive.c */
void MemLiveReset(void);
void MemLiveTick(void);
void MemLiveClear(void);
bool MemLiveWatchAdd(UINT64 addr, DWORD size, DWORD access, const char *label);
bool MemLiveWatchRemove(int slot);
LiveWatch *MemLiveGetWatches(int *count);

/* dkid_k0.c  -  Ring-0 kernel driver bridge */
bool  K0Init(void);
void  K0Shutdown(void);
bool  K0IsAvailable(void);
bool  K0SetTarget(DWORD pid);
bool  K0ReadMem(DWORD pid, UINT64 addr, void *buf, DWORD size);
bool  K0WriteMem(DWORD pid, UINT64 addr, const void *buf, DWORD size);
int   K0QueryRegions(DWORD pid, UINT64 start, K0Region *out, int max);
bool  K0WatchAdd(DWORD pid, UINT64 addr, DWORD size, DWORD access, DWORD *id);
bool  K0WatchRemove(DWORD id);
int   K0PollEvents(K0Event *out, int max);
void  K0FlushEvents(void);
bool  K0GetPhysAddr(DWORD pid, UINT64 va, UINT64 *pa);
bool  K0GetCR3(UINT64 *cr3);

#endif /* IDAPROBE_H */
