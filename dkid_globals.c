/* dkid_globals.c - all global variable definitions */
#include "dkid.h"

ProcInfo    g_procs[4096];          int g_proc_count = 0;
ModInfo     g_mods[MAX_MODULES];    int g_mod_count  = 0;
IATEntry    g_iat[MAX_IAT];         int g_iat_count  = 0;

AesKey      g_aes_keys[MAX_AES_KEYS]; int g_aes_count = 0;
CRITICAL_SECTION g_aes_cs;

FoundString g_strings[MAX_STRINGS]; int g_str_count = 0;
CRITICAL_SECTION g_str_cs;

ImportEntry g_imports[MAX_IAT];     int g_imp_count = 0;
ExportEntry g_exports[4096];        int g_exp_count = 0;
SectionEntry g_sections[64];        int g_sec_count = 0;

DisasmLine  g_disasm[MAX_DISASM_LINES]; int g_disasm_count = 0;
int         g_disasm_sel = 0;
CRITICAL_SECTION g_disasm_cs;

LogLine    *g_log_lines = NULL;     int g_log_count = 0;
int         g_log_cap   = 0;
CRITICAL_SECTION g_log_cs;

HexView     g_hex = {0};

HANDLE      g_target      = NULL;
DWORD       g_target_pid  = 0;
char        g_target_name[MAX_PATH] = {0};
UINT64      g_dll_base    = 0;
DWORD       g_dll_size    = 0;
char        g_dll_name[MAX_PATH]    = {0};
bool        g_attached        = false;
bool        g_scan_running    = false;
bool        g_str_scan_running = false;
char        g_status[256]     = "Ready";

Plugin      g_plugins[MAX_PLUGINS]; int g_plugin_count = 0;
ExtraPanel  g_extra_panels[32];     int g_extra_panel_count = 0;
PluginAPI   g_plugin_api    = {0};

/* UI state */
int  g_sidebar_tab  = 0;
int  g_main_tab     = 0;
int  g_bot_tab      = 0;
int  g_sidebar_w    = 260;
int  g_bottom_h     = 200;
char g_jump_buf[32] = {0};
char g_search_buf[128] = {0};
int  g_proc_sel     = -1;
int  g_mod_sel      = -1;
float g_disasm_scroll = 0.f;
float g_hex_scroll    = 0.f;

char g_clean_disasm_text[131072] = {0};
char g_clean_disasm_status[256]  = "Not generated";
bool g_clean_disasm_running      = false;
CRITICAL_SECTION g_clean_disasm_cs;

MemEvent g_mem_events[MAX_MEM_EVENTS];
int g_mem_event_count = 0;
bool g_mem_live_enabled = true;
CRITICAL_SECTION g_mem_cs;
