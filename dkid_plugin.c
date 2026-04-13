/*
 * dkid_plugin.c - DLL plugin loader
 *
 * Plugin DLL must export:
 *   int  plugin_init(PluginAPI *api)   - return 0 on success
 *   void plugin_exit(void)
 *   void plugin_draw(struct nk_context *ctx)   [optional]
 */
#include "dkid.h"

/* -- PluginAPI implementation -------------------------------------- */
static void api_log(const char *fmt, ...)
{
    char buf[512]; va_list ap; va_start(ap,fmt);
    vsnprintf(buf,512,fmt,ap); va_end(ap);
    Log(IDA_CYAN, "[PLUGIN] %s", buf);
}
static HANDLE api_get_target (void)      { return g_target; }
static DWORD  api_get_pid    (void)      { return g_target_pid; }
static int    api_read_mem   (UINT64 addr, void *buf, int sz) {
    if (!g_target) return 0;
    SIZE_T got=0;
    return ReadProcessMemory(g_target,(LPCVOID)(uintptr_t)addr,buf,(SIZE_T)sz,&got)&&got>0;
}
static void api_get_aes_keys(AesKey **out, int *count)
{
    *out   = g_aes_keys;
    *count = g_aes_count;
}
static void api_get_strings(FoundString **out, int *count)
{
    *out   = g_strings;
    *count = g_str_count;
}
static void api_add_tab(const char *name, void (*draw)(struct nk_context *))
{
    if (g_extra_panel_count >= 32) return;
    ExtraPanel *p = &g_extra_panels[g_extra_panel_count++];
    strncpy(p->name, name, 63);
    p->draw = draw;
}

static void BuildAPI(void)
{
    g_plugin_api.version       = 1;
    g_plugin_api.log           = api_log;
    g_plugin_api.get_target    = api_get_target;
    g_plugin_api.get_target_pid= api_get_pid;
    g_plugin_api.read_mem      = api_read_mem;
    g_plugin_api.get_aes_keys  = api_get_aes_keys;
    g_plugin_api.get_strings   = api_get_strings;
    g_plugin_api.add_tab       = api_add_tab;
}

/* -- PluginLoadFile ------------------------------------------------ */
void PluginLoadFile(const char *path)
{
    if (g_plugin_count >= MAX_PLUGINS) {
        Log(IDA_RED,"[!] Max plugins (%d) reached", MAX_PLUGINS);
        return;
    }

    HMODULE dll = LoadLibraryA(path);
    if (!dll) {
        Log(IDA_RED,"[!] LoadLibrary failed: %s  err=%lu", path, GetLastError());
        return;
    }

    typedef int  (*FnInit)(PluginAPI*);
    typedef void (*FnExit)(void);
    typedef void (*FnDraw)(struct nk_context*);

    FnInit fn_init = (FnInit)GetProcAddress(dll,"plugin_init");
    FnExit fn_exit = (FnExit)GetProcAddress(dll,"plugin_exit");
    FnDraw fn_draw = (FnDraw)GetProcAddress(dll,"plugin_draw");

    if (!fn_init || !fn_exit) {
        Log(IDA_RED,"[!] Plugin missing plugin_init / plugin_exit: %s", path);
        FreeLibrary(dll);
        return;
    }

    BuildAPI();
    int rc = fn_init(&g_plugin_api);
    if (rc != 0) {
        Log(IDA_RED,"[!] plugin_init returned %d for: %s", rc, path);
        FreeLibrary(dll);
        return;
    }

    Plugin *plug     = &g_plugins[g_plugin_count++];
    plug->dll        = dll;
    plug->fn_init    = fn_init;
    plug->fn_exit    = fn_exit;
    plug->fn_draw    = fn_draw;
    plug->loaded     = true;
    strncpy(plug->path, path, MAX_PATH-1);

    /* extract name from filename */
    const char *slash = strrchr(path,'\\');
    if (!slash) slash = strrchr(path,'/');
    strncpy(plug->name, slash ? slash+1 : path, 63);

    Log(IDA_GREEN,"[+] Plugin loaded: %s", plug->name);

    /* if plugin has a draw function, register it as an extra tab */
    if (fn_draw) api_add_tab(plug->name, fn_draw);
}

/* -- PluginInit ---------------------------------------------------- */
void PluginInit(void)
{
    /* auto-load all *.dll from ./plugins/ */
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("plugins\\*.dll", &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        char full[MAX_PATH];
        snprintf(full, MAX_PATH, "plugins\\%s", fd.cFileName);
        PluginLoadFile(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* -- PluginShutdown ------------------------------------------------ */
void PluginShutdown(void)
{
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i].fn_exit) g_plugins[i].fn_exit();
        FreeLibrary(g_plugins[i].dll);
    }
    g_plugin_count = 0;
}
