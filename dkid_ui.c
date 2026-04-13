/*
 * dkid_ui.c - IDA Pro-style multi-pane Nuklear UI
 *
 * Layout:
 *   top 26px   : menu bar
 *   26..58px   : toolbar
 *   58..H-bot  : [ sidebar | main (disasm/hex) ]
 *   H-bot..H-20: bottom tabs (log / AES / strings / plugin panels)
 *   H-20..H    : status bar
 */
#include "dkid.h"
#include "nk_win.h"
#include "k0probe_iface.h"

#define MENU_H   26
#define TOOL_H   34
#define STAT_H   22
#define SPLITTER 4

/* forward */
static void IDADrawMenuBar(struct nk_context *ctx, int W);
static void DrawToolbar(struct nk_context *ctx, int W);
static void DrawSidebar(struct nk_context *ctx, int W, int Y, int H);
static void DrawMain   (struct nk_context *ctx, int X, int Y, int W, int H);
static void DrawRightModules(struct nk_context *ctx, int W, int H);
static void DrawBottom (struct nk_context *ctx, int W, int Y, int H);
static void DrawStatus (struct nk_context *ctx, int W, int H);

static void DrawDisasm (struct nk_context *ctx, int W, int H);
static void DrawHex    (struct nk_context *ctx, int W, int H);
static void DrawSettings(struct nk_context *ctx, int W, int H);
static void DrawLogPane(struct nk_context *ctx, int W, int H);
static void DrawAESPane(struct nk_context *ctx, int W, int H);
static void DrawStrPane(struct nk_context *ctx, int W, int H);
static void DrawCleanDisasmPane(struct nk_context *ctx, int W, int H);
static void DrawLiveMemPane(struct nk_context *ctx, int W, int H);
static void DrawSideProcs   (struct nk_context *ctx, int W, int H);
static void DrawSideMods    (struct nk_context *ctx, int W, int H);
static void DrawSideSections(struct nk_context *ctx, int W, int H);
static void DrawSideImports (struct nk_context *ctx, int W, int H);
static void DrawSideExports (struct nk_context *ctx, int W, int H);

static void UIClipboardSetText(const char *text)
{
    if (!text) return;
    size_t len = strlen(text);
    if (len == 0) return;
    if (!OpenClipboard(NULL)) return;
    EmptyClipboard();
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, len + 1);
    if (h) {
        char *dst = (char*)GlobalLock(h);
        if (dst) {
            memcpy(dst, text, len + 1);
            GlobalUnlock(h);
            SetClipboardData(CF_TEXT, h);
            h = NULL;
        }
    }
    if (h) GlobalFree(h);
    CloseClipboard();
}

/* =========================================== Theme ================== */
void UISetTheme(struct nk_context *ctx)
{
    struct nk_color t[NK_COLOR_COUNT];
    t[NK_COLOR_TEXT]                    = nk_rgba(0xDC,0xDC,0xDC,0xFF);
    t[NK_COLOR_WINDOW]                  = nk_rgba(0x25,0x25,0x26,0xFF);
    t[NK_COLOR_HEADER]                  = nk_rgba(0x2D,0x2D,0x30,0xFF);
    t[NK_COLOR_BORDER]                  = nk_rgba(0x3F,0x3F,0x46,0xFF);
    t[NK_COLOR_BUTTON]                  = nk_rgba(0x3C,0x3C,0x3C,0xFF);
    t[NK_COLOR_BUTTON_HOVER]            = nk_rgba(0x52,0x52,0x52,0xFF);
    t[NK_COLOR_BUTTON_ACTIVE]           = nk_rgba(0x00,0x5F,0x9E,0xFF);
    t[NK_COLOR_TOGGLE]                  = nk_rgba(0x3C,0x3C,0x3C,0xFF);
    t[NK_COLOR_TOGGLE_HOVER]            = nk_rgba(0x52,0x52,0x52,0xFF);
    t[NK_COLOR_TOGGLE_CURSOR]           = nk_rgba(0x00,0x7A,0xCC,0xFF);
    t[NK_COLOR_SELECT]                  = nk_rgba(0x25,0x25,0x26,0xFF);
    t[NK_COLOR_SELECT_ACTIVE]           = nk_rgba(0x26,0x4F,0x78,0xFF);
    t[NK_COLOR_SLIDER]                  = nk_rgba(0x3C,0x3C,0x3C,0xFF);
    t[NK_COLOR_SLIDER_CURSOR]           = nk_rgba(0x00,0x7A,0xCC,0xFF);
    t[NK_COLOR_SLIDER_CURSOR_HOVER]     = nk_rgba(0x00,0x97,0xFF,0xFF);
    t[NK_COLOR_SLIDER_CURSOR_ACTIVE]    = nk_rgba(0x00,0x5F,0x9E,0xFF);
    t[NK_COLOR_PROPERTY]                = nk_rgba(0x2D,0x2D,0x30,0xFF);
    t[NK_COLOR_EDIT]                    = nk_rgba(0x1E,0x1E,0x1E,0xFF);
    t[NK_COLOR_EDIT_CURSOR]             = nk_rgba(0xDC,0xDC,0xDC,0xFF);
    t[NK_COLOR_COMBO]                   = nk_rgba(0x2D,0x2D,0x30,0xFF);
    t[NK_COLOR_CHART]                   = nk_rgba(0x1E,0x1E,0x1E,0xFF);
    t[NK_COLOR_CHART_COLOR]             = nk_rgba(0x00,0x7A,0xCC,0xFF);
    t[NK_COLOR_CHART_COLOR_HIGHLIGHT]   = nk_rgba(0xF4,0x47,0x47,0xFF);
    t[NK_COLOR_SCROLLBAR]               = nk_rgba(0x2D,0x2D,0x30,0xFF);
    t[NK_COLOR_SCROLLBAR_CURSOR]        = nk_rgba(0x56,0x56,0x5A,0xFF);
    t[NK_COLOR_SCROLLBAR_CURSOR_HOVER]  = nk_rgba(0x78,0x78,0x78,0xFF);
    t[NK_COLOR_SCROLLBAR_CURSOR_ACTIVE] = nk_rgba(0x96,0x96,0x96,0xFF);
    t[NK_COLOR_TAB_HEADER]              = nk_rgba(0x2D,0x2D,0x30,0xFF);
    nk_style_from_table(ctx, t);

    /* rounded buttons */
    ctx->style.button.rounding = 2;
    ctx->style.window.border   = 1.f;
    ctx->style.window.padding  = nk_vec2(4, 4);
    ctx->style.window.spacing  = nk_vec2(2, 2);
}

/* =========================================== Entry ================== */
void UIBuild(struct nk_context *ctx, int W, int H)
{
    int top     = MENU_H + TOOL_H;
    int botY    = H - g_bottom_h - STAT_H;
    int midH    = botY - top;
    int mainX   = g_sidebar_w + SPLITTER;
    int mainW   = W - mainX;

    IDADrawMenuBar(ctx, W);
    DrawToolbar(ctx, W);
    DrawSidebar(ctx, g_sidebar_w, top, midH);
    DrawMain   (ctx, mainX, top, mainW, midH);
    DrawBottom (ctx, W, botY, g_bottom_h);
    DrawStatus (ctx, W, H);
}

/* =========================================== Menu Bar =============== */
static void IDADrawMenuBar(struct nk_context *ctx, int W)
{
    nk_flags flags = NK_WINDOW_NO_SCROLLBAR | NK_WINDOW_BACKGROUND;
    if (nk_begin(ctx, "##menu", nk_rect(0,0,W,MENU_H), flags))
    {
        nk_menubar_begin(ctx);
        nk_layout_row_begin(ctx, NK_STATIC, MENU_H-4, 6);

        /* File */
        nk_layout_row_push(ctx, 50);
        if (nk_menu_begin_label(ctx, "File", NK_TEXT_LEFT, nk_vec2(140, 120))) {
            nk_layout_row_dynamic(ctx, 22, 1);
            if (nk_menu_item_label(ctx, "Open Binary...",  NK_TEXT_LEFT)) { /* TODO */ }
            if (nk_menu_item_label(ctx, "Load Plugins...", NK_TEXT_LEFT)) { /* TODO */ }
            nk_menu_item_label(ctx, "-------------", NK_TEXT_LEFT);
            if (nk_menu_item_label(ctx, "Save Log...",     NK_TEXT_LEFT)) LogSave("dkid.log");
            nk_menu_item_label(ctx, "-------------", NK_TEXT_LEFT);
            if (nk_menu_item_label(ctx, "Exit",            NK_TEXT_LEFT)) PostQuitMessage(0);
            nk_menu_end(ctx);
        }

        /* View */
        nk_layout_row_push(ctx, 50);
        if (nk_menu_begin_label(ctx, "View", NK_TEXT_LEFT, nk_vec2(180, 130))) {
            nk_layout_row_dynamic(ctx, 22, 1);
            if (nk_menu_item_label(ctx, "Disassembly  [D]", NK_TEXT_LEFT)) g_main_tab = 0;
            if (nk_menu_item_label(ctx, "Hex View     [H]", NK_TEXT_LEFT)) g_main_tab = 1;
            if (nk_menu_item_label(ctx, "Settings", NK_TEXT_LEFT)) g_main_tab = 2;
            if (nk_menu_item_label(ctx, "Refresh Procs",    NK_TEXT_LEFT)) ProcRefresh();
            nk_menu_end(ctx);
        }

        /* Analyze */
        nk_layout_row_push(ctx, 70);
        if (nk_menu_begin_label(ctx, "Analyze", NK_TEXT_LEFT, nk_vec2(180, 120))) {
            nk_layout_row_dynamic(ctx, 22, 1);
            if (nk_menu_item_label(ctx, "AES Key Scan  [F5]", NK_TEXT_LEFT)) AESScanLaunch();
            if (nk_menu_item_label(ctx, "Strings Scan  [F6]", NK_TEXT_LEFT)) StringsScanLaunch();
            if (nk_menu_item_label(ctx, "PE Analysis   [F7]", NK_TEXT_LEFT)) PEAnalyze();
            if (nk_menu_item_label(ctx, "Disassemble   [F8]", NK_TEXT_LEFT)) DisasmRefresh();
            nk_menu_end(ctx);
        }

        /* Plugins */
        nk_layout_row_push(ctx, 60);
        if (nk_menu_begin_label(ctx, "Plugin", NK_TEXT_LEFT, nk_vec2(180, 80))) {
            nk_layout_row_dynamic(ctx, 22, 1);
            if (nk_menu_item_label(ctx, "Load Plugin DLL...", NK_TEXT_LEFT)) {
                char buf[MAX_PATH] = {0};
                OPENFILENAMEA ofn = {0};
                ofn.lStructSize = sizeof(ofn);
                ofn.lpstrFilter = "DLL Plugin\0*.dll\0All\0*.*\0";
                ofn.lpstrFile   = buf;
                ofn.nMaxFile    = MAX_PATH;
                ofn.Flags       = OFN_FILEMUSTEXIST;
                if (GetOpenFileNameA(&ofn)) PluginLoadFile(buf);
            }
            nk_menu_item_label(ctx, "-------------", NK_TEXT_LEFT);
            for (int i = 0; i < g_plugin_count; i++)
                nk_label(ctx, g_plugins[i].name, NK_TEXT_LEFT);
            nk_menu_end(ctx);
        }

        /* Help */
        nk_layout_row_push(ctx, 50);
        if (nk_menu_begin_label(ctx, "Help", NK_TEXT_LEFT, nk_vec2(180, 60))) {
            nk_layout_row_dynamic(ctx, 22, 1);
            if (nk_menu_item_label(ctx, "About DKID", NK_TEXT_LEFT))
                MessageBoxA(NULL,
                    "DKID v3.0\nAdvanced Memory Analysis\n"
                    "UI: Nuklear (immediate-mode C)\n"
                    "Plugin API: PluginAPI v1",
                    "About", MB_OK);
            nk_menu_end(ctx);
        }

        nk_layout_row_end(ctx);
        nk_menubar_end(ctx);
    }
    nk_end(ctx);
}

/* =========================================== Toolbar ================ */
static void DrawToolbar(struct nk_context *ctx, int W)
{
    nk_flags flags = NK_WINDOW_NO_SCROLLBAR | NK_WINDOW_BACKGROUND;
    if (nk_begin(ctx, "##toolbar", nk_rect(0, MENU_H, W, TOOL_H), flags))
    {
        nk_layout_row_begin(ctx, NK_STATIC, TOOL_H-6, 20);

        #define TB(w, lbl) nk_layout_row_push(ctx, w); \
                           nk_button_label(ctx, lbl)

        /* Process control */
        nk_layout_row_push(ctx, 80);
        if (nk_button_label(ctx, "Refresh")) ProcRefresh();

        nk_layout_row_push(ctx, 80);
        if (nk_button_label(ctx, "Attach")) {
            if (g_proc_sel >= 0 && g_proc_sel < g_proc_count)
                ProcAttach(g_procs[g_proc_sel].pid);
        }

        nk_layout_row_push(ctx, 70);
        if (nk_button_label(ctx, "Detach")) ProcDetach();

        /* separator */
        nk_layout_row_push(ctx, 8);
        nk_label(ctx, "|", NK_TEXT_CENTERED);

        /* Analysis */
        nk_layout_row_push(ctx, 80);
        if (nk_button_label(ctx, g_scan_running ? "Scanning..." : "AES Scan"))
            if (!g_scan_running) AESScanLaunch();

        nk_layout_row_push(ctx, 80);
        if (nk_button_label(ctx, g_str_scan_running ? "Scanning..." : "Strings"))
            if (!g_str_scan_running) StringsScanLaunch();

        nk_layout_row_push(ctx, 70);
        if (nk_button_label(ctx, "Disasm")) DisasmRefresh();

        nk_layout_row_push(ctx, 90);
        if (nk_button_label(ctx, g_clean_disasm_running ? "AI Busy..." : "Clean Disasm")) {
            if (!g_clean_disasm_running) CleanDisasmRequest();
        }

        nk_layout_row_push(ctx, 60);
        if (nk_button_label(ctx, "PE Info")) PEDumpLog();

        /* separator */
        nk_layout_row_push(ctx, 8);
        nk_label(ctx, "|", NK_TEXT_CENTERED);

        /* Goto address */
        nk_layout_row_push(ctx, 38);
        nk_label(ctx, "Goto:", NK_TEXT_LEFT);
        nk_layout_row_push(ctx, 130);
        nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, g_jump_buf, sizeof(g_jump_buf),
                                       nk_filter_ascii);
        nk_layout_row_push(ctx, 50);
        if (nk_button_label(ctx, "Go")) {
            UINT64 a = (UINT64)strtoull(g_jump_buf, NULL, 16);
            if (a) HexLoad(a, 4096);
        }

        /* separator */
        nk_layout_row_push(ctx, 8);
        nk_label(ctx, "|", NK_TEXT_CENTERED);

        /* Search */
        nk_layout_row_push(ctx, 44);
        nk_label(ctx, "Find:", NK_TEXT_LEFT);
        nk_layout_row_push(ctx, 160);
        nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, g_search_buf, sizeof(g_search_buf),
                                       nk_filter_default);

        /* AES key count badge */
        if (g_aes_count > 0) {
            char badge[32]; snprintf(badge, 32, " [AES:%d]", g_aes_count);
            nk_layout_row_push(ctx, 90);
            nk_label_colored(ctx, badge, NK_TEXT_LEFT, IDA_GREEN);
        }

        nk_layout_row_end(ctx);
        #undef TB
    }
    nk_end(ctx);
}

/* =========================================== Sidebar ================ */
static void DrawSidebar(struct nk_context *ctx, int W, int Y, int H)
{
    nk_flags flags = NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR;
    if (nk_begin(ctx, "##sidebar", nk_rect(0, Y, W, H), flags))
    {
        /* tab bar */
        static const char *tabs[] = {"Procs","Mods","Sects","Imps","Exps"};
        nk_layout_row_dynamic(ctx, 22, 5);
        for (int i = 0; i < 5; i++) {
            bool sel = (g_sidebar_tab == i);
            if (sel) nk_style_push_color(ctx, &ctx->style.button.normal.data.color,
                                         nk_rgba(0x00,0x5F,0x9E,0xFF));
            if (nk_button_label(ctx, tabs[i])) g_sidebar_tab = i;
            if (sel) nk_style_pop_color(ctx);
        }

        /* divider */
        nk_layout_row_dynamic(ctx, 1, 1);
        nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

        int panH = H - 22 - 8;

        /* group for scroll */
        nk_layout_row_dynamic(ctx, (float)panH, 1);
        if (nk_group_begin(ctx, "##sidegrp",
            NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR * 0))
        {
            switch (g_sidebar_tab) {
            case 0: DrawSideProcs   (ctx, W-8, panH); break;
            case 1: DrawSideMods    (ctx, W-8, panH); break;
            case 2: DrawSideSections(ctx, W-8, panH); break;
            case 3: DrawSideImports (ctx, W-8, panH); break;
            case 4: DrawSideExports (ctx, W-8, panH); break;
            }
            nk_group_end(ctx);
        }
    }
    nk_end(ctx);
}

/* -- sidebar contents ---------------------------------------------- */
static void DrawSideProcs(struct nk_context *ctx, int W, int H)
{
    (void)W; (void)H;
    char hdr[32]; snprintf(hdr, 32, "PROCESSES  [%d]", g_proc_count);
    nk_label_colored(ctx, hdr, NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_dynamic(ctx, 18, 1);
    for (int i = 0; i < g_proc_count; i++) {
        char buf[MAX_PATH+16];
        snprintf(buf, sizeof(buf), "[%5lu] %s",
                 (unsigned long)g_procs[i].pid, g_procs[i].name);
        nk_bool sel = (g_proc_sel == i);
        nk_bool pushed = sel;
        if (pushed) nk_style_push_color(ctx, &ctx->style.selectable.normal.data.color, IDA_SEL);
        if (nk_selectable_label(ctx, buf, NK_TEXT_LEFT, &sel)) {
            g_proc_sel = sel ? i : -1;
        }
        if (pushed) nk_style_pop_color(ctx);
    }
}

static void DrawSideMods(struct nk_context *ctx, int W, int H)
{
    (void)W; (void)H;
    char hdr[32]; snprintf(hdr, 32, "MODULES  [%d]", g_mod_count);
    nk_label_colored(ctx, hdr, NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_dynamic(ctx, 18, 1);
    for (int i = 0; i < g_mod_count; i++) {
        nk_bool sel = (g_mod_sel == i);
        nk_bool pushed = sel;
        if (pushed) nk_style_push_color(ctx, &ctx->style.selectable.normal.data.color, IDA_SEL);
        if (nk_selectable_label(ctx, g_mods[i].name, NK_TEXT_LEFT, &sel)) {
            if (sel) { g_mod_sel = i; ModAnalyze(i); }
            else      g_mod_sel = -1;
        }
        if (pushed) nk_style_pop_color(ctx);
    }
}

static void DrawSideSections(struct nk_context *ctx, int W, int H)
{
    (void)W; (void)H;
    char hdr[32]; snprintf(hdr, 32, "SECTIONS  [%d]", g_sec_count);
    nk_label_colored(ctx, hdr, NK_TEXT_LEFT, IDA_COMMENT);

    /* header row */
    nk_layout_row_begin(ctx, NK_STATIC, 18, 3);
    nk_layout_row_push(ctx, 70);  nk_label_colored(ctx,"Name",    NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_push(ctx, 90);  nk_label_colored(ctx,"VA",      NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_push(ctx, 60);  nk_label_colored(ctx,"VSize",   NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_end(ctx);

    for (int i = 0; i < g_sec_count; i++) {
        char va[24], sz[16];
        snprintf(va, 24, "%08llX", (unsigned long long)g_sections[i].va);
        snprintf(sz, 16, "%06lX", (unsigned long)g_sections[i].vsize);
        nk_layout_row_begin(ctx, NK_STATIC, 18, 3);
        nk_layout_row_push(ctx, 70);
        nk_label_colored(ctx, g_sections[i].name, NK_TEXT_LEFT, IDA_MNEM);
        nk_layout_row_push(ctx, 90);
        nk_label_colored(ctx, va, NK_TEXT_LEFT, IDA_ADDR);
        nk_layout_row_push(ctx, 60);
        nk_label_colored(ctx, sz, NK_TEXT_LEFT, IDA_IMM);
        nk_layout_row_end(ctx);
    }
}

static void DrawSideImports(struct nk_context *ctx, int W, int H)
{
    (void)W; (void)H;
    char hdr[32]; snprintf(hdr, 32, "IMPORTS  [%d]", g_imp_count);
    nk_label_colored(ctx, hdr, NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_dynamic(ctx, 18, 1);
    for (int i = 0; i < g_imp_count; i++) {
        char buf[256];
        snprintf(buf, 256, "%s!%s", g_imports[i].dll, g_imports[i].name);
        nk_label_colored(ctx, buf, NK_TEXT_LEFT, IDA_STR);
    }
}

static void DrawSideExports(struct nk_context *ctx, int W, int H)
{
    (void)W; (void)H;
    char hdr[32]; snprintf(hdr, 32, "EXPORTS  [%d]", g_exp_count);
    nk_label_colored(ctx, hdr, NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_dynamic(ctx, 18, 1);
    for (int i = 0; i < g_exp_count; i++) {
        char buf[64]; snprintf(buf, 64, "%04lX  %s",
                               (unsigned long)g_exports[i].ordinal, g_exports[i].name);
        nk_label_colored(ctx, buf, NK_TEXT_LEFT, IDA_IMM);
    }
}

/* -- right-side live modules panel -------------------------------- */
static void DrawRightModules(struct nk_context *ctx, int W, int H)
{
    (void)H;
    if (!g_attached) {
        nk_layout_row_dynamic(ctx, 20, 1);
        nk_label_colored(ctx, "Attach a process to view live modules.", NK_TEXT_LEFT, IDA_TEXT2);
        return;
    }

    char hdr[96];
    snprintf(hdr, sizeof(hdr), "LIVE MODULES (%d)", g_mod_count);
    nk_layout_row_dynamic(ctx, 20, 1);
    nk_label_colored(ctx, hdr, NK_TEXT_LEFT, IDA_COMMENT);

    nk_layout_row_dynamic(ctx, 18, 1);
    nk_label_colored(ctx, g_target_name[0] ? g_target_name : "<attached>", NK_TEXT_LEFT, IDA_TEXT2);

    nk_layout_row_dynamic(ctx, 1, 1);
    nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

    int list_h = (H > 52) ? (H - 52) : 60;
    nk_layout_row_dynamic(ctx, (float)list_h, 1);
    if (nk_group_begin(ctx, "##live_mods_group", NK_WINDOW_BORDER)) {
        nk_layout_row_dynamic(ctx, 18, 1);
        for (int i = 0; i < g_mod_count; i++) {
            char row[256];
            snprintf(row, sizeof(row), "%s  [0x%llX]", g_mods[i].name,
                     (unsigned long long)g_mods[i].base);
            nk_bool sel = (g_mod_sel == i);
            nk_bool pushed = sel;
            if (pushed) nk_style_push_color(ctx, &ctx->style.selectable.normal.data.color, IDA_SEL);
            if (nk_selectable_label(ctx, row, NK_TEXT_LEFT, &sel) && sel) {
                g_mod_sel = i;
                ModAnalyze(i);
                DisasmRefreshLive();
            }
            if (pushed) nk_style_pop_color(ctx);
        }
        nk_group_end(ctx);
    }

    (void)W;
}

/* =========================================== Main panel ============= */
static void DrawMain(struct nk_context *ctx, int X, int Y, int W, int H)
{
    nk_flags flags = NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR;
    if (nk_begin(ctx, "##main", nk_rect(X, Y, W, H), flags))
    {
        /* tab bar */
        static const char *tabs[] = { "Disassembly", "Hex View", "Settings" };
        nk_layout_row_begin(ctx, NK_STATIC, 24, 3);
        for (int i = 0; i < 3; i++) {
            nk_layout_row_push(ctx, i == 2 ? 90.f : 100.f);
            bool sel = (g_main_tab == i);
            if (sel) nk_style_push_color(ctx, &ctx->style.button.normal.data.color,
                                         nk_rgba(0x00,0x5F,0x9E,0xFF));
            if (nk_button_label(ctx, tabs[i])) g_main_tab = i;
            if (sel) nk_style_pop_color(ctx);
        }
        nk_layout_row_end(ctx);

        /* divider */
        nk_layout_row_dynamic(ctx, 1, 1);
        nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

        int panH = H - 24 - 8;
        int panW = W - 8;

        if (g_attached && g_main_tab != 2) {
            int rightW = 320;
            if (panW < 900) rightW = 260;
            if (panW < 700) rightW = 220;
            if (rightW > panW - 220) rightW = panW - 220;
            if (rightW < 180) rightW = 180;
            int leftW = panW - rightW - 4;

            nk_layout_row_begin(ctx, NK_STATIC, (float)panH, 2);
            nk_layout_row_push(ctx, (float)leftW);
            if (nk_group_begin(ctx, "##maingrp", NK_WINDOW_BORDER)) {
                if      (g_main_tab == 0) DrawDisasm(ctx, leftW - 8, panH);
                else if (g_main_tab == 1) DrawHex   (ctx, leftW - 8, panH);
                nk_group_end(ctx);
            }

            nk_layout_row_push(ctx, (float)rightW);
            if (nk_group_begin(ctx, "##right_mods", NK_WINDOW_BORDER)) {
                DrawRightModules(ctx, rightW - 8, panH);
                nk_group_end(ctx);
            }
            nk_layout_row_end(ctx);
        } else {
            nk_layout_row_dynamic(ctx, (float)panH, 1);
            if (nk_group_begin(ctx, "##maingrp", NK_WINDOW_BORDER)) {
                if      (g_main_tab == 0) DrawDisasm(ctx, panW, panH);
                else if (g_main_tab == 1) DrawHex   (ctx, panW, panH);
                else if (g_main_tab == 2) DrawSettings(ctx, panW, panH);
                nk_group_end(ctx);
            }
        }
    }
    nk_end(ctx);
}

/* -- Disassembly view ---------------------------------------------- */
static void DrawDisasm(struct nk_context *ctx, int W, int H)
{
    (void)H;
    nk_layout_row_dynamic(ctx, 22, 1);
    if (nk_button_label(ctx, "Copy All Disassembly")) {
        EnterCriticalSection(&g_disasm_cs);
        size_t cap = (size_t)(g_disasm_count > 0 ? g_disasm_count : 1) * 220 + 64;
        char *txt = (char*)malloc(cap);
        if (txt) {
            size_t at = 0;
            for (int i = 0; i < g_disasm_count; i++) {
                DisasmLine *ln = &g_disasm[i];
                int n = snprintf(txt + at, cap - at, "%016llX  %-10s %-48s %s\r\n",
                    (unsigned long long)ln->addr, ln->mnem, ln->operands,
                    ln->comment[0] ? ln->comment : "");
                if (n <= 0 || (size_t)n >= cap - at) break;
                at += (size_t)n;
            }
            UIClipboardSetText(txt);
            free(txt);
            Log(IDA_GREEN, "[+] Copied disassembly lines");
        }
        LeaveCriticalSection(&g_disasm_cs);
    }

    if (g_disasm_count == 0) {
        nk_layout_row_dynamic(ctx, 20, 1);
        nk_label_colored(ctx,
            "No disassembly.  Attach a process, select a module, then press Disasm.",
            NK_TEXT_LEFT, IDA_TEXT2);
        return;
    }

    /* 3 columns: address | bytes | mnemonic+operands */
    static const int COL_ADDR  = 140;
    static const int COL_BYTES = 180;

    EnterCriticalSection(&g_disasm_cs);

    for (int i = 0; i < g_disasm_count; i++) {
        DisasmLine *ln = &g_disasm[i];

        /* highlight selected line */
        nk_bool sel = (g_disasm_sel == i);
        if (sel) {
            nk_layout_row_dynamic(ctx, 18, 1);
            /* draw selection background via colored rect */
            struct nk_rect bounds = nk_widget_bounds(ctx);
            nk_fill_rect(nk_window_get_canvas(ctx), bounds, 0, IDA_SEL);
        }

        nk_layout_row_begin(ctx, NK_STATIC, 18, 4);

        /* address */
        nk_layout_row_push(ctx, COL_ADDR);
        char addr_s[24];
        snprintf(addr_s, 24, "%016llX", (unsigned long long)ln->addr);
        if (nk_selectable_label(ctx, addr_s, NK_TEXT_LEFT, &sel)) {
            g_disasm_sel = i;
            HexLoad(ln->addr, (SIZE_T)ln->raw_len < 64 ? 256 : (SIZE_T)ln->raw_len);
        }

        /* raw bytes */
        nk_layout_row_push(ctx, COL_BYTES);
        char bytes_s[64] = "";
        for (int b = 0; b < ln->raw_len && b < 8; b++) {
            char h[4]; snprintf(h, 4, "%02X ", ln->raw[b]); strcat(bytes_s, h);
        }
        if (ln->raw_len > 8) strcat(bytes_s, "...");
        nk_label_colored(ctx, bytes_s, NK_TEXT_LEFT, IDA_HEX_BYTES);

        /* mnemonic */
        nk_layout_row_push(ctx, 90);
        nk_label_colored(ctx, ln->mnem, NK_TEXT_LEFT, ln->mnem_color);

        /* operands + comment */
        int rem = W - COL_ADDR - COL_BYTES - 90 - 20;
        if (rem < 60) rem = 60;
        nk_layout_row_push(ctx, (float)rem);
        char ops[200]; snprintf(ops, 200, "%-36s %s", ln->operands,
                                ln->comment[0] ? ln->comment : "");
        nk_label_colored(ctx, ops, NK_TEXT_LEFT, ln->op_color);

        nk_layout_row_end(ctx);
    }

    LeaveCriticalSection(&g_disasm_cs);
}

/* -- Settings page ------------------------------------------------ */
static void DrawSettings(struct nk_context *ctx, int W, int H)
{
    (void)W; (void)H;
    static bool loaded = false;
    static char key_buf[768] = {0};
    static char status[256] = "";
    static bool status_ok = true;

    if (!loaded) {
        char key[768] = {0};
        if (AIReadConfiguredKey(key, (int)sizeof(key))) {
            snprintf(key_buf, sizeof(key_buf), "Bearer %s", key);
            snprintf(status, sizeof(status), "Loaded existing key");
            status_ok = true;
        } else {
            key_buf[0] = 0;
            snprintf(status, sizeof(status), "No key configured yet");
            status_ok = true;
        }
        loaded = true;
    }

    nk_layout_row_dynamic(ctx, 20, 1);
    nk_label_colored(ctx, "SETTINGS - NVIDIA API", NK_TEXT_LEFT, IDA_COMMENT);

    nk_layout_row_dynamic(ctx, 18, 1);
    nk_label_colored(ctx,
        "Paste key as 'Bearer nvapi-...' or raw 'nvapi-...'. Save writes nvidia_api_key.txt.",
        NK_TEXT_LEFT, IDA_TEXT2);

    nk_layout_row_dynamic(ctx, 26, 1);
    nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, key_buf, sizeof(key_buf), nk_filter_default);

    nk_layout_row_dynamic(ctx, 26, 3);
    if (nk_button_label(ctx, "Save Key")) {
        status_ok = AISaveConfiguredKey(key_buf, status, (int)sizeof(status));
    }
    if (nk_button_label(ctx, "Reload")) {
        char key[768] = {0};
        if (AIReadConfiguredKey(key, (int)sizeof(key))) {
            snprintf(key_buf, sizeof(key_buf), "Bearer %s", key);
            snprintf(status, sizeof(status), "Reloaded key");
            status_ok = true;
        } else {
            key_buf[0] = 0;
            snprintf(status, sizeof(status), "No key in env/file");
            status_ok = false;
        }
    }
    if (nk_button_label(ctx, "Clear Saved")) {
        status_ok = AIClearConfiguredKey(status, (int)sizeof(status));
        key_buf[0] = 0;
    }

    nk_layout_row_dynamic(ctx, 18, 1);
    nk_label_colored(ctx, status, NK_TEXT_LEFT, status_ok ? IDA_GREEN : IDA_RED);

    nk_layout_row_dynamic(ctx, 18, 1);
    nk_label_colored(ctx,
        "Environment variables NVIDIA_API_KEY/NVAPI_KEY still override file if present.",
        NK_TEXT_LEFT, IDA_TEXT2);
}

/* -- Hex view ------------------------------------------------------ */
static void DrawHex(struct nk_context *ctx, int W, int H)
{
    (void)H;
    nk_layout_row_dynamic(ctx, 22, 1);
    if (nk_button_label(ctx, "Copy All Hex")) {
        if (g_hex.loaded && g_hex.data && g_hex.size) {
            const int COLS = 16;
            SIZE_T rows = (g_hex.size + COLS - 1) / COLS;
            size_t cap = (size_t)rows * 96 + 128;
            char *txt = (char*)malloc(cap);
            if (txt) {
                size_t at = 0;
                for (SIZE_T r = 0; r < rows; r++) {
                    UINT64 row_addr = g_hex.base + r * COLS;
                    SIZE_T row_off  = r * COLS;
                    int n = snprintf(txt + at, cap - at, "%016llX  ", (unsigned long long)row_addr);
                    if (n <= 0 || (size_t)n >= cap - at) break;
                    at += (size_t)n;
                    for (int c = 0; c < COLS && at + 4 < cap; c++) {
                        SIZE_T idx = row_off + c;
                        if (idx < g_hex.size) at += (size_t)snprintf(txt + at, cap - at, "%02X ", g_hex.data[idx]);
                        else at += (size_t)snprintf(txt + at, cap - at, "   ");
                    }
                    if (at + 3 >= cap) break;
                    txt[at++] = '\r'; txt[at++] = '\n'; txt[at] = 0;
                }
                UIClipboardSetText(txt);
                free(txt);
                Log(IDA_GREEN, "[+] Copied hex dump");
            }
        }
    }

    if (!g_hex.loaded || !g_hex.data) {
        nk_layout_row_dynamic(ctx, 20, 1);
        nk_label_colored(ctx, "No data.  Use Goto or click a disasm address.",
                         NK_TEXT_LEFT, IDA_TEXT2);
        return;
    }

    const int COLS = 16;
    SIZE_T rows = (g_hex.size + COLS - 1) / COLS;
    int addr_w   = 140, hex_w = 26 * COLS, asc_w = 12 * COLS;
    (void)W;

    for (SIZE_T r = 0; r < rows; r++) {
        UINT64 row_addr = g_hex.base + r * COLS;
        SIZE_T row_off  = r * COLS;

        nk_layout_row_begin(ctx, NK_STATIC, 17, 3);

        /* address */
        nk_layout_row_push(ctx, (float)addr_w);
        char as[24]; snprintf(as, 24, "%016llX", (unsigned long long)row_addr);
        nk_label_colored(ctx, as, NK_TEXT_LEFT, IDA_ADDR);

        /* hex bytes */
        nk_layout_row_push(ctx, (float)hex_w);
        char hs[256] = "";
        for (int c = 0; c < COLS; c++) {
            SIZE_T idx = row_off + c;
            if (idx < g_hex.size) {
                char h[4]; snprintf(h, 4, "%02X ", g_hex.data[idx]); strcat(hs, h);
            } else {
                strcat(hs, "   ");
            }
            if (c == 7) strcat(hs, " ");
        }
        nk_label_colored(ctx, hs, NK_TEXT_LEFT, IDA_HEX_BYTES);

        /* ASCII */
        nk_layout_row_push(ctx, (float)asc_w);
        char asc[COLS+4]; memset(asc, 0, sizeof(asc));
        for (int c = 0; c < COLS; c++) {
            SIZE_T idx = row_off + c;
            if (idx < g_hex.size) {
                BYTE b = g_hex.data[idx];
                asc[c] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
            } else {
                asc[c] = ' ';
            }
        }
        asc[COLS] = 0;
        nk_label_colored(ctx, asc, NK_TEXT_LEFT, IDA_TEXT);

        nk_layout_row_end(ctx);
    }
}

/* =========================================== Bottom panel =========== */
static void DrawBottom(struct nk_context *ctx, int W, int Y, int H)
{
    nk_flags flags = NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR;
    if (nk_begin(ctx, "##bottom", nk_rect(0, Y, W, H), flags))
    {
        /* dynamic tab list: built-in + plugin extras */
        int n_builtin = 5;
        int n_tabs    = n_builtin + g_extra_panel_count;

        nk_layout_row_begin(ctx, NK_STATIC, 22, n_tabs);
        static const char *btabs[] = {"Output", "AES Keys", "Strings", "Cleaned Disasm", "Live Memory"};

        for (int i = 0; i < n_builtin; i++) {
            int tw = (int)(strlen(btabs[i]) * 9 + 14);
            nk_layout_row_push(ctx, (float)tw);
            bool sel = (g_bot_tab == i);
            if (sel) nk_style_push_color(ctx, &ctx->style.button.normal.data.color,
                                         nk_rgba(0x00,0x5F,0x9E,0xFF));
            if (nk_button_label(ctx, btabs[i])) g_bot_tab = i;
            if (sel) nk_style_pop_color(ctx);
        }
        for (int i = 0; i < g_extra_panel_count; i++) {
            int tw = (int)(strlen(g_extra_panels[i].name) * 9 + 14);
            nk_layout_row_push(ctx, (float)tw);
            bool sel = (g_bot_tab == n_builtin + i);
            if (sel) nk_style_push_color(ctx, &ctx->style.button.normal.data.color,
                                         nk_rgba(0x00,0x5F,0x9E,0xFF));
            if (nk_button_label(ctx, g_extra_panels[i].name)) g_bot_tab = n_builtin + i;
            if (sel) nk_style_pop_color(ctx);
        }
        nk_layout_row_end(ctx);

        nk_layout_row_dynamic(ctx, 1, 1);
        nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

        int panH = H - 22 - 8;
        nk_layout_row_dynamic(ctx, (float)panH, 1);
        if (nk_group_begin(ctx, "##botgrp", NK_WINDOW_BORDER)) {
            if      (g_bot_tab == 0) DrawLogPane(ctx, W-8, panH);
            else if (g_bot_tab == 1) DrawAESPane(ctx, W-8, panH);
            else if (g_bot_tab == 2) DrawStrPane(ctx, W-8, panH);
            else if (g_bot_tab == 3) DrawCleanDisasmPane(ctx, W-8, panH);
            else if (g_bot_tab == 4) DrawLiveMemPane(ctx, W-8, panH);
            else {
                int pi = g_bot_tab - n_builtin;
                if (pi >= 0 && pi < g_extra_panel_count && g_extra_panels[pi].draw)
                    g_extra_panels[pi].draw(ctx);
            }
            nk_group_end(ctx);
        }
    }
    nk_end(ctx);
}

/* -- Output log ---------------------------------------------------- */
static void DrawLogPane(struct nk_context *ctx, int W, int H)
{
    (void)W; (void)H;
    nk_layout_row_dynamic(ctx, 22, 1);
    if (nk_button_label(ctx, "Copy All Output")) {
        EnterCriticalSection(&g_log_cs);
        size_t cap = (size_t)(g_log_count > 0 ? g_log_count : 1) * 560 + 64;
        char *txt = (char*)malloc(cap);
        if (txt) {
            size_t at = 0;
            for (int i = 0; i < g_log_count; i++) {
                int n = snprintf(txt + at, cap - at, "%s\r\n", g_log_lines[i].text);
                if (n <= 0 || (size_t)n >= cap - at) break;
                at += (size_t)n;
            }
            UIClipboardSetText(txt);
            free(txt);
            Log(IDA_GREEN, "[+] Copied output log");
        }
        LeaveCriticalSection(&g_log_cs);
    }

    nk_layout_row_dynamic(ctx, 17, 1);
    EnterCriticalSection(&g_log_cs);
    /* show last N lines that fit */
    int start = g_log_count > 2000 ? g_log_count - 2000 : 0;
    for (int i = start; i < g_log_count; i++) {
        nk_label_colored(ctx, g_log_lines[i].text, NK_TEXT_LEFT, g_log_lines[i].color);
    }
    LeaveCriticalSection(&g_log_cs);
}

/* -- AES Keys pane ------------------------------------------------- */
static void DrawAESPane(struct nk_context *ctx, int W, int H)
{
    (void)H;
    nk_layout_row_dynamic(ctx, 22, 1);
    if (nk_button_label(ctx, "Copy All AES Keys")) {
        EnterCriticalSection(&g_aes_cs);
        size_t cap = (size_t)(g_aes_count > 0 ? g_aes_count : 1) * 220 + 64;
        char *txt = (char*)malloc(cap);
        if (txt) {
            size_t at = 0;
            for (int i = 0; i < g_aes_count; i++) {
                AesKey *k = &g_aes_keys[i];
                int n = snprintf(txt + at, cap - at, "0x%016llX entropy=%.3f note=%s\r\n",
                    (unsigned long long)k->addr, k->entropy, k->note);
                if (n <= 0 || (size_t)n >= cap - at) break;
                at += (size_t)n;
            }
            UIClipboardSetText(txt);
            free(txt);
            Log(IDA_GREEN, "[+] Copied AES key list");
        }
        LeaveCriticalSection(&g_aes_cs);
    }

    char hdr[48]; snprintf(hdr, 48, "AES-256 Candidates  [%d found]%s",
                           g_aes_count, g_scan_running ? "  [scanning...]" : "");
    nk_layout_row_dynamic(ctx, 18, 1);
    nk_label_colored(ctx, hdr, NK_TEXT_LEFT, IDA_COMMENT);

    /* column header */
    nk_layout_row_begin(ctx, NK_STATIC, 17, 4);
    nk_layout_row_push(ctx, 140); nk_label_colored(ctx, "Address",  NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_push(ctx,  55); nk_label_colored(ctx, "Entropy",  NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_push(ctx, 360); nk_label_colored(ctx, "Key Bytes (first 32)", NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_push(ctx, (float)(W-580)); nk_label_colored(ctx, "Note", NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_end(ctx);

    EnterCriticalSection(&g_aes_cs);
    for (int i = 0; i < g_aes_count; i++) {
        AesKey *k = &g_aes_keys[i];
        char addr_s[24], ent_s[16], key_s[100], note_s[100];
        snprintf(addr_s, 24,  "0x%016llX", (unsigned long long)k->addr);
        snprintf(ent_s,  16,  "%.3f", k->entropy);
        /* first 24 bytes */
        key_s[0] = 0;
        for (int b = 0; b < 24; b++) { char h[4]; snprintf(h,4,"%02X ",k->bytes[b]); strcat(key_s,h); }
        snprintf(note_s, 100, "%s", k->note);

        nk_layout_row_begin(ctx, NK_STATIC, 17, 4);
        nk_layout_row_push(ctx, 140); nk_label_colored(ctx, addr_s, NK_TEXT_LEFT, IDA_ADDR);
        nk_layout_row_push(ctx,  55); nk_label_colored(ctx, ent_s,  NK_TEXT_LEFT, IDA_IMM);
        nk_layout_row_push(ctx, 360); nk_label_colored(ctx, key_s,  NK_TEXT_LEFT, IDA_HEX_BYTES);
        nk_layout_row_push(ctx, (float)(W-580)); nk_label_colored(ctx, note_s, NK_TEXT_LEFT, IDA_TEXT2);
        nk_layout_row_end(ctx);
    }
    LeaveCriticalSection(&g_aes_cs);
}

/* -- Strings pane -------------------------------------------------- */
static void DrawStrPane(struct nk_context *ctx, int W, int H)
{
    (void)H;
    nk_layout_row_dynamic(ctx, 22, 1);
    if (nk_button_label(ctx, "Copy All Strings")) {
        EnterCriticalSection(&g_str_cs);
        size_t cap = (size_t)(g_str_count > 0 ? g_str_count : 1) * 320 + 64;
        char *txt = (char*)malloc(cap);
        if (txt) {
            size_t at = 0;
            for (int i = 0; i < g_str_count; i++) {
                FoundString *s = &g_strings[i];
                int n = snprintf(txt + at, cap - at, "0x%016llX len=%d  %s\r\n",
                    (unsigned long long)s->addr, s->len, s->text);
                if (n <= 0 || (size_t)n >= cap - at) break;
                at += (size_t)n;
            }
            UIClipboardSetText(txt);
            free(txt);
            Log(IDA_GREEN, "[+] Copied strings list");
        }
        LeaveCriticalSection(&g_str_cs);
    }

    char hdr[48]; snprintf(hdr, 48, "Strings  [%d found]%s",
                           g_str_count, g_str_scan_running ? "  [scanning...]" : "");
    nk_layout_row_dynamic(ctx, 18, 1);
    nk_label_colored(ctx, hdr, NK_TEXT_LEFT, IDA_COMMENT);

    nk_layout_row_begin(ctx, NK_STATIC, 17, 3);
    nk_layout_row_push(ctx, 140); nk_label_colored(ctx, "Address", NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_push(ctx,  40); nk_label_colored(ctx, "Len",     NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_push(ctx, (float)(W-190)); nk_label_colored(ctx, "String", NK_TEXT_LEFT, IDA_TEXT2);
    nk_layout_row_end(ctx);

    EnterCriticalSection(&g_str_cs);
    /* filter */
    bool has_filter = g_search_buf[0] != 0;
    for (int i = 0; i < g_str_count; i++) {
        FoundString *s = &g_strings[i];
        if (has_filter && !strstr(s->text, g_search_buf)) continue;

        char addr_s[24], len_s[8];
        snprintf(addr_s, 24, "0x%016llX", (unsigned long long)s->addr);
        snprintf(len_s,   8, "%d", s->len);

        nk_layout_row_begin(ctx, NK_STATIC, 17, 3);
        nk_layout_row_push(ctx, 140); nk_label_colored(ctx, addr_s, NK_TEXT_LEFT, IDA_ADDR);
        nk_layout_row_push(ctx,  40); nk_label_colored(ctx, len_s,  NK_TEXT_LEFT, IDA_IMM);
        nk_layout_row_push(ctx, (float)(W-190));
        nk_label_colored(ctx, s->text, NK_TEXT_LEFT, IDA_STR);
        nk_layout_row_end(ctx);
    }
    LeaveCriticalSection(&g_str_cs);
}

/* -- Cleaned disassembly pane ------------------------------------- */
static void DrawCleanDisasmPane(struct nk_context *ctx, int W, int H)
{
    (void)H;
    nk_layout_row_dynamic(ctx, 18, 1);
    nk_label_colored(ctx, "AI CLEANED DISASSEMBLY", NK_TEXT_LEFT, IDA_COMMENT);

    nk_layout_row_dynamic(ctx, 22, 3);
    if (nk_button_label(ctx, g_clean_disasm_running ? "Analyzing..." : "Generate Human-Readable")) {
        if (!g_clean_disasm_running) CleanDisasmRequest();
    }
    if (nk_button_label(ctx, "Copy All")) {
        EnterCriticalSection(&g_clean_disasm_cs);
        if (g_clean_disasm_text[0]) {
            UIClipboardSetText(g_clean_disasm_text);
            Log(IDA_GREEN, "[+] Copied cleaned disassembly");
        }
        LeaveCriticalSection(&g_clean_disasm_cs);
    }
    nk_label_colored(ctx, g_clean_disasm_status, NK_TEXT_LEFT, g_clean_disasm_running ? IDA_YELLOW : IDA_TEXT2);

    nk_layout_row_dynamic(ctx, 1, 1);
    nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

    int list_h = (H > 52) ? (H - 52) : 80;
    nk_layout_row_dynamic(ctx, (float)list_h, 1);
    if (nk_group_begin(ctx, "##clean_disasm_group", NK_WINDOW_BORDER)) {
        EnterCriticalSection(&g_clean_disasm_cs);
        if (!g_clean_disasm_text[0]) {
            nk_layout_row_dynamic(ctx, 18, 1);
            nk_label_colored(ctx,
                "No output yet. Set NVIDIA_API_KEY/NVAPI_KEY (Bearer token is accepted) or add nvidia_api_key.txt.",
                NK_TEXT_LEFT, IDA_TEXT2);
        } else {
            nk_layout_row_dynamic(ctx, 18, 1);
            nk_label_wrap(ctx, g_clean_disasm_text);
        }
        LeaveCriticalSection(&g_clean_disasm_cs);
        nk_group_end(ctx);
    }

    (void)W;
}

/* -- Live memory pane (user-mode) -------------------------------- */
/* -- Live Memory pane - Ring-0 kernel mode ----------------------- */
/* Sub-tab state */
static int  s_live_sub      = 0;   /* 0=Events 1=Watchpoints 2=Regions 3=PhysMap */
static char s_watch_addr[32] = {0};
static char s_watch_size[8]  = {"4"};
static int  s_watch_acc      = K0_WATCH_WRITE;
static char s_watch_label[32]= {0};
static char s_phys_addr[32]  = {0};
static char s_phys_result[64]= {0};
static char s_cr3_buf[32]    = {0};

/* Regions panel state */
#define MAX_LIVE_REGIONS 256
static K0Region s_regions[MAX_LIVE_REGIONS];
static int      s_region_count = 0;
static bool     s_regions_stale = true;

static const char *EvtTypeName(DWORD t)
{
    if (t & K0_EVT_MEM_WRITE)   return "WR";
    if (t & K0_EVT_MEM_READ)    return "RD";
    if (t & K0_EVT_MEM_EXEC)    return "EX";
    if (t & K0_EVT_PAGE_CHANGE) return "CH";
    if (t & K0_EVT_ALLOC)       return "AL";
    if (t & K0_EVT_FREE)        return "FR";
    return "??";
}

static struct nk_color EvtTypeColor(DWORD t)
{
    if (t & K0_EVT_MEM_WRITE)   return IDA_RED;
    if (t & K0_EVT_MEM_READ)    return IDA_CYAN;
    if (t & K0_EVT_MEM_EXEC)    return IDA_YELLOW;
    if (t & K0_EVT_PAGE_CHANGE) return IDA_HEX_BYTES;
    if (t & K0_EVT_ALLOC)       return IDA_GREEN;
    if (t & K0_EVT_FREE)        return IDA_TEXT2;
    return IDA_TEXT;
}

static void DrawLiveEventsPanel(struct nk_context *ctx, int W, int H)
{
    /* Controls row */
    nk_layout_row_dynamic(ctx, 22, 5);
    if (nk_button_label(ctx, g_mem_live_enabled ? "? Pause" : "? Resume"))
        g_mem_live_enabled = !g_mem_live_enabled;
    if (nk_button_label(ctx, "Reset Snap"))
        MemLiveReset();
    if (nk_button_label(ctx, "Clear")) {
        MemLiveClear();
        if (K0IsAvailable()) K0FlushEvents();
    }
    if (nk_button_label(ctx, "Copy All")) {
        EnterCriticalSection(&g_mem_cs);
        size_t cap = (size_t)(g_mem_event_count > 0 ? g_mem_event_count : 1) * 160 + 128;
        char *txt = (char*)malloc(cap);
        if (txt) {
            size_t at = 0;
            for (int i = 0; i < g_mem_event_count; i++) {
                MemEvent *e = &g_mem_events[i];
                int n = snprintf(txt + at, cap - at,
                    "%10lu  %-2s  0x%016llX  %02X->%02X  wp=%u  %s\r\n",
                    (unsigned long)e->tick,
                    EvtTypeName(e->event_type),
                    (unsigned long long)e->addr,
                    e->oldv, e->newv,
                    e->watch_id,
                    e->context);
                if (n <= 0 || (size_t)n >= cap - at) break;
                at += n;
            }
            UIClipboardSetText(txt);
            free(txt);
            Log(IDA_GREEN, "[+] Copied %d events", g_mem_event_count);
        }
        LeaveCriticalSection(&g_mem_cs);
    }
    /* Driver status badge */
    nk_label_colored(ctx,
        K0IsAvailable() ? "? RING-0" : "? USR-MODE",
        NK_TEXT_CENTERED,
        K0IsAvailable() ? IDA_GREEN : IDA_YELLOW);

    /* Status line */
    char stat[256];
    snprintf(stat, sizeof(stat),
             "%s | events=%d | pid=%lu | module=%s",
             g_mem_live_enabled ? "Monitoring" : "Paused",
             g_mem_event_count,
             (unsigned long)g_target_pid,
             g_dll_name[0] ? g_dll_name : "<none>");
    nk_layout_row_dynamic(ctx, 16, 1);
    nk_label_colored(ctx, stat, NK_TEXT_LEFT, IDA_TEXT2);

    nk_layout_row_dynamic(ctx, 1, 1);
    nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

    /* Column header */
    nk_layout_row_begin(ctx, NK_STATIC, 16, 5);
    nk_layout_row_push(ctx, 90);  nk_label_colored(ctx, "Tick",    NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 28);  nk_label_colored(ctx, "Type",   NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 150); nk_label_colored(ctx, "Address",NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 80);  nk_label_colored(ctx, "Old->New",NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, (float)(W - 90 - 28 - 150 - 80 - 20));
                                  nk_label_colored(ctx, "Context",NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_end(ctx);

    int list_h = (H > 110) ? (H - 110) : 60;
    nk_layout_row_dynamic(ctx, (float)list_h, 1);
    if (nk_group_begin(ctx, "##evts", NK_WINDOW_BORDER)) {
        EnterCriticalSection(&g_mem_cs);
        for (int i = g_mem_event_count - 1; i >= 0; i--) {
            MemEvent *e = &g_mem_events[i];
            struct nk_color col = EvtTypeColor(e->event_type);

            nk_layout_row_begin(ctx, NK_STATIC, 16, 5);
            char tmp[64];

            nk_layout_row_push(ctx, 90);
            snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)e->tick);
            nk_label_colored(ctx, tmp, NK_TEXT_LEFT, IDA_TEXT2);

            nk_layout_row_push(ctx, 28);
            nk_label_colored(ctx, EvtTypeName(e->event_type), NK_TEXT_LEFT, col);

            nk_layout_row_push(ctx, 150);
            snprintf(tmp, sizeof(tmp), "0x%016llX", (unsigned long long)e->addr);
            nk_label_colored(ctx, tmp, NK_TEXT_LEFT, IDA_ADDR);

            nk_layout_row_push(ctx, 80);
            snprintf(tmp, sizeof(tmp), "%02X -> %02X", e->oldv, e->newv);
            nk_label_colored(ctx, tmp, NK_TEXT_LEFT, col);

            nk_layout_row_push(ctx, (float)(W - 90 - 28 - 150 - 80 - 20));
            nk_label_colored(ctx,
                e->context[0] ? e->context :
                (e->watch_id ? "(watchpoint)" : "(snapshot diff)"),
                NK_TEXT_LEFT, IDA_TEXT2);

            nk_layout_row_end(ctx);
        }
        LeaveCriticalSection(&g_mem_cs);
        nk_group_end(ctx);
    }
}

static void DrawLiveWatchPanel(struct nk_context *ctx, int W, int H)
{
    (void)H;
    bool k0ok = K0IsAvailable();

    /* Add watchpoint form */
    nk_layout_row_dynamic(ctx, 16, 1);
    nk_label_colored(ctx, "Add Hardware Watchpoint (DR0-DR3):", NK_TEXT_LEFT, IDA_COMMENT);

    nk_layout_row_begin(ctx, NK_STATIC, 22, 5);
    nk_layout_row_push(ctx, 100); nk_label(ctx, "Address:", NK_TEXT_RIGHT);
    nk_layout_row_push(ctx, 140);
    nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, s_watch_addr,
                                   sizeof(s_watch_addr), nk_filter_ascii);
    nk_layout_row_push(ctx, 50);  nk_label(ctx, "Size:", NK_TEXT_RIGHT);
    nk_layout_row_push(ctx, 50);
    nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, s_watch_size,
                                   sizeof(s_watch_size), nk_filter_decimal);
    nk_layout_row_push(ctx, (float)(W - 100 - 140 - 50 - 50 - 20));
    /* placeholder */ nk_label(ctx, "", NK_TEXT_LEFT);
    nk_layout_row_end(ctx);

    nk_layout_row_begin(ctx, NK_STATIC, 22, 6);
    nk_layout_row_push(ctx, 100); nk_label(ctx, "Access:", NK_TEXT_RIGHT);
    nk_layout_row_push(ctx, 50);
    if (nk_button_label(ctx, "R")) s_watch_acc ^= K0_WATCH_READ;
    if (s_watch_acc & K0_WATCH_READ)  { /* highlight done via color push below */ }
    nk_layout_row_push(ctx, 50);
    if (nk_button_label(ctx, "W")) s_watch_acc ^= K0_WATCH_WRITE;
    nk_layout_row_push(ctx, 50);
    if (nk_button_label(ctx, "X")) s_watch_acc ^= K0_WATCH_EXEC;
    nk_layout_row_push(ctx, 100); nk_label(ctx, "Label:", NK_TEXT_RIGHT);
    nk_layout_row_push(ctx, (float)(W - 100 - 50 - 50 - 50 - 100 - 20));
    nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, s_watch_label,
                                   sizeof(s_watch_label), nk_filter_default);
    nk_layout_row_end(ctx);

    nk_layout_row_dynamic(ctx, 22, 2);

    /* Access indicator */
    char acc_str[16];
    snprintf(acc_str, sizeof(acc_str), "Access: %s%s%s",
             (s_watch_acc & K0_WATCH_READ)  ? "R" : "-",
             (s_watch_acc & K0_WATCH_WRITE) ? "W" : "-",
             (s_watch_acc & K0_WATCH_EXEC)  ? "X" : "-");
    nk_label_colored(ctx, acc_str, NK_TEXT_LEFT,
                     s_watch_acc ? IDA_GREEN : IDA_TEXT2);

    if (nk_button_label(ctx, k0ok ? "ARM Watchpoint" : "Add (no driver)")) {
        UINT64 addr = 0;
        sscanf(s_watch_addr, "%llx", (unsigned long long*)&addr);
        DWORD sz = (DWORD)atoi(s_watch_size);
        if (sz == 0) sz = 1;
        if (addr)
            MemLiveWatchAdd(addr, sz, s_watch_acc ? s_watch_acc : K0_WATCH_WRITE,
                            s_watch_label[0] ? s_watch_label : NULL);
        else
            Log(IDA_RED, "[K0] Enter a valid hex address");
    }

    nk_layout_row_dynamic(ctx, 1, 1);
    nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

    /* Active watchpoints table */
    nk_layout_row_dynamic(ctx, 16, 1);
    nk_label_colored(ctx, "Active Watchpoints:", NK_TEXT_LEFT, IDA_COMMENT);

    int wcount = 0;
    void *wptr = MemLiveGetWatches(&wcount);
    /* Cast via char* to avoid including the struct definition in dkid_ui.c.
       The struct layout is: bool(4) UINT64 DWORD DWORD DWORD char[64] */
    typedef struct {
        bool   active; char _pad[3];
        UINT64 addr;
        DWORD  size, access, k0_id;
        char   label[64];
    } _LW;
    _LW *ws = (_LW*)wptr;

    nk_layout_row_begin(ctx, NK_STATIC, 16, 5);
    nk_layout_row_push(ctx, 24);  nk_label_colored(ctx, "#",       NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 140); nk_label_colored(ctx, "Address", NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 40);  nk_label_colored(ctx, "Sz",      NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 40);  nk_label_colored(ctx, "Acc",     NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, (float)(W - 24 - 140 - 40 - 40 - 20));
                                  nk_label_colored(ctx, "Label",   NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_end(ctx);

    for (int i = 0; i < wcount; i++) {
        if (!ws[i].active) continue;
        char tmp[64];
        nk_layout_row_begin(ctx, NK_STATIC, 20, 6);

        nk_layout_row_push(ctx, 24);
        snprintf(tmp, sizeof(tmp), "%d", i);
        nk_label_colored(ctx, tmp, NK_TEXT_LEFT, IDA_TEXT2);

        nk_layout_row_push(ctx, 140);
        snprintf(tmp, sizeof(tmp), "0x%016llX", (unsigned long long)ws[i].addr);
        nk_label_colored(ctx, tmp, NK_TEXT_LEFT, IDA_ADDR);

        nk_layout_row_push(ctx, 40);
        snprintf(tmp, sizeof(tmp), "%u", ws[i].size);
        nk_label_colored(ctx, tmp, NK_TEXT_LEFT, IDA_TEXT);

        nk_layout_row_push(ctx, 40);
        snprintf(tmp, sizeof(tmp), "%s%s%s",
                 (ws[i].access & K0_WATCH_READ)  ? "R" : "",
                 (ws[i].access & K0_WATCH_WRITE) ? "W" : "",
                 (ws[i].access & K0_WATCH_EXEC)  ? "X" : "");
        nk_label_colored(ctx, tmp, NK_TEXT_LEFT, IDA_YELLOW);

        nk_layout_row_push(ctx, (float)(W - 24 - 140 - 40 - 40 - 60 - 20));
        nk_label_colored(ctx, ws[i].label, NK_TEXT_LEFT, IDA_TEXT2);

        nk_layout_row_push(ctx, 55);
        snprintf(tmp, sizeof(tmp), "Del##w%d", i);
        if (nk_button_label(ctx, tmp))
            MemLiveWatchRemove(i);

        nk_layout_row_end(ctx);
    }
    if (wcount == 0)
        nk_label_colored(ctx, "  (none)", NK_TEXT_LEFT, IDA_TEXT2);
}

static void DrawLiveRegionsPanel(struct nk_context *ctx, int W, int H)
{
    nk_layout_row_dynamic(ctx, 22, 3);
    if (nk_button_label(ctx, "Refresh Regions")) {
        if (K0IsAvailable() && g_target_pid) {
            s_region_count = K0QueryRegions(g_target_pid, 0,
                                            s_regions, MAX_LIVE_REGIONS);
            s_regions_stale = false;
            Log(IDA_TEXT2, "[K0] %d committed regions", s_region_count);
        } else {
            Log(IDA_YELLOW, "[K0] Driver required for region enumeration");
        }
    }
    char rbuf[64];
    snprintf(rbuf, sizeof(rbuf), "%d regions", s_region_count);
    nk_label_colored(ctx, rbuf, NK_TEXT_LEFT, IDA_TEXT2);
    nk_label_colored(ctx,
        s_regions_stale ? "(stale - click Refresh)" : "(up to date)",
        NK_TEXT_LEFT, s_regions_stale ? IDA_YELLOW : IDA_GREEN);

    /* Header */
    nk_layout_row_begin(ctx, NK_STATIC, 16, 5);
    nk_layout_row_push(ctx, 150); nk_label_colored(ctx, "Base",      NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 90);  nk_label_colored(ctx, "Size",      NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 70);  nk_label_colored(ctx, "Protect",   NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, 60);  nk_label_colored(ctx, "Type",      NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_push(ctx, (float)(W - 150 - 90 - 70 - 60 - 20));
                                  nk_label_colored(ctx, "Module",    NK_TEXT_LEFT, IDA_COMMENT);
    nk_layout_row_end(ctx);

    nk_layout_row_dynamic(ctx, 1, 1);
    nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

    int list_h = H > 80 ? H - 80 : 40;
    nk_layout_row_dynamic(ctx, (float)list_h, 1);
    if (nk_group_begin(ctx, "##regions", NK_WINDOW_BORDER)) {
        for (int i = 0; i < s_region_count; i++) {
            K0Region *r = &s_regions[i];
            char tmp[64];

            nk_layout_row_begin(ctx, NK_STATIC, 16, 5);

            nk_layout_row_push(ctx, 150);
            snprintf(tmp, sizeof(tmp), "0x%016llX", (unsigned long long)r->base);
            nk_label_colored(ctx, tmp, NK_TEXT_LEFT, IDA_ADDR);

            nk_layout_row_push(ctx, 90);
            if (r->size >= 1024*1024)
                snprintf(tmp, sizeof(tmp), "%lu MB", (unsigned long)(r->size >> 20));
            else if (r->size >= 1024)
                snprintf(tmp, sizeof(tmp), "%lu KB", (unsigned long)(r->size >> 10));
            else
                snprintf(tmp, sizeof(tmp), "%lu B", (unsigned long)r->size);
            nk_label_colored(ctx, tmp, NK_TEXT_LEFT, IDA_TEXT);

            nk_layout_row_push(ctx, 70);
            /* Decode PAGE_* */
            const char *prot = "???";
            switch (r->protect & 0xFF) {
                case 0x01: prot = "---";   break;
                case 0x02: prot = "R--";   break;
                case 0x04: prot = "RW-";   break;
                case 0x08: prot = "WC-";   break;
                case 0x10: prot = "--X";   break;
                case 0x20: prot = "R-X";   break;
                case 0x40: prot = "RWX";   break;
                case 0x80: prot = "WCX";   break;
            }
            struct nk_color pc = (r->protect & 0x40) ? IDA_RED :
                                 (r->protect & 0x10 || r->protect & 0x20) ? IDA_YELLOW : IDA_TEXT;
            nk_label_colored(ctx, prot, NK_TEXT_LEFT, pc);

            nk_layout_row_push(ctx, 60);
            const char *ty = r->type == 0x1000000 ? "IMG" :
                             r->type == 0x40000   ? "MAP" : "PRV";
            nk_label_colored(ctx, ty, NK_TEXT_LEFT, IDA_TEXT2);

            nk_layout_row_push(ctx, (float)(W - 150 - 90 - 70 - 60 - 20));
            nk_label_colored(ctx,
                r->mapped_file[0] ? r->mapped_file : "",
                NK_TEXT_LEFT, IDA_COMMENT);

            nk_layout_row_end(ctx);
        }
        nk_group_end(ctx);
    }
}

static void DrawLivePhysPanel(struct nk_context *ctx, int W, int H)
{
    (void)W; (void)H;
    bool k0ok = K0IsAvailable();

    nk_layout_row_dynamic(ctx, 16, 1);
    nk_label_colored(ctx,
        "Physical Memory Mapping  (requires Ring-0 driver)",
        NK_TEXT_LEFT, IDA_COMMENT);

    /* CR3 row */
    nk_layout_row_begin(ctx, NK_STATIC, 22, 3);
    nk_layout_row_push(ctx, 60); nk_label(ctx, "CR3:", NK_TEXT_RIGHT);
    nk_layout_row_push(ctx, 180);
    nk_label_colored(ctx, s_cr3_buf[0] ? s_cr3_buf : "(not read)",
                     NK_TEXT_LEFT, IDA_IMM);
    nk_layout_row_push(ctx, 100);
    if (nk_button_label(ctx, "Read CR3")) {
        UINT64 cr3 = 0;
        if (K0GetCR3(&cr3))
            snprintf(s_cr3_buf, sizeof(s_cr3_buf), "0x%016llX",
                     (unsigned long long)cr3);
        else
            strncpy(s_cr3_buf, "(unavailable)", sizeof(s_cr3_buf)-1);
    }
    nk_layout_row_end(ctx);

    nk_layout_row_dynamic(ctx, 1, 1);
    nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

    /* VA -> PA translator */
    nk_layout_row_dynamic(ctx, 16, 1);
    nk_label_colored(ctx, "VA -> Physical Address Translation:",
                     NK_TEXT_LEFT, IDA_COMMENT);

    nk_layout_row_begin(ctx, NK_STATIC, 22, 4);
    nk_layout_row_push(ctx, 60);  nk_label(ctx, "VA:", NK_TEXT_RIGHT);
    nk_layout_row_push(ctx, 180);
    nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD,
                                   s_phys_addr, sizeof(s_phys_addr),
                                   nk_filter_ascii);
    nk_layout_row_push(ctx, 100);
    if (nk_button_label(ctx, k0ok ? "Translate" : "(no driver)")) {
        if (k0ok && g_target_pid) {
            UINT64 va = 0, pa = 0;
            sscanf(s_phys_addr, "%llx", (unsigned long long *)&va);
            if (K0GetPhysAddr(g_target_pid, va, &pa))
                snprintf(s_phys_result, sizeof(s_phys_result),
                         "PA = 0x%016llX", (unsigned long long)pa);
            else
                strncpy(s_phys_result, "Translation failed", sizeof(s_phys_result)-1);
        } else {
            strncpy(s_phys_result, "Driver not loaded", sizeof(s_phys_result)-1);
        }
    }
    nk_layout_row_push(ctx, (float)(W - 60 - 180 - 100 - 20));
    nk_label_colored(ctx,
                     s_phys_result[0] ? s_phys_result : "",
                     NK_TEXT_LEFT, IDA_GREEN);
    nk_layout_row_end(ctx);

    nk_layout_row_dynamic(ctx, 1, 1);
    nk_rule_horizontal(ctx, IDA_BORDER, nk_false);

    /* Driver info */
    nk_layout_row_dynamic(ctx, 16, 1);
    nk_label_colored(ctx, "Driver Status:", NK_TEXT_LEFT, IDA_COMMENT);

    char info[256];
    snprintf(info, sizeof(info),
        "K0Probe: %s   |   Target PID: %lu   |   DR watchpoints: up to 4 (DR0-DR3)",
        k0ok ? "LOADED (ring-0 active)" : "NOT LOADED - run:  sc start K0Probe",
        (unsigned long)g_target_pid);
    nk_layout_row_dynamic(ctx, 16, 1);
    nk_label_colored(ctx, info, NK_TEXT_LEFT,
                     k0ok ? IDA_GREEN : IDA_YELLOW);

    if (!k0ok) {
        nk_layout_row_dynamic(ctx, 16, 1);
        nk_label_colored(ctx,
            "  To load:  sc create K0Probe type= kernel start= demand binPath= <path>\\k0probe.sys",
            NK_TEXT_LEFT, IDA_TEXT2);
        nk_label_colored(ctx,
            "  Then:     sc start K0Probe   (requires Admin + test-signing or EV cert)",
            NK_TEXT_LEFT, IDA_TEXT2);
        nk_label_colored(ctx,
            "  Test mode: bcdedit /set testsigning on  (then reboot)",
            NK_TEXT_LEFT, IDA_TEXT2);
    }
}

static void DrawLiveMemPane(struct nk_context *ctx, int W, int H)
{
    (void)W;

    /* Sub-tab bar */
    static const char *stabs[] = {"Events", "Watchpoints", "Regions", "Phys Map"};
    nk_layout_row_dynamic(ctx, 22, 4);
    for (int i = 0; i < 4; i++) {
        bool sel = (s_live_sub == i);
        if (sel) nk_style_push_color(ctx,
            &ctx->style.button.normal.data.color, IDA_SEL);
        if (nk_button_label(ctx, stabs[i])) s_live_sub = i;
        if (sel) nk_style_pop_color(ctx);
    }

    nk_layout_row_dynamic(ctx, 1, 1);
    nk_rule_horizontal(ctx, IDA_ACCENT, nk_false);

    int sub_h = (H > 46) ? H - 46 : 10;

    switch (s_live_sub) {
    case 0: DrawLiveEventsPanel  (ctx, W, sub_h); break;
    case 1: DrawLiveWatchPanel   (ctx, W, sub_h); break;
    case 2: DrawLiveRegionsPanel (ctx, W, sub_h); break;
    case 3: DrawLivePhysPanel    (ctx, W, sub_h); break;
    }
}

/* =========================================== Status bar ============= */
static void DrawStatus(struct nk_context *ctx, int W, int H)
{
    nk_flags flags = NK_WINDOW_NO_SCROLLBAR | NK_WINDOW_BACKGROUND;
    if (nk_begin(ctx, "##status", nk_rect(0, H-STAT_H, W, STAT_H), flags))
    {
        nk_layout_row_begin(ctx, NK_STATIC, STAT_H-4, 5);
        nk_layout_row_push(ctx, (float)(W-400));
        nk_label_colored(ctx, g_status, NK_TEXT_LEFT, IDA_TEXT);

        nk_layout_row_push(ctx, 120);
        char mod_s[32] = "";
        if (g_dll_base) snprintf(mod_s, 32, "  Base: %08llX", (unsigned long long)g_dll_base);
        nk_label_colored(ctx, mod_s, NK_TEXT_LEFT, IDA_ADDR);

        nk_layout_row_push(ctx, 80);
        nk_label_colored(ctx, g_attached ? "  ATTACHED" : "", NK_TEXT_LEFT, IDA_GREEN);

        nk_layout_row_push(ctx, 90);
        nk_label_colored(ctx, g_scan_running ? "  SCANNING..." : "", NK_TEXT_LEFT, IDA_YELLOW);

        nk_layout_row_push(ctx, 90);
        char key_s[32] = "";
        if (g_aes_count) snprintf(key_s, 32, "  KEYS: %d", g_aes_count);
        nk_label_colored(ctx, key_s, NK_TEXT_LEFT, IDA_GREEN);

        nk_layout_row_end(ctx);
    }
    nk_end(ctx);
}
