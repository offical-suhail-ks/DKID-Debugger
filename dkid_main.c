/* dkid_main.c - WinMain, window class, Nuklear message loop */
/* NK_WIN_IMPLEMENTATION is defined exactly once in nk_impl.c - do NOT redefine here */
#include "dkid.h"
#include "nk_win.h"

static NkWin  g_nk;
static NkFont *g_font_code = NULL;
static NkFont *g_font_ui   = NULL;
static NkFont *g_font_bold = NULL;
static bool    g_quit      = false;
static int     g_win_w     = 1600;
static int     g_win_h     = 960;
static DWORD   g_last_proc_refresh = 0;
static DWORD   g_last_mod_refresh = 0;
static DWORD   g_last_disasm_refresh = 0;
static DWORD   g_last_mem_refresh = 0;

/* -- window procedure ----------------------------------------------- */
static LRESULT CALLBACK WndProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        g_quit = true;
        return 0;
    case WM_SIZE:
        if (wp != SIZE_MINIMIZED) {
            g_win_w = LOWORD(lp);
            g_win_h = HIWORD(lp);
            nk_win_resize(&g_nk, g_win_w, g_win_h);
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        BeginPaint(wnd, &ps);
        EndPaint(wnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    default:
        return DefWindowProcA(wnd, msg, wp, lp);
    }
}

/* -- WinMain -------------------------------------------------------- */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hPrev; (void)lpCmd;

    /* Init critical sections */
    InitializeCriticalSection(&g_aes_cs);
    InitializeCriticalSection(&g_str_cs);
    InitializeCriticalSection(&g_disasm_cs);
    InitializeCriticalSection(&g_log_cs);
    InitializeCriticalSection(&g_clean_disasm_cs);
    InitializeCriticalSection(&g_mem_cs);

    /* Log buffer */
    g_log_cap   = MAX_LOG_LINES;
    g_log_lines = (LogLine *)calloc(g_log_cap, sizeof(LogLine));

    /* Register window class */
    WNDCLASSEXA wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = APP_CLASS;
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExA(&wc);

    HWND hwnd = CreateWindowExA(
        WS_EX_APPWINDOW,
        APP_CLASS,
        APP_NAME " v" APP_VERSION " - Advanced Memory Analysis",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        g_win_w, g_win_h,
        NULL, NULL, hInst, NULL);

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    /* Create fonts */
    g_font_code = nk_win_font_create("Consolas",  14, 0);
    g_font_ui   = nk_win_font_create("Segoe UI",  14, 0);
    g_font_bold = nk_win_font_create("Segoe UI",  14, 1);

    /* Init Nuklear */
    nk_win_init(&g_nk, hwnd, g_font_code, g_win_w, g_win_h);
    UISetTheme(&g_nk.ctx);

    /* Init plugins (loads ./plugins/*.dll) */
    PluginInit();

    /* Attempt to connect to the K0Probe ring-0 driver */
    K0Init();

    /* Initial process list */
    ProcRefresh();
    g_last_proc_refresh = GetTickCount();
    g_last_mod_refresh = g_last_proc_refresh;
    g_last_disasm_refresh = g_last_proc_refresh;
    g_last_mem_refresh = g_last_proc_refresh;
    Log(IDA_GREEN, "DKID v" APP_VERSION " ready  -  attach a process to begin");

    /* -- main loop --------------------------------------------------- */
    while (!g_quit)
    {
        MSG msg;

        /* --- begin input frame --- */
        nk_input_begin(&g_nk.ctx);
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT) { g_quit = true; break; }
            TranslateMessage(&msg);
            DispatchMessage(&msg);

            /* route input to Nuklear */
            switch (msg.message)
            {
            case WM_LBUTTONDOWN:
            case WM_LBUTTONDBLCLK:
                SetCapture(hwnd);
                nk_win_mouse_button(&g_nk, NK_BUTTON_LEFT,
                    GET_X_LPARAM(msg.lParam), GET_Y_LPARAM(msg.lParam), 1);
                break;
            case WM_LBUTTONUP:
                ReleaseCapture();
                nk_win_mouse_button(&g_nk, NK_BUTTON_LEFT,
                    GET_X_LPARAM(msg.lParam), GET_Y_LPARAM(msg.lParam), 0);
                break;
            case WM_RBUTTONDOWN:
            case WM_RBUTTONDBLCLK:
                nk_win_mouse_button(&g_nk, NK_BUTTON_RIGHT,
                    GET_X_LPARAM(msg.lParam), GET_Y_LPARAM(msg.lParam), 1);
                break;
            case WM_RBUTTONUP:
                nk_win_mouse_button(&g_nk, NK_BUTTON_RIGHT,
                    GET_X_LPARAM(msg.lParam), GET_Y_LPARAM(msg.lParam), 0);
                break;
            case WM_MBUTTONDOWN:
                nk_win_mouse_button(&g_nk, NK_BUTTON_MIDDLE,
                    GET_X_LPARAM(msg.lParam), GET_Y_LPARAM(msg.lParam), 1);
                break;
            case WM_MBUTTONUP:
                nk_win_mouse_button(&g_nk, NK_BUTTON_MIDDLE,
                    GET_X_LPARAM(msg.lParam), GET_Y_LPARAM(msg.lParam), 0);
                break;
            case WM_MOUSEMOVE:
                nk_win_mouse_move(&g_nk,
                    GET_X_LPARAM(msg.lParam), GET_Y_LPARAM(msg.lParam));
                break;
            case WM_MOUSEWHEEL:
                nk_win_mouse_wheel(&g_nk, GET_WHEEL_DELTA_WPARAM(msg.wParam));
                break;
            case WM_KEYDOWN:
            case WM_SYSKEYDOWN:
                nk_win_key(&g_nk, (int)msg.wParam, 1);
                break;
            case WM_KEYUP:
            case WM_SYSKEYUP:
                nk_win_key(&g_nk, (int)msg.wParam, 0);
                break;
            case WM_CHAR:
                nk_win_char(&g_nk, (unsigned int)msg.wParam);
                break;
            }
        }
        nk_input_end(&g_nk.ctx);

        /* --- build UI --- */
        {
            DWORD now = GetTickCount();
            if (!g_attached) {
                if (now - g_last_proc_refresh > 3000) {
                    ProcRefresh();
                    g_last_proc_refresh = now;
                }
            } else {
                /* Live module tracking while attached. */
                if (now - g_last_mod_refresh > 2000) {
                    ModRefreshLive();
                    g_last_mod_refresh = now;
                }

                /* Live disassembly refresh for the currently selected module. */
                if (g_main_tab == 0 && g_mod_sel >= 0 && now - g_last_disasm_refresh > 1200) {
                    DisasmRefreshLive();
                    g_last_disasm_refresh = now;
                }

                if (now - g_last_mem_refresh > 600) {
                    MemLiveTick();
                    g_last_mem_refresh = now;
                }
            }
        }

        UIBuild(&g_nk.ctx, g_win_w, g_win_h);

        /* --- render --- */
        nk_win_render(&g_nk);

        /* yield ~16 ms so we don't spin at 100% CPU */
        Sleep(8);
    }

    /* cleanup */
    PluginShutdown();
    K0Shutdown();
    nk_win_shutdown(&g_nk);
    nk_win_font_destroy(g_font_bold);
    nk_win_font_destroy(g_font_ui);
    nk_win_font_destroy(g_font_code);
    HexFree();
    free(g_log_lines);
    DeleteCriticalSection(&g_aes_cs);
    DeleteCriticalSection(&g_str_cs);
    DeleteCriticalSection(&g_disasm_cs);
    DeleteCriticalSection(&g_log_cs);
    DeleteCriticalSection(&g_clean_disasm_cs);
    DeleteCriticalSection(&g_mem_cs);
    return 0;
}
