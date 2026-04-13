/*
 * nk_win.h - Nuklear Win32 GDI backend (pure C, no GDI+)
 * Include with  #define NK_WIN_IMPLEMENTATION  in exactly ONE .c file.
 */
#pragma once
#ifndef NK_WIN_H
#define NK_WIN_H

#include <windows.h>
#include "nuklear.h"

/* -- types -------------------------------------------------------- */
typedef struct {
    HFONT             handle;
    HDC               measure_dc;
    int               height;       /* pixel height */
    struct nk_user_font nk;
} NkFont;

typedef struct {
    HWND    wnd;
    HDC     dc;        /* window DC (permanent) */
    HDC     mem_dc;    /* back-buffer DC */
    HBITMAP mem_bmp;
    HBITMAP old_bmp;
    int     width, height;
    NkFont *font;
    struct nk_context ctx;
} NkWin;

/* -- API ----------------------------------------------------------- */
NkFont *nk_win_font_create(const char *name, int size, int bold);
void    nk_win_font_destroy(NkFont *f);
void    nk_win_init   (NkWin *g, HWND wnd, NkFont *font, int w, int h);
void    nk_win_resize (NkWin *g, int w, int h);
void    nk_win_render (NkWin *g);
void    nk_win_shutdown(NkWin *g);

/* Input helpers - call from main message-loop: */
void nk_win_mouse_move  (NkWin *g, int x, int y);
void nk_win_mouse_button(NkWin *g, enum nk_buttons btn, int x, int y, int down);
void nk_win_mouse_wheel (NkWin *g, int delta);
void nk_win_key         (NkWin *g, int vk, int down);
void nk_win_char        (NkWin *g, unsigned int c);

#ifdef NK_WIN_IMPLEMENTATION
/* --------------------------- IMPLEMENTATION ------------------------ */

/* -- font text-width callback ------------------------------------ */
static float
s_nk_text_width(nk_handle handle, float height, const char *text, int len)
{
    NkFont *f = (NkFont *)handle.ptr;
    (void)height;
    if (!f || !text || len <= 0) return 0.f;
    SIZE sz = {0};
    HFONT old = (HFONT)SelectObject(f->measure_dc, f->handle);
    GetTextExtentPoint32A(f->measure_dc, text, len, &sz);
    SelectObject(f->measure_dc, old);
    return (float)sz.cx;
}

/* -- public: create font ------------------------------------------- */
NkFont *nk_win_font_create(const char *name, int size, int bold)
{
    NkFont *f = (NkFont *)calloc(1, sizeof(NkFont));
    if (!f) return NULL;
    f->handle = CreateFontA(
        -size, 0, 0, 0,
        bold ? FW_BOLD : FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
        name);
    f->measure_dc = CreateCompatibleDC(NULL);

    /* measure actual cell height */
    HFONT old = (HFONT)SelectObject(f->measure_dc, f->handle);
    TEXTMETRICA tm = {0};
    GetTextMetricsA(f->measure_dc, &tm);
    f->height = tm.tmHeight;
    SelectObject(f->measure_dc, old);

    f->nk.userdata.ptr = f;
    f->nk.height       = (float)f->height;
    f->nk.width        = s_nk_text_width;
    return f;
}

void nk_win_font_destroy(NkFont *f)
{
    if (!f) return;
    DeleteDC(f->measure_dc);
    DeleteObject(f->handle);
    free(f);
}

/* -- helper: nk_color -> COLORREF -------------------------------- */
static COLORREF s_c2gdi(struct nk_color c) { return RGB(c.r, c.g, c.b); }

/* -- clipboard bridge for Nuklear text edit ----------------------- */
static void s_nk_clipboard_copy(nk_handle usr, const char *text, int len)
{
    (void)usr;
    if (!text || len <= 0) return;

    if (!OpenClipboard(NULL)) return;
    EmptyClipboard();

    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)len + 1);
    if (h) {
        char *dst = (char*)GlobalLock(h);
        if (dst) {
            memcpy(dst, text, (size_t)len);
            dst[len] = 0;
            GlobalUnlock(h);
            SetClipboardData(CF_TEXT, h);
            h = NULL; /* ownership transferred to clipboard */
        }
    }
    if (h) GlobalFree(h);
    CloseClipboard();
}

static void s_nk_clipboard_paste(nk_handle usr, struct nk_text_edit *edit)
{
    (void)usr;
    if (!edit) return;

    if (!OpenClipboard(NULL)) return;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (h) {
        const char *src = (const char*)GlobalLock(h);
        if (src) {
            nk_textedit_paste(edit, src, nk_strlen(src));
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
}

/* -- init / resize / shutdown -------------------------------------- */
void nk_win_init(NkWin *g, HWND wnd, NkFont *font, int w, int h)
{
    g->wnd    = wnd;
    g->dc     = GetDC(wnd);
    g->font   = font;
    g->width  = w;
    g->height = h;

    g->mem_dc  = CreateCompatibleDC(g->dc);
    g->mem_bmp = CreateCompatibleBitmap(g->dc, w, h);
    g->old_bmp = (HBITMAP)SelectObject(g->mem_dc, g->mem_bmp);

    SetBkMode(g->mem_dc, TRANSPARENT);
    nk_init_default(&g->ctx, &font->nk);
    g->ctx.clip.copy  = s_nk_clipboard_copy;
    g->ctx.clip.paste = s_nk_clipboard_paste;
    g->ctx.clip.userdata.ptr = g;
}

void nk_win_resize(NkWin *g, int w, int h)
{
    if (w == g->width && h == g->height) return;
    g->width = w; g->height = h;
    SelectObject(g->mem_dc, g->old_bmp);
    DeleteObject(g->mem_bmp);
    g->mem_bmp = CreateCompatibleBitmap(g->dc, w, h);
    g->old_bmp = (HBITMAP)SelectObject(g->mem_dc, g->mem_bmp);
    SetBkMode(g->mem_dc, TRANSPARENT);
}

void nk_win_shutdown(NkWin *g)
{
    nk_free(&g->ctx);
    SelectObject(g->mem_dc, g->old_bmp);
    DeleteObject(g->mem_bmp);
    DeleteDC(g->mem_dc);
    ReleaseDC(g->wnd, g->dc);
}

/* -- render -------------------------------------------------------- */
void nk_win_render(NkWin *g)
{
    HDC dc = g->mem_dc;
    int W  = g->width, H = g->height;

    /* clear to background */
    {
        HBRUSH bg = CreateSolidBrush(RGB(0x1E,0x1E,0x1E));
        RECT   r  = {0, 0, W, H};
        FillRect(dc, &r, bg);
        DeleteObject(bg);
    }

    const struct nk_command *cmd;
    nk_foreach(cmd, &g->ctx)
    {
        switch (cmd->type)
        {
        case NK_COMMAND_NOP: break;

        /* -- scissor ------------------------------- */
        case NK_COMMAND_SCISSOR: {
            const struct nk_command_scissor *s = (const void *)cmd;
            if (s->x < 0 || s->y < 0) {
                SelectClipRgn(dc, NULL);
            } else {
                int x2 = s->x + s->w, y2 = s->y + s->h;
                if (x2 > W) x2 = W;
                if (y2 > H) y2 = H;
                HRGN rgn = CreateRectRgn(s->x, s->y, x2, y2);
                SelectClipRgn(dc, rgn);
                DeleteObject(rgn);
            }
        } break;

        /* -- line ---------------------------------- */
        case NK_COMMAND_LINE: {
            const struct nk_command_line *l = (const void *)cmd;
            HPEN pen = CreatePen(PS_SOLID, l->line_thickness, s_c2gdi(l->color));
            HPEN op  = (HPEN)SelectObject(dc, pen);
            MoveToEx(dc, l->begin.x, l->begin.y, NULL);
            LineTo  (dc, l->end.x,   l->end.y);
            SelectObject(dc, op); DeleteObject(pen);
        } break;

        /* -- curve (approx as line) ---------------- */
        case NK_COMMAND_CURVE: {
            const struct nk_command_curve *c = (const void *)cmd;
            HPEN pen = CreatePen(PS_SOLID, c->line_thickness, s_c2gdi(c->color));
            HPEN op  = (HPEN)SelectObject(dc, pen);
            MoveToEx(dc, c->begin.x, c->begin.y, NULL);
            LineTo  (dc, c->end.x,   c->end.y);
            SelectObject(dc, op); DeleteObject(pen);
        } break;

        /* -- rect outline -------------------------- */
        case NK_COMMAND_RECT: {
            const struct nk_command_rect *r = (const void *)cmd;
            HPEN   pen = CreatePen(PS_SOLID, r->line_thickness, s_c2gdi(r->color));
            HPEN   op  = (HPEN)SelectObject(dc, pen);
            HBRUSH ob  = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
            if (r->rounding > 0)
                RoundRect(dc, r->x, r->y, r->x+r->w, r->y+r->h, r->rounding*2, r->rounding*2);
            else
                Rectangle(dc, r->x, r->y, r->x+r->w, r->y+r->h);
            SelectObject(dc, op); SelectObject(dc, ob); DeleteObject(pen);
        } break;

        /* -- filled rect --------------------------- */
        case NK_COMMAND_RECT_FILLED: {
            const struct nk_command_rect_filled *r = (const void *)cmd;
            HBRUSH br  = CreateSolidBrush(s_c2gdi(r->color));
            if (r->rounding > 0) {
                HPEN pen = CreatePen(PS_SOLID, 1, s_c2gdi(r->color));
                HPEN op  = (HPEN)SelectObject(dc, pen);
                HBRUSH ob = (HBRUSH)SelectObject(dc, br);
                RoundRect(dc, r->x, r->y, r->x+r->w, r->y+r->h, r->rounding*2, r->rounding*2);
                SelectObject(dc, op); SelectObject(dc, ob); DeleteObject(pen);
            } else {
                RECT rc = {r->x, r->y, r->x+r->w, r->y+r->h};
                FillRect(dc, &rc, br);
            }
            DeleteObject(br);
        } break;

        /* -- filled triangle ----------------------- */
        case NK_COMMAND_TRIANGLE_FILLED: {
            const struct nk_command_triangle_filled *t = (const void *)cmd;
            HBRUSH br  = CreateSolidBrush(s_c2gdi(t->color));
            HPEN   pen = CreatePen(PS_SOLID, 1, s_c2gdi(t->color));
            HPEN   op  = (HPEN)SelectObject(dc, pen);
            HBRUSH ob  = (HBRUSH)SelectObject(dc, br);
            POINT pts[3] = {{t->a.x,t->a.y},{t->b.x,t->b.y},{t->c.x,t->c.y}};
            Polygon(dc, pts, 3);
            SelectObject(dc, op); SelectObject(dc, ob);
            DeleteObject(pen); DeleteObject(br);
        } break;

        /* -- circle -------------------------------- */
        case NK_COMMAND_CIRCLE_FILLED: {
            const struct nk_command_circle_filled *c = (const void *)cmd;
            HBRUSH br  = CreateSolidBrush(s_c2gdi(c->color));
            HPEN   pen = CreatePen(PS_SOLID, 1, s_c2gdi(c->color));
            HPEN   op  = (HPEN)SelectObject(dc, pen);
            HBRUSH ob  = (HBRUSH)SelectObject(dc, br);
            Ellipse(dc, c->x, c->y, c->x+c->w, c->y+c->h);
            SelectObject(dc, op); SelectObject(dc, ob);
            DeleteObject(pen); DeleteObject(br);
        } break;

        /* -- text ---------------------------------- */
        case NK_COMMAND_TEXT: {
            const struct nk_command_text *t = (const void *)cmd;
            NkFont *f = (NkFont *)t->font->userdata.ptr;
            if (!f) break;
            HFONT old = (HFONT)SelectObject(dc, f->handle);
            SetTextColor(dc, s_c2gdi(t->foreground));
            SetBkMode(dc, TRANSPARENT);
            TextOutA(dc, t->x, t->y, t->string, t->length);
            SelectObject(dc, old);
        } break;

        case NK_COMMAND_IMAGE:  break;
        case NK_COMMAND_CUSTOM: break;
        default:                break;
        }
    }

    /* reset clip & blit */
    SelectClipRgn(dc, NULL);
    BitBlt(g->dc, 0, 0, W, H, dc, 0, 0, SRCCOPY);
    nk_clear(&g->ctx);
}

/* -- input --------------------------------------------------------- */
void nk_win_mouse_move(NkWin *g, int x, int y)
{
    nk_input_motion(&g->ctx, x, y);
}

void nk_win_mouse_button(NkWin *g, enum nk_buttons btn, int x, int y, int down)
{
    nk_input_button(&g->ctx, btn, x, y, down);
}

void nk_win_mouse_wheel(NkWin *g, int delta)
{
    nk_input_scroll(&g->ctx, nk_vec2(0.f, (float)(delta / WHEEL_DELTA) * 3.f));
}

void nk_win_key(NkWin *g, int vk, int down)
{
    int ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
    switch (vk) {
    case VK_SHIFT:   nk_input_key(&g->ctx, NK_KEY_SHIFT,  down); break;
    case VK_CONTROL: nk_input_key(&g->ctx, NK_KEY_CTRL,   down); break;
    case VK_DELETE:  nk_input_key(&g->ctx, NK_KEY_DEL,    down); break;
    case VK_RETURN:  nk_input_key(&g->ctx, NK_KEY_ENTER,  down); break;
    case VK_TAB:     nk_input_key(&g->ctx, NK_KEY_TAB,    down); break;
    case VK_BACK:    nk_input_key(&g->ctx, NK_KEY_BACKSPACE, down); break;
    case VK_UP:      nk_input_key(&g->ctx, NK_KEY_UP,     down); break;
    case VK_DOWN:    nk_input_key(&g->ctx, NK_KEY_DOWN,   down); break;
    case VK_LEFT:    nk_input_key(&g->ctx, NK_KEY_LEFT,   down); break;
    case VK_RIGHT:   nk_input_key(&g->ctx, NK_KEY_RIGHT,  down); break;
    case VK_HOME:    nk_input_key(&g->ctx, NK_KEY_TEXT_LINE_START, down); break;
    case VK_END:     nk_input_key(&g->ctx, NK_KEY_TEXT_LINE_END,   down); break;
    case VK_PRIOR:   nk_input_key(&g->ctx, NK_KEY_SCROLL_UP,   down); break;
    case VK_NEXT:    nk_input_key(&g->ctx, NK_KEY_SCROLL_DOWN, down); break;
    case 'C': if (down&&ctrl) nk_input_key(&g->ctx, NK_KEY_COPY, 1); break;
    case 'V': if (down&&ctrl) nk_input_key(&g->ctx, NK_KEY_PASTE,1); break;
    case 'X': if (down&&ctrl) nk_input_key(&g->ctx, NK_KEY_CUT,  1); break;
    case 'A': if (down&&ctrl) nk_input_key(&g->ctx, NK_KEY_TEXT_SELECT_ALL,1); break;
    case 'Z': if (down&&ctrl) nk_input_key(&g->ctx, NK_KEY_TEXT_UNDO,1); break;
    case 'Y': if (down&&ctrl) nk_input_key(&g->ctx, NK_KEY_TEXT_REDO,1); break;
    default:  break;
    }
}

void nk_win_char(NkWin *g, unsigned int c)
{
    if (c >= 32)
        nk_input_unicode(&g->ctx, (nk_rune)c);
}

#endif /* NK_WIN_IMPLEMENTATION */
#endif /* NK_WIN_H */
