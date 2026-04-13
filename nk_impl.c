/*
 * nk_impl.c - single translation unit that bakes Nuklear + GDI backend.
 *
 * nuklear.h's implementation block lives OUTSIDE its include guard, so it
 * would be compiled a second time if any later header re-includes nuklear.h
 * with NK_IMPLEMENTATION still defined.  We therefore:
 *   1. Define all NK_INCLUDE_* flags manually here (not via dkid.h)
 *   2. Define NK_IMPLEMENTATION and include nuklear.h exactly once
 *   3. #undef NK_IMPLEMENTATION immediately after so no subsequent
 *      re-include of nuklear.h triggers the impl block again
 *   4. Define NK_WIN_IMPLEMENTATION and include nk_win.h
 */

/* -- Nuklear feature flags (mirror dkid.h) -- */
#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT

/* -- Bake Nuklear implementation (one TU only) -- */
#define NK_IMPLEMENTATION
#include "nuklear.h"
#undef NK_IMPLEMENTATION   /* prevent re-trigger if nuklear.h is re-included */

/* -- Bake the Win32 GDI backend (one TU only) -- */
#define NK_WIN_IMPLEMENTATION
#include "nk_win.h"
