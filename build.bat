@echo off
REM =======================================================================
REM  DKID v3.0 Build Script
REM  Advanced Memory Analysis Tool
REM
REM  REQUIREMENTS:
REM    1. nuklear.h in this directory
REM       https://github.com/Immediate-Mode-UI/Nuklear/raw/master/nuklear.h
REM    2. MinGW-w64 GCC 64-bit in PATH
REM       https://winlibs.com
REM =======================================================================

if not exist nuklear.h (
    echo [!] nuklear.h not found.
    echo     Download: https://github.com/Immediate-Mode-UI/Nuklear/raw/master/nuklear.h
    pause & exit /b 1
)

where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] gcc not found in PATH. Install MinGW-w64: https://winlibs.com
    pause & exit /b 1
)

echo.
echo  DKID v3.0 Build
echo  ===============
for /f "tokens=*" %%v in ('gcc --version 2^>^&1 ^| findstr /i "gcc"') do echo  Compiler: %%v
echo.

REM -----------------------------------------------------------------------
REM  Build dkid.exe  (main application)
REM -----------------------------------------------------------------------
echo [*] Building dkid.exe ...

gcc ^
    nk_impl.c ^
    dkid_main.c ^
    dkid_globals.c ^
    dkid_ui.c ^
    dkid_disasm.c ^
    dkid_pe.c ^
    dkid_process.c ^
    dkid_scan.c ^
    dkid_strings.c ^
    dkid_plugin.c ^
    dkid_hexview.c ^
    dkid_log.c ^
    dkid_ai.c ^
    dkid_memlive.c ^
    dkid_k0.c ^
    -o dkid.exe ^
    -lpsapi -ldbghelp -lgdi32 -luser32 -lkernel32 ^
    -lwinhttp -lcomctl32 -lcomdlg32 -lole32 ^
    -mwindows -O2 -m64 -std=c11 -lm ^
    -Wno-unknown-pragmas ^
    -Wno-stringop-truncation ^
    -Wno-format-truncation

if %errorlevel% neq 0 (
    echo [!] dkid.exe build FAILED
    pause & exit /b 1
)
echo [+] dkid.exe built OK

REM -----------------------------------------------------------------------
REM  Build probe_dll.dll  (inject agent for Live Memory tab)
REM  Requires probe_dll.c and probe_iface.h in this directory
REM -----------------------------------------------------------------------
if exist probe_dll.c (
    echo.
    echo [*] Building probe_dll.dll ...
    gcc probe_dll.c -shared -o probe_dll.dll ^
        -lpsapi -lgdi32 -luser32 -lkernel32 ^
        -O2 -m64 -std=c11 ^
        -Wno-unknown-pragmas ^
        -Wno-stringop-truncation ^
        -Wl,--enable-stdcall-fixup
    if %errorlevel% equ 0 (
        echo [+] probe_dll.dll built OK  -- keep next to dkid.exe
    ) else (
        echo [!] probe_dll.dll FAILED  (Live Memory inject disabled^)
    )
) else (
    echo [i] probe_dll.c not found -- skipping inject agent
)

REM -----------------------------------------------------------------------
REM  Build example plugin  (optional)
REM -----------------------------------------------------------------------
if exist plugin_example\plugin_example.c (
    if not exist plugins mkdir plugins
    echo.
    echo [*] Building example plugin ...
    gcc plugin_example\plugin_example.c ^
        -shared -o plugins\example.dll ^
        -I. -lgdi32 -luser32 ^
        -O2 -m64 ^
        -Wl,--allow-shlib-undefined ^
        -Wno-unknown-pragmas
    if %errorlevel% equ 0 (
        echo [+] plugins\example.dll built OK
    ) else (
        echo [!] Example plugin FAILED (optional^)
    )
)

echo.
echo =====================================================================
echo  Output:   dkid.exe
echo  Plugins:  plugins\*.dll  (drop .dll files here^)
echo  Agent:    probe_dll.dll  (keep next to dkid.exe^)
echo.
echo  Run:      Right-click dkid.exe - Run as Administrator
echo            Attach - select process - select module
echo            Live Memory tab - Follow Module - Inject Agent
echo =====================================================================
pause
