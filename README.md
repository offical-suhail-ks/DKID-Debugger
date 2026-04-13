# DKID -- Advanced Windows Memory Analysis Tool

> Native Win32 memory debugger with an IDA Pro-style UI. Attach to any process, inspect PE structures, scan for cryptographic material, disassemble live code, and watch memory change in real time -- with an optional ring-0 kernel driver for unrestricted access.

---

## Features

### Core Analysis
- **PE Inspector** -- full DOS/NT headers, section table, import/export tables, data directories with resolved virtual addresses
- **x86-64 Disassembler** -- live disassembly with address / raw bytes / mnemonic / operand columns; click any address to jump to hex view
- **Hex View** -- 16-byte-per-row hex dump with ASCII panel; navigable via Goto bar or disassembly click
- **String Scanner** -- background scan for ASCII and wide strings across all readable regions; filterable by keyword
- **IAT Hook Detection** -- baselines all import address table entries on attach, alerts immediately when any entry is modified

### Cryptographic Scanning
- **AES-256 Key Finder** -- entropy-based scanner that sweeps all committed memory regions and flags 32-byte blocks with high Shannon entropy and sufficient byte diversity; runs as a background thread automatically on attach
- Results shown with address, entropy score, hex preview, and source note

### Live Memory Debug
- **Real-time hex grid** -- per-row change highlighting: red on change, fades to yellow over subsequent frames
- **In-process inject agent** (`probe_dll.dll`) -- injected via `CreateRemoteThread` + `LoadLibraryA`; reads memory via direct `memcpy()` inside the target -- no `ReadProcessMemory` limitations, no page protection bypass required
- **Watchpoints** -- up to 8 user-defined addresses; any byte change triggers a timestamped event in the event log
- **Byte search** -- hex pattern search across the live buffer
- **Export** -- save any frame to a `.hex` file
- Status shows `[INJ]` (in-process agent active) or `[RPM]` (ReadProcessMemory fallback)

### AI Disassembly Cleanup
- Sends raw disassembly to the **NVIDIA NIM API** (llama-3.1-70b) and returns a human-readable analysis
- Configure your API key in the Settings tab or via `NVIDIA_API_KEY` / `NVAPI_KEY` environment variables

### Kernel Driver (optional)
- **K0Probe** -- a ring-0 `.sys` driver that exposes `MmCopyVirtualMemory`, hardware debug register watchpoints (DR0-DR3), VA to PA translation, and a kernel-polled event ring
- Falls back gracefully to user-mode RPM if the driver is not loaded
- Build requires WDK 10; load requires test-signing or DSE bypass

### Plugin System
- Load `.dll` plugins at runtime from the `plugins/` directory
- Plugins implement `plugin_init(PluginAPI*)`, `plugin_exit()`, and optionally `plugin_draw(nk_context*)` to add a new bottom tab
- Plugin API exposes: log, get target handle/PID, read memory, get AES key results, get string results

---

## UI Layout

```
+-- [Menu: File | View | Analyze | Plugin | Help] -------------------------+
+-- [Toolbar: Refresh | Attach | Detach | Inject | AES Scan | Strings ...] +
|                      |                                  |                |
|  SIDEBAR             |  MAIN PANEL                      |  LIVE MODULES  |
|  [Procs][Mods]       |  [Disassembly][Hex][Settings]    |  (attached)    |
|  [Sects][Imps][Exps] |                                  |                |
|                      |                                                    |
+-- [BOTTOM: Output | AES Keys | Strings | Cleaned Disasm | Live Memory] --+
+-- [Status: module | base addr | ATTACHED | SCANNING | KEYS: N ] ---------+
```

Built with [Nuklear](https://github.com/Immediate-Mode-UI/Nuklear) -- immediate-mode C UI, GDI backend, no external dependencies beyond the Windows SDK.

---

## Building

### Requirements

| Tool | Download |
|---|---|
| MinGW-w64 GCC 64-bit | https://winlibs.com -- GCC 14.x or later, UCRT, x86_64 |
| nuklear.h | https://github.com/Immediate-Mode-UI/Nuklear/raw/master/nuklear.h |

Place `nuklear.h` in the source folder, then:

```bat
build.bat
```

Produces `dkid.exe`. Run as **Administrator** for full process memory access.

### Optional: inject agent

`probe_dll.dll` is built automatically by `build.bat` if `probe_dll.c` is present in the folder. Keep it in the same directory as `dkid.exe`.

### Optional: kernel driver (K0Probe)

Requires **Windows Driver Kit (WDK 10)** and Visual Studio 2022:

```bat
msbuild k0probe.vcxproj /p:Configuration=Release /p:Platform=x64
```

Enable test signing (`bcdedit /set testsigning on`), self-sign the `.sys`, then:

```bat
sc create K0Probe type= kernel binPath= <path>\k0probe.sys
sc start K0Probe
```

---

## File Structure

```
dkid.h                   shared header -- types, globals, prototypes
dkid_main.c              WinMain, message loop, frame timer
dkid_globals.c           global variable definitions
dkid_ui.c                full Nuklear UI (menu, toolbar, sidebar, panels)
dkid_disasm.c            x86-64 disassembler
dkid_pe.c                PE header / import / export parser
dkid_process.c           process listing, attach, module enumeration
dkid_scan.c              AES-256 entropy scanner (background thread)
dkid_strings.c           string scanner (background thread)
dkid_hexview.c           hex view data management
dkid_log.c               output log
dkid_ai.c                NVIDIA NIM API integration
dkid_memlive.c           live memory debug panel + inject agent bridge
dkid_k0.c                user-mode bridge to K0Probe kernel driver
dkid_plugin.c            plugin loader and API
nk_impl.c                Nuklear implementation unit
nk_win.h                 Win32/GDI Nuklear backend
k0probe.c                ring-0 kernel driver source
k0probe_iface.h          shared kernel/user IOCTL interface
plugin_example/          minimal plugin template
build.bat                build script (MinGW)
```

---

## Usage

1. Run `dkid.exe` as Administrator
2. Click **Refresh** to list running processes
3. Select a process and click **Attach**
4. Click a module in the **Modules** sidebar -- PE analysis, string scan, and AES scan start automatically
5. Press **Disasm** to disassemble the module's `.text` section live
6. Switch to the **Live Memory** tab -- press **Follow Module** then **Inject Agent** to start real-time hex monitoring

---

## Stack

| | |
|---|---|
| Language | C11 (no C++) |
| UI | Nuklear (immediate-mode, GDI backend) |
| Win32 | psapi, dbghelp, comctl32, comdlg32, winhttp |
| Compiler | MinGW-w64 GCC |
| Kernel | WDK 10 (K0Probe driver, optional) |

---

## License

MIT
