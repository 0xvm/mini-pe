# mini-pe

Minimal Windows console PE that manually resolves kernel32 exports at runtime so the binary ships without an import table. The custom entry point (`MyEntry`) walks the PEB to find `kernel32.dll`, resolves `LoadLibraryA`/`GetProcAddress`, and exposes a tiny REPL where you can call exports directly using `module!function(arg0, arg1, ...)`. Arguments accept decimal, hex (`0x`), `NULL`, and a few named constants like `STD_OUTPUT_HANDLE`. With `ENABLE_DEBUG=1` you also get `[dbg] resolved ...` lines when modules/functions are loaded.

## Build
- Open a Visual Studio Developer Command Prompt (x64 or x86 to match your target).
- Run the provided script (source file is optional; defaults to `pe-mini.c`):
  ```
  build.bat pe-mini.c
  ```
- The script invokes `cl` with CRT removal (`/NODEFAULTLIB:libcmt`), merges sections to shrink size, and defines `ENABLE_DEBUG=1`. Drop that define if you want a quieter build.

## Run / example session
Launch the produced EXE and issue Win32 calls directly:
```
C:\Users\user\Source\pe-mini>pe-mini.c.exe
[*] Hello from MyEntry!
Enter calls like: kernel32!VirtualAlloc(NULL, 1000, 0x3000, 0x40)
Type help for usage or exit to quit.
cmd> kernel32!GetStdHandle(STD_OUTPUT_HANDLE)
[+] retval=0x0000000000000074 last_error=0x0000000000000000
cmd> kernel32!GetStdHandle(STD_INPUT_HANDLE)
[+] retval=0x0000000000000070 last_error=0x0000000000000000
cmd> kernel32!VirtualAlloc(NULL, 0x100, 0x3000, 0x40)
[+] retval=0x000002abe6280000 last_error=0x0000000000000000
cmd> kernel32!ReadConsoleA(0x70, 0x000002abe6280000, 0x100, 0x000002abe6280060, 0)
AAAAAAAAAAAAAAAAAAAAAAAA
[+] retval=0x0000000000000001 last_error=0x0000000000000000
cmd> kernel32!WriteConsoleA(0x74, 0x000002abe6280000, 0x100, 0x000002abe6280070, 0)
AAAAAAAAAAAAAAAAAAAAAAAA
␦[+] retval=0x0000000000000001 last_error=0x0000000000000000
cmd> exit
```

Note: the REPL does not marshal strings; you pass pointers/handles yourself. Be careful with calling conventions and buffer lengths to avoid crashes or stray characters (the `␦` above came from writing more bytes than were read).
