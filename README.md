# mini-pe

Minimal Windows console PE that manually resolves kernel32 exports at runtime so the binary ships without an import table. The custom entry point (`MyEntry`) walks the PEB to find `kernel32.dll`, resolves `LoadLibraryA`/`GetProcAddress` plus console I/O, prints a short message, and waits for ENTER.

## Build
- Open a Visual Studio Developer Command Prompt (x64 or x86 to match your target).
- Run the provided script:
  ```
  build.bat
  ```
- The script invokes `cl` with CRT removal (`/NODEFAULTLIB:libcmt`), merges sections to shrink size, and defines `ENABLE_DEBUG=1` to print resolved pointer addresses. Remove that define if you want a quieter build.

## Run
```
pe-mini.c.exe
```
You should see a greeting and a prompt to press ENTER before exit.
