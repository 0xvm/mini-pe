@echo off
REM Single cl invocation: compile + link without the CRT, size-oriented.
setlocal

set SRC=%~1
if "%SRC%"=="" set SRC=pe-mini.c
set CFLAGS=/DNDEBUG /DENABLE_DEBUG=1

cl /nologo /Os /GS- /GR- /W3 /Zl /Gy /Fe:%SRC%.exe %SRC% %CFLAGS% ^
  /link /NODEFAULTLIB:libcmt /ENTRY:MyEntry /SUBSYSTEM:CONSOLE ^
  /OPT:REF /OPT:ICF /INCREMENTAL:NO /MERGE:.rdata=.text /MERGE:.pdata=.text /ALIGN:16 /IGNORE:4108 ^
  kernel32.lib

endlocal
exit /b %ERRORLEVEL%
