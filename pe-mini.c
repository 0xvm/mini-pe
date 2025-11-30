// Minimal console example that resolves kernel32 exports (including LoadLibraryA/GetProcAddress) at runtime.
#include <windows.h>
#include <intrin.h>

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef HMODULE(WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HANDLE(WINAPI *PFN_GetStdHandle)(DWORD);
typedef BOOL(WINAPI *PFN_ReadConsoleA)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
typedef BOOL(WINAPI *PFN_WriteConsoleA)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
typedef DWORD(WINAPI *PFN_GetLastError)(VOID);
typedef VOID(WINAPI *PFN_SetLastError)(DWORD);

#ifndef ENABLE_DEBUG
#define ENABLE_DEBUG 0
#endif

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	BYTE Reserved1[3];
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
} PEB, *PPEB;

static PFN_LoadLibraryA pLoadLibraryA = NULL;
static PFN_GetProcAddress pGetProcAddress = NULL;
static PFN_GetStdHandle pGetStdHandle = NULL;
static PFN_ReadConsoleA pReadConsoleA = NULL;
static PFN_WriteConsoleA pWriteConsoleA = NULL;
static PFN_GetLastError pGetLastError = NULL;
static PFN_SetLastError pSetLastError = NULL;
static HANDLE g_hConsole = INVALID_HANDLE_VALUE;

#if ENABLE_DEBUG
static PPEB g_debugPeb = NULL;
static HMODULE g_debugKernel32 = NULL;
#endif

#define INPUT_BUFFER_SIZE 256
#define MAX_ARGS 6

// Simple strlen replacement to avoid importing msvcrt.
// Returns the length of a null-terminated ASCII string.
static DWORD CStringLength(LPCSTR str) {
	if (str == NULL) {
		return 0;
	}

	DWORD len = 0;
	while (str[len] != '\0') {
		++len;
	}
	return len;
}

// Convert an uppercase ASCII letter to lowercase.
static CHAR ToLowerChar(CHAR c) {
	if (c >= 'A' && c <= 'Z') {
		return c + 32;
	}
	return c;
}

// Format a pointer-sized value as a hex string (e.g., 0x1234abcd).
static void FormatPointerHex(const void *ptr, CHAR *out, DWORD outSize) {
	if (out == NULL || outSize < 3) {
		return;
	}

	static const CHAR kHex[] = "0123456789abcdef";
	UINT_PTR value = (UINT_PTR)ptr;
	int digits = (int)(sizeof(UINT_PTR) * 2);

	if (outSize <= (DWORD)(digits + 2)) {
		out[0] = '\0';
		return;
	}

	out[0] = '0';
	out[1] = 'x';

	for (int i = 0; i < digits; ++i) {
		int shift = (digits - 1 - i) * 4;
		out[2 + i] = kHex[(value >> shift) & 0xF];
	}

	out[2 + digits] = '\0';
}

#if ENABLE_DEBUG
// Append a null-terminated string to a buffer with bounds checking.
static void AppendString(CHAR *dst, DWORD dstSize, DWORD *idx, const CHAR *src) {
	if (dst == NULL || idx == NULL || src == NULL) {
		return;
	}

	while (*src != '\0' && (*idx + 1) < dstSize) {
		dst[*idx] = *src;
		++(*idx);
		++src;
	}
}

// Emit a debug line with a label and pointer address.
static void DebugPrintPointer(const CHAR *label, const void *value) {
	if (label == NULL || g_hConsole == INVALID_HANDLE_VALUE || pWriteConsoleA == NULL) {
		return;
	}

	CHAR hexBuffer[32];
	CHAR message[128];
	DWORD idx = 0;

	FormatPointerHex(value, hexBuffer, sizeof(hexBuffer));
	AppendString(message, sizeof(message), &idx, "[dbg] ");
	AppendString(message, sizeof(message), &idx, label);
	AppendString(message, sizeof(message), &idx, ": ");
	AppendString(message, sizeof(message), &idx, hexBuffer);
	AppendString(message, sizeof(message), &idx, "\r\n");

	if (idx < sizeof(message)) {
		message[idx] = '\0';
	} else {
		message[sizeof(message) - 1] = '\0';
	}

	DWORD written = 0;
	pWriteConsoleA(g_hConsole, message, CStringLength(message), &written, NULL);
}

// Emit a debug line for resolution events.
static void DebugPrintResolved(const CHAR *kind, const CHAR *name, const void *addr, const CHAR *moduleName) {
	if (kind == NULL || name == NULL || g_hConsole == INVALID_HANDLE_VALUE || pWriteConsoleA == NULL) {
		return;
	}

	CHAR addrHex[32];
	CHAR message[192];
	DWORD idx = 0;

	FormatPointerHex(addr, addrHex, sizeof(addrHex));

	AppendString(message, sizeof(message), &idx, "[dbg] resolved ");
	AppendString(message, sizeof(message), &idx, name);
	AppendString(message, sizeof(message), &idx, " at ");
	AppendString(message, sizeof(message), &idx, addrHex);
	if (moduleName != NULL) {
		AppendString(message, sizeof(message), &idx, " in ");
		AppendString(message, sizeof(message), &idx, moduleName);
	}
	AppendString(message, sizeof(message), &idx, "\r\n");

	if (idx < sizeof(message)) {
		message[idx] = '\0';
	} else {
		message[sizeof(message) - 1] = '\0';
	}

	DWORD written = 0;
	pWriteConsoleA(g_hConsole, message, CStringLength(message), &written, NULL);
}
#else
#define DebugPrintPointer(label, value) ((void)0)
#define DebugPrintResolved(kind, name, addr, moduleName) ((void)0)
#endif

// Compare a UNICODE_STRING to an ASCII string without case sensitivity.
static BOOL UnicodeEqualsAsciiInsensitive(const UNICODE_STRING *uni, LPCSTR ascii) {
	if (uni == NULL || uni->Buffer == NULL || ascii == NULL) {
		return FALSE;
	}

	DWORD asciiLen = CStringLength(ascii);
	if (uni->Length / sizeof(WCHAR) != asciiLen) {
		return FALSE;
	}

	for (DWORD i = 0; i < asciiLen; ++i) {
		CHAR uniChar = (CHAR)uni->Buffer[i];
		if (ToLowerChar(uniChar) != ToLowerChar(ascii[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

// Case-insensitive ASCII comparison for narrow strings.
static BOOL AsciiEqualsInsensitive(LPCSTR a, LPCSTR b) {
	if (a == NULL || b == NULL) {
		return FALSE;
	}

	while (*a != '\0' && *b != '\0') {
		if (ToLowerChar(*a) != ToLowerChar(*b)) {
			return FALSE;
		}
		++a;
		++b;
	}

	return *a == '\0' && *b == '\0';
}

// Trim trailing CR/LF characters in-place.
static void TrimTrailingNewlines(CHAR *buf) {
	if (buf == NULL) {
		return;
	}

	DWORD len = CStringLength(buf);
	while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) {
		buf[len - 1] = '\0';
		--len;
	}
}

// Map common named constants to their values.
static BOOL ParseNamedConstant(const CHAR *str, UINT_PTR *outValue) {
	if (str == NULL || outValue == NULL) {
		return FALSE;
	}

	if (AsciiEqualsInsensitive(str, "STD_INPUT_HANDLE")) {
		*outValue = (UINT_PTR)(INT_PTR)-10;
		return TRUE;
	}
	if (AsciiEqualsInsensitive(str, "STD_OUTPUT_HANDLE")) {
		*outValue = (UINT_PTR)(INT_PTR)-11;
		return TRUE;
	}
	if (AsciiEqualsInsensitive(str, "STD_ERROR_HANDLE")) {
		*outValue = (UINT_PTR)(INT_PTR)-12;
		return TRUE;
	}

	return FALSE;
}

// Parse a signed or unsigned number (decimal or 0x-prefixed hex) into a UINT_PTR.
static BOOL ParseNumber(const CHAR *str, UINT_PTR *outValue) {
	if (str == NULL || outValue == NULL || *str == '\0') {
		return FALSE;
	}

	if (ParseNamedConstant(str, outValue)) {
		return TRUE;
	}

	BOOL negative = FALSE;
	const CHAR *p = str;
	if (*p == '+' || *p == '-') {
		negative = (*p == '-');
		++p;
		if (*p == '\0') {
			return FALSE;
		}
	}

	UINT_PTR value = 0;
	BOOL hex = FALSE;

	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		hex = TRUE;
		p += 2;
		if (*p == '\0') {
			return FALSE;
		}
	}

	if (hex) {
		while (*p != '\0') {
			CHAR c = *p;
			UINT_PTR digit = 0;
			if (c >= '0' && c <= '9') {
				digit = (UINT_PTR)(c - '0');
			} else if (c >= 'a' && c <= 'f') {
				digit = (UINT_PTR)(c - 'a' + 10);
			} else if (c >= 'A' && c <= 'F') {
				digit = (UINT_PTR)(c - 'A' + 10);
			} else {
				return FALSE;
			}
			value = (value << 4) | digit;
			++p;
		}
	} else {
		while (*p != '\0') {
			if (*p < '0' || *p > '9') {
				return FALSE;
			}
			value = (value * 10u) + (UINT_PTR)(*p - '0');
			++p;
		}
	}

	if (negative) {
		value = (UINT_PTR)(-(INT_PTR)value);
	}

	*outValue = value;
	return TRUE;
}

// Parse "module!function(arg0, arg1, ...)" into components in-place.
static BOOL ParseInvocation(CHAR *line, CHAR **outModule, CHAR **outFunction, UINT_PTR *args, DWORD *outArgCount) {
	if (line == NULL || outModule == NULL || outFunction == NULL || args == NULL || outArgCount == NULL) {
		return FALSE;
	}

	*outArgCount = 0;

	// Skip leading spaces.
	while (*line == ' ') {
		++line;
	}
	if (*line == '\0') {
		return FALSE;
	}

	// Locate '!'.
	CHAR *bang = line;
	while (*bang != '\0' && *bang != '!') {
		++bang;
	}
	if (*bang != '!') {
		return FALSE;
	}

	// Trim module name and null-terminate.
	CHAR *moduleStart = line;
	CHAR *moduleEnd = bang - 1;
	while (moduleEnd >= moduleStart && *moduleEnd == ' ') {
		--moduleEnd;
	}
	if (moduleEnd < moduleStart) {
		return FALSE;
	}
	moduleEnd[1] = '\0';
	*outModule = moduleStart;

	// Function start after '!'.
	CHAR *funcStart = bang + 1;
	while (*funcStart == ' ') {
		++funcStart;
	}
	if (*funcStart == '\0') {
		return FALSE;
	}

	// Find '(' to end function token.
	CHAR *paren = funcStart;
	while (*paren != '\0' && *paren != '(') {
		++paren;
	}
	if (*paren != '(') {
		return FALSE;
	}

	CHAR *funcEnd = paren - 1;
	while (funcEnd >= funcStart && *funcEnd == ' ') {
		--funcEnd;
	}
	if (funcEnd < funcStart) {
		return FALSE;
	}
	funcEnd[1] = '\0';
	*outFunction = funcStart;

	// Parse arguments.
	CHAR *cursor = paren + 1;
	for (;;) {
		while (*cursor == ' ') {
			++cursor;
		}
		if (*cursor == ')') {
			++cursor;
			break;
		}
		if (*cursor == '\0') {
			return FALSE;
		}

		if (*outArgCount >= MAX_ARGS) {
			return FALSE;
		}

		CHAR *argStart = cursor;
		while (*cursor != '\0' && *cursor != ',' && *cursor != ')') {
			++cursor;
		}
		if (*cursor == '\0') {
			return FALSE;
		}

		CHAR delimiter = *cursor;
		CHAR *argEnd = cursor - 1;
		while (argEnd >= argStart && *argEnd == ' ') {
			--argEnd;
		}
		argEnd[1] = '\0';

		UINT_PTR value = 0;
		if (AsciiEqualsInsensitive(argStart, "null")) {
			value = 0;
		} else if (!ParseNumber(argStart, &value)) {
			return FALSE;
		}

		args[*outArgCount] = value;
		++(*outArgCount);

		if (delimiter == ')') {
			++cursor;
			break;
		} else if (delimiter == ',') {
			++cursor;
		} else {
			return FALSE;
		}
	}

	return TRUE;
}

// Obtain the current process PEB via the TEB segment register.
static PPEB GetCurrentPeb(void) {
#if defined(_M_X64) || defined(_M_AMD64) || defined(_WIN64)
	return (PPEB)__readgsqword(0x60);
#else
	return (PPEB)__readfsdword(0x30);
#endif
}

// Walk the PEB loader list to find kernel32.dll base address.
static HMODULE FindKernel32Base(void) {
	PPEB peb = GetCurrentPeb();
#if ENABLE_DEBUG
	g_debugPeb = peb;
#endif
	if (peb == NULL || peb->Ldr == NULL) {
		return NULL;
	}

	LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
	for (LIST_ENTRY *entry = head->Flink; entry != head; entry = entry->Flink) {
		PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (module != NULL && UnicodeEqualsAsciiInsensitive(&module->BaseDllName, "kernel32.dll")) {
#if ENABLE_DEBUG
			g_debugKernel32 = (HMODULE)module->DllBase;
#endif
			return (HMODULE)module->DllBase;
		}
	}

	return NULL;
}

// Resolve an export by name directly from a module's PE headers.
static FARPROC ResolveExportByName(HMODULE module, LPCSTR exportName) {
	if (module == NULL || exportName == NULL) {
		return NULL;
	}

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)module + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportRva == 0) {
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)module + exportRva);
	DWORD *nameRVAs = (DWORD *)((BYTE *)module + exports->AddressOfNames);
	WORD *ordinals = (WORD *)((BYTE *)module + exports->AddressOfNameOrdinals);
	DWORD *funcRVAs = (DWORD *)((BYTE *)module + exports->AddressOfFunctions);

	for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
		LPCSTR currentName = (LPCSTR)((BYTE *)module + nameRVAs[i]);
		if (currentName != NULL) {
			const CHAR *namePtr = currentName;
			const CHAR *wantPtr = exportName;
			while (ToLowerChar(*namePtr) == ToLowerChar(*wantPtr)) {
				if (*namePtr == '\0') {
					WORD ordinal = ordinals[i];
					DWORD funcRva = funcRVAs[ordinal];
					return (FARPROC)((BYTE *)module + funcRva);
				}
				++namePtr;
				++wantPtr;
			}
			if (*namePtr == '\0' && *wantPtr == '\0') {
				WORD ordinal = ordinals[i];
				DWORD funcRva = funcRVAs[ordinal];
				return (FARPROC)((BYTE *)module + funcRva);
			}
		}
	}

	return NULL;
}

// Load kernel32 exports manually so the binary has no import table.
static BOOL ResolveKernel32Imports(void) {
	// Manually locate kernel32 via the PEB and pull exports without an import table.
	HMODULE hKernel32 = FindKernel32Base();
	if (hKernel32 == NULL) {
		return FALSE;
	}

	pLoadLibraryA = (PFN_LoadLibraryA)ResolveExportByName(hKernel32, "LoadLibraryA");
	pGetProcAddress = (PFN_GetProcAddress)ResolveExportByName(hKernel32, "GetProcAddress");
	pGetStdHandle = (PFN_GetStdHandle)ResolveExportByName(hKernel32, "GetStdHandle");
	pReadConsoleA = (PFN_ReadConsoleA)ResolveExportByName(hKernel32, "ReadConsoleA");
	pWriteConsoleA = (PFN_WriteConsoleA)ResolveExportByName(hKernel32, "WriteConsoleA");
	pGetLastError = (PFN_GetLastError)ResolveExportByName(hKernel32, "GetLastError");
	pSetLastError = (PFN_SetLastError)ResolveExportByName(hKernel32, "SetLastError");

	if (pLoadLibraryA == NULL || pGetProcAddress == NULL || pGetStdHandle == NULL || pReadConsoleA == NULL || pWriteConsoleA == NULL ||
	    pGetLastError == NULL || pSetLastError == NULL) {
		return FALSE;
	}

	// Initialize console handle early for debug printing.
	g_hConsole = pGetStdHandle(STD_OUTPUT_HANDLE);

#if ENABLE_DEBUG
	DebugPrintPointer("peb", g_debugPeb);
	DebugPrintPointer("kernel32", g_debugKernel32);
	DebugPrintPointer("LoadLibraryA", pLoadLibraryA);
	DebugPrintPointer("GetProcAddress", pGetProcAddress);
	DebugPrintPointer("GetStdHandle", pGetStdHandle);
	DebugPrintPointer("ReadConsoleA", pReadConsoleA);
	DebugPrintPointer("WriteConsoleA", pWriteConsoleA);
	DebugPrintPointer("GetLastError", pGetLastError);
	DebugPrintPointer("SetLastError", pSetLastError);
#endif

	return TRUE;

}

// Write a message to the console using the dynamically resolved API.
static void WriteConsoleMessage(LPCSTR message) {
	// Skip writes if console isn't ready or the import failed.
	if (g_hConsole == INVALID_HANDLE_VALUE || pWriteConsoleA == NULL) {
		return;
	}

	DWORD written = 0;
	pWriteConsoleA(g_hConsole, message, CStringLength(message), &written, NULL);
}

typedef UINT_PTR(WINAPI *PFN_GENERIC0)(void);
typedef UINT_PTR(WINAPI *PFN_GENERIC1)(UINT_PTR);
typedef UINT_PTR(WINAPI *PFN_GENERIC2)(UINT_PTR, UINT_PTR);
typedef UINT_PTR(WINAPI *PFN_GENERIC3)(UINT_PTR, UINT_PTR, UINT_PTR);
typedef UINT_PTR(WINAPI *PFN_GENERIC4)(UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR);
typedef UINT_PTR(WINAPI *PFN_GENERIC5)(UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR);
typedef UINT_PTR(WINAPI *PFN_GENERIC6)(UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR);

// Try to load a module by name, optionally appending ".dll" if absent.
static HMODULE LoadModuleByName(const CHAR *moduleName) {
	if (moduleName == NULL || pLoadLibraryA == NULL) {
		return NULL;
	}

	CHAR buffer[64];
	DWORD len = CStringLength(moduleName);
	if (len >= sizeof(buffer)) {
		return NULL;
	}

	for (DWORD i = 0; i <= len; ++i) {
		buffer[i] = moduleName[i];
	}

	HMODULE mod = pLoadLibraryA(buffer);
	if (mod != NULL) {
		DebugPrintResolved("module", buffer, mod, buffer);
		return mod;
	}

	BOOL hasDot = FALSE;
	for (DWORD i = 0; i < len; ++i) {
		if (buffer[i] == '.') {
			hasDot = TRUE;
			break;
		}
	}

	if (!hasDot && (len + 4) < sizeof(buffer)) {
		buffer[len + 0] = '.';
		buffer[len + 1] = 'd';
		buffer[len + 2] = 'l';
		buffer[len + 3] = 'l';
		buffer[len + 4] = '\0';
		mod = pLoadLibraryA(buffer);
	}

	if (mod != NULL) {
		DebugPrintResolved("module", buffer, mod, buffer);
	}

	return mod;
}

// Invoke the target function with up to MAX_ARGS positional UINT_PTR arguments.
static UINT_PTR InvokeFunction(FARPROC fn, UINT_PTR *args, DWORD argCount) {
	if (fn == NULL) {
		return 0;
	}

	switch (argCount) {
	case 0: return ((PFN_GENERIC0)fn)();
	case 1: return ((PFN_GENERIC1)fn)(args[0]);
	case 2: return ((PFN_GENERIC2)fn)(args[0], args[1]);
	case 3: return ((PFN_GENERIC3)fn)(args[0], args[1], args[2]);
	case 4: return ((PFN_GENERIC4)fn)(args[0], args[1], args[2], args[3]);
	case 5: return ((PFN_GENERIC5)fn)(args[0], args[1], args[2], args[3], args[4]);
	default: return ((PFN_GENERIC6)fn)(args[0], args[1], args[2], args[3], args[4], args[5]);
	}
}

// Parse and execute a single "module!function(args...)" invocation.
static void HandleInvocation(CHAR *line) {
	CHAR *module = NULL;
	CHAR *function = NULL;
	UINT_PTR args[MAX_ARGS];
	DWORD argCount = 0;

	if (!ParseInvocation(line, &module, &function, args, &argCount)) {
		WriteConsoleMessage("[!] parse failed\r\n");
		return;
	}

	HMODULE hModule = LoadModuleByName(module);
	if (hModule == NULL) {
		WriteConsoleMessage("[!] failed to load module\r\n");
		return;
	}

	FARPROC fn = pGetProcAddress != NULL ? pGetProcAddress(hModule, function) : NULL;
	if (fn == NULL) {
		WriteConsoleMessage("[!] function not found\r\n");
		return;
	}
	DebugPrintResolved("function", function, fn, module);

	if (pSetLastError != NULL) {
		pSetLastError(0);
	}

	UINT_PTR result = InvokeFunction(fn, args, argCount);
	DWORD lastErr = pGetLastError != NULL ? pGetLastError() : 0;

	CHAR resHex[32];
	CHAR errHex[32];
	CHAR msg[128];
	FormatPointerHex((const void *)result, resHex, sizeof(resHex));
	FormatPointerHex((const void *)(UINT_PTR)lastErr, errHex, sizeof(errHex));

	DWORD idx = 0;
	const CHAR prefix[] = "[+] retval=";
	for (DWORD i = 0; prefix[i] != '\0' && idx < sizeof(msg) - 1; ++i) {
		msg[idx++] = prefix[i];
	}
	for (DWORD i = 0; resHex[i] != '\0' && idx < sizeof(msg) - 1; ++i) {
		msg[idx++] = resHex[i];
	}
	const CHAR mid[] = " last_error=";
	for (DWORD i = 0; mid[i] != '\0' && idx < sizeof(msg) - 1; ++i) {
		msg[idx++] = mid[i];
	}
	for (DWORD i = 0; errHex[i] != '\0' && idx < sizeof(msg) - 1; ++i) {
		msg[idx++] = errHex[i];
	}
	if (idx < sizeof(msg)) {
		msg[idx++] = '\0';
	}

	WriteConsoleMessage(msg);
	WriteConsoleMessage("\r\n");
}

// Handle a single input line. Returns FALSE to exit.
static BOOL HandleCommand(CHAR *line) {
	if (line == NULL) {
		return TRUE;
	}

	while (*line == ' ') {
		++line;
	}
	if (*line == '\0') {
		return TRUE;
	}

	if (AsciiEqualsInsensitive(line, "exit") || AsciiEqualsInsensitive(line, "quit")) {
		return FALSE;
	}
	if (AsciiEqualsInsensitive(line, "help")) {
		WriteConsoleMessage("Usage: module!function(arg0, arg1, ...)\r\nExample: kernel32!VirtualAlloc(NULL, 1000, 0x3000, 0x40)\r\n");
		return TRUE;
	}

	HandleInvocation(line);
	return TRUE;
}

// Minimal entry point that resolves imports, greets, and waits for input.
int WINAPI MyEntry(void) {
	// Resolve imports before making any WinAPI calls.
	if (!ResolveKernel32Imports()) {
		return 1;
	}

	g_hConsole = pGetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE hInput = pGetStdHandle(STD_INPUT_HANDLE);

	WriteConsoleMessage("[*] Hello from MyEntry!\r\n");
	WriteConsoleMessage("Enter calls like: kernel32!VirtualAlloc(NULL, 1000, 0x3000, 0x40)\r\n");
	WriteConsoleMessage("Type help for usage or exit to quit.\r\n");

	CHAR input[INPUT_BUFFER_SIZE];
	DWORD read = 0;

	for (;;) {
		WriteConsoleMessage("cmd> ");
		if (!pReadConsoleA(hInput, input, INPUT_BUFFER_SIZE - 1, &read, NULL)) {
			break;
		}
		if (read == 0) {
			continue;
		}
		if (read >= INPUT_BUFFER_SIZE) {
			read = INPUT_BUFFER_SIZE - 1;
		}
		input[read] = '\0';
		TrimTrailingNewlines(input);
		if (!HandleCommand(input)) {
			break;
		}
	}

	return 0;
}
