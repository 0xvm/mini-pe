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
static HANDLE g_hConsole = INVALID_HANDLE_VALUE;

#if ENABLE_DEBUG
static PPEB g_debugPeb = NULL;
static HMODULE g_debugKernel32 = NULL;
#endif

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
#else
#define DebugPrintPointer(label, value) ((void)0)
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

	if (pLoadLibraryA == NULL || pGetProcAddress == NULL || pGetStdHandle == NULL || pReadConsoleA == NULL || pWriteConsoleA == NULL) {
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

// Minimal entry point that resolves imports, greets, and waits for input.
int WINAPI MyEntry(void) {
	// Resolve imports before making any WinAPI calls.
	if (!ResolveKernel32Imports()) {
		return 1;
	}

	g_hConsole = pGetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE hInput = pGetStdHandle(STD_INPUT_HANDLE);

	WriteConsoleMessage("[*] Hello from MyEntry!\r\n");
	WriteConsoleMessage("Press ENTER to exit.\r\n");

	CHAR buffer = 0;
	DWORD read = 0;
	pReadConsoleA(hInput, &buffer, 1, &read, NULL);

	return 0;
}
