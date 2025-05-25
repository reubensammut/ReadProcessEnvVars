#pragma once

#include <windows.h>

typedef enum {
	PROC_NONE,
	PROC_X86,
	PROC_X64
} PROC_TYPE;

typedef struct {
	DWORD pid;
	PROC_TYPE type;
	HANDLE handle;
	ULONGLONG peb_addr;
	PVOID env;
	ULONGLONG envsize;
} PROCESS_CTX;