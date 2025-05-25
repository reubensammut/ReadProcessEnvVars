#include <stdio.h>

#include "internals.h"
#include "process_ctx.h"

_NtQueryInformationProcess pNtQueryInformationProcess = NULL;

BOOL Init()
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");

	if (hNtdll == NULL)
	{
		perror("[-] Failed to load ntdll.dll");
		return FALSE;
	}

	pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if (pNtQueryInformationProcess == NULL)
	{
		perror("[-] Failed to get address for NtQueryInformationProcess");
		return FALSE;
	}

	return TRUE;
}

BOOL Check32BitProcess(PROCESS_CTX *proc)
{
	const ULONG ProcessWow64Information = 26;

	ULONGLONG res = 0;
	ULONG resLen = 0;

	NTSTATUS s = pNtQueryInformationProcess(proc->handle, ProcessWow64Information, &res, sizeof(res), &resLen);

	if (s != 0)
	{
		perror("[-] Failed getting ProcessWow64Information");
		return FALSE;
	}

	if (res == 0)
	{
		proc->type = PROC_X64;
	}
	else
	{
		proc->type = PROC_X86;
		proc->peb_addr = res;
	}

	return TRUE;
}

BOOL GetPEBAddress(PROCESS_CTX *proc)
{
	const ULONG ProcessBasicInformation = 0;

	PROCESS_BASIC_INFORMATION info = { 0 };
	ULONG resLen = 0;

	NTSTATUS s = pNtQueryInformationProcess(proc->handle, ProcessBasicInformation, &info, sizeof(info), &resLen);

	if (s != 0)
	{
		perror("[-] Failed getting ProcessBasicInformation");
		return FALSE;
	}
	else {
		proc->peb_addr = (ULONGLONG)info.PebBaseAddress;
	}

	return TRUE;
}

BOOL ReadAddress(PROCESS_CTX* proc, ULONGLONG addr_read, ULONGLONG* addr_out)
{
	SIZE_T count = proc->type == PROC_X64 ? 8 : 4;
	SIZE_T res_size = 0;
	return ReadProcessMemory(proc->handle, (LPCVOID)addr_read, addr_out, count, &res_size);
}

PROCESS_CTX * InitProcess(DWORD pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (hProcess == NULL)
	{
		perror("[-] Failed to open process");
		return NULL;
	}

	PROCESS_CTX* proc = new PROCESS_CTX;
	memset(proc, 0, sizeof PROCESS_CTX);
	proc->pid = pid;
	proc->handle = hProcess;

	// PEB for 32 bit processes can be extracted from ProcessWow64Information according to the following
	// https://www.unknowncheats.me/forum/c-and-c-/188303-enumerate-x86-modules-process-x64-process.html 

	if (Check32BitProcess(proc))
	{
		if (proc->type == PROC_X64)
		{
			if (!GetPEBAddress(proc))
			{
				delete proc;
				return NULL;
			}
		}
	}
	else
	{
		delete proc;
		proc = NULL;
	}

	return proc;
}

BOOL GetProcessParameters(PROCESS_CTX* proc, ULONGLONG *proc_params)
{
	ULONGLONG addr_to_read = proc->peb_addr;
		
	addr_to_read += proc->type == PROC_X64 ? 0x20 : 0x10;

	return ReadAddress(proc, addr_to_read, proc_params);
}

BOOL ReadEnvVarsFromProc(PROCESS_CTX* proc)
{
	const ULONG env_offset = proc->type == PROC_X64 ? 0x80 : 0x48;
	const ULONG env_len_offset = proc->type == PROC_X64 ? 0x3f0 : 0x290;

	ULONGLONG proc_params = 0;
	
	if (!GetProcessParameters(proc, &proc_params))
	{
		return FALSE;
	}

	ULONGLONG envptr = 0;
	if (!ReadAddress(proc, proc_params + env_offset, &envptr))
	{
		return FALSE;
	}

	ULONGLONG envsize = 0;
	if (!ReadAddress(proc, proc_params + env_len_offset, &envsize))
	{
		return FALSE;
	}

	proc->envsize = envsize;
	proc->env = new unsigned char[envsize];

	SIZE_T ret_size = 0;

	if (!ReadProcessMemory(proc->handle, (LPCVOID)envptr, proc->env, envsize, &ret_size))
	{
		return FALSE;
	}

	return TRUE;
}

VOID DisplayEnvVarsForProc(PROCESS_CTX* proc)
{
	ULONGLONG remaining = proc->envsize;
	wchar_t* envptr = (wchar_t*)proc->env;

	while (remaining > 0)
	{
		int printed = wprintf(L"%s\n", envptr);
		remaining = remaining - (printed * 2);
		envptr += printed;
	}
}

VOID FreeProcCTX(PROCESS_CTX* proc)
{
	if (proc)
	{
		if (proc->env)
		{
			delete [] proc->env;
			proc->env = NULL;
			proc->envsize = 0;
		}
		delete proc;
	}
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		return 1;
	}

	int pid = atoi(argv[1]);

	if (!Init())
	{
		fprintf(stderr, "[-] Failed initialization\n");
		return 1;
	}

	PROCESS_CTX* proc = InitProcess(pid);

	if (proc)
	{
		ReadEnvVarsFromProc(proc);
		DisplayEnvVarsForProc(proc);
		FreeProcCTX(proc);
	}
	else 
	{
		fprintf(stderr, "[-] Failed to get process for pid: %d\n", pid);
	}

	return 0;
}