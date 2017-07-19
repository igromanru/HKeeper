#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

#include "detours.h"

using namespace std;

HANDLE pubgHandle = NULL;

static HANDLE(WINAPI* pOpenProcess)
(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) = OpenProcess;

DWORD GetProcID(char* procName);

char* processName = "TslGame.exe";

HANDLE WINAPI hOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	if (GetProcID(processName) == dwProcessId) {
		dwDesiredAccess = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
		pubgHandle = pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

		return false;
	}

	return pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

DWORD GetProcID(char* procName)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32))
	{
		do {
			if (strcmp(pe32.szExeFile, procName) == 0)
				break;
		} while (Process32Next(hSnapshot, &pe32));
	}

	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);

	return pe32.th32ProcessID;
}

DWORD_PTR GetModuleBaseAddress(DWORD pid, TCHAR *name)
{
	DWORD_PTR baseAddress = NULL;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	MODULEENTRY32 entry = { NULL };

	entry.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapshot, &entry)) {
		CloseHandle(hSnapshot);
		return NULL;
	}

	do {
		if (!strcmp(entry.szModule, name))
		{
			baseAddress = (DWORD_PTR)entry.modBaseAddr;
			break;
		}

	} while (Module32Next(hSnapshot, &entry));

	CloseHandle(hSnapshot);

	return baseAddress;
}

void hookOpenProcess()
{
	AllocConsole();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&pOpenProcess, hOpenProcess);
	DetourTransactionCommit();

	while (pubgHandle != NULL) {
		char buffer[3];

		ReadProcessMemory(pubgHandle, (LPVOID)GetModuleBaseAddress(GetProcID(processName), processName), buffer, 2, NULL);
		buffer[3] = '\0';

		cout << buffer << endl;
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(hookOpenProcess), NULL, NULL, NULL);
		break;

	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}