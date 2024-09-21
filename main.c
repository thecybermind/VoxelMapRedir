#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

void ErrorMsg(DWORD dw)
{
	// Retrieve the system error message for the last-error code

	LPWSTR lpMsgBuf;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	wprintf(L"%s\n", lpMsgBuf);

	LocalFree(lpMsgBuf);
}

DWORD FindProcess(LPWSTR exeName) {
	DWORD pid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 pe = { sizeof(pe) };
	if (Process32First(hSnapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, exeName) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return pid;
}

int DoInject(LPWSTR process, char* inject) {
	DWORD pid;

	if (pid = FindProcess(process)) {
		printf("Pid found: %d\n", pid);

		HANDLE process = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
		if (process == NULL) {
			printf("Error: the specified pid couldn't be opened.\n");
			ErrorMsg(GetLastError());
			return 0;
		}

		LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
		if (addr == NULL) {
			printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
			ErrorMsg(GetLastError());
			return 0;
		}

		LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(inject) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (arg == NULL) {
			printf("Error: the memory could not be allocated inside the chosen process.\n");
			ErrorMsg(GetLastError());
			return 0;
		}

		int n = WriteProcessMemory(process, arg, inject, strlen(inject) + 1, NULL);
		if (n == 0) {
			printf("Error: there was no bytes written to the process's address space.\n");
			ErrorMsg(GetLastError());
			return 0;
		}

		HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
		if (threadID == NULL) {
			printf("Error: the remote thread could not be created.\n");
			ErrorMsg(GetLastError());
			return 0;
		}
		else {
			printf("Success: the remote thread was successfully created.\n");
			return 1;
		}

		CloseHandle(process);
	}

	return 0;
}

int main() {
	while (1) {
		printf("Scanning...\n");
		while (!DoInject(L"javaw.exe", "C:\\Minecraft\\Curse\\Instances\\Minecraft\\VoxelMapRedirDLL.dll")) {
			Sleep(1000);
		}
		printf("Finished\n");

		printf("Waiting for process to exit...\n");
		while (FindProcess(L"javaw.exe")) {
			Sleep(10000);
		}
		printf("Process exited\n");
	}	
		
	return 0;
}
