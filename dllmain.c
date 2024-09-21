#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>

#include "MinHook.h"

#pragma comment(lib, "libMinHook-x64-v141-mdd")

char buffer[1024];
wchar_t wbuffer[1024];

typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef LONG NTSTATUS;

#undef MessageBox
#define MessageBox(a,b,c,d) /* */

typedef BOOL(WINAPI *pfnGetFileAttributesExW)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
pfnGetFileAttributesExW pGetFileAttributesExW_Trampoline = NULL;
pfnGetFileAttributesExW pGetFileAttributesExW_orig = NULL;
BOOL Detour_GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation) {
	int len = (int)wcslen(lpFileName);
	wchar_t newFileName[MAX_PATH] = L"C:\\Minecraft\\Curse\\Instances\\Minecraft\\mods\\mamiyaotaru\\voxelmap\\realm.";

	//waypoint file
	if (wcsstr(lpFileName, L"mamiyaotaru") && wcscmp(lpFileName + len - wcslen(L".points"), L".points") == 0) {
		MessageBox(NULL, L"\"mamiyaotaru\" and ends with \".points\"\n", L"VoxelMapRedir", MB_OK);
		wcscat(newFileName, L"points");
		lpFileName = newFileName;
		wcstombs(buffer, lpFileName, 1023);
		MessageBox(NULL, lpFileName, L"VoxelMapRedir", MB_OK);
	}
	//map data
	else if (wcsstr(lpFileName, L"mamiyaotaru") && wcsstr(lpFileName, L"cache")) {
		MessageBox(NULL, L"\"mamiyaotaru\" and \"cache\" found\n", L"VoxelMapRedir", MB_OK);

		//file
		if (wcscmp(lpFileName + len - wcslen(L".zip"), L".zip") == 0) {
			MessageBox(NULL, L"ends with \".zip\"\n", L"VoxelMapRedir", MB_OK);
			int slashes = 0;
			int endfilename = len - 1;

			for (int i = len - 1; i >= 0; i--) {
				if (lpFileName[i] == L'\\' || lpFileName[i] == L'/')
					slashes++;
				if (slashes >= 2) {
					endfilename = i;
					break;
				}
			}

			wcscat(newFileName, &lpFileName[endfilename + 1]);
			lpFileName = newFileName;
			wcstombs(buffer, lpFileName, 1023);
			MessageBox(NULL, lpFileName, L"VoxelMapRedir", MB_OK);
		}
		//directory
		else {
			MessageBox(NULL, L"doesn't end with \".zip\"\n", L"VoxelMapRedir", MB_OK);
			int slashes = 0;
			int endfilename = len - 1;

			//if string ends with \ then account for it
			if (lpFileName[endfilename] == L'\\' || lpFileName[endfilename] == L'/') {
				slashes--;
			}

			for (int i = len - 1; i >= 0; i--) {
				if (lpFileName[i] == L'\\' || lpFileName[i] == L'/')
					slashes++;
				if (slashes >= 1) {
					endfilename = i;
					break;
				}
			}

			wcscat(newFileName, &lpFileName[endfilename + 1]);
			lpFileName = newFileName;
			wcstombs(buffer, lpFileName, 1023);
			MessageBox(NULL, lpFileName, L"VoxelMapRedir", MB_OK);
		}
	};

	return pGetFileAttributesExW_Trampoline(lpFileName, fInfoLevelId, lpFileInformation);
}


typedef HANDLE(WINAPI *pfnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
pfnCreateFileW pCreateFileW_Trampoline = NULL;
pfnCreateFileW pCreateFileW_orig = NULL;
HANDLE Detour_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	int len = (int)wcslen(lpFileName);
	wchar_t newFileName[MAX_PATH] = L"C:\\Minecraft\\Curse\\Instances\\Minecraft\\mods\\mamiyaotaru\\voxelmap\\realm.";

	//waypoint file
	if (wcsstr(lpFileName, L"mamiyaotaru") && wcscmp(lpFileName + len - wcslen(L".points"), L".points") == 0) {
		MessageBox(NULL, L"\"mamiyaotaru\" and ends with \".points\"\n", L"VoxelMapRedir", MB_OK);
		wcscat(newFileName, L"points");
		lpFileName = newFileName;
		wcstombs(buffer, lpFileName, 1023);
		MessageBox(NULL, lpFileName, L"VoxelMapRedir", MB_OK);
	}
	//map data
	else if (wcsstr(lpFileName, L"mamiyaotaru") && wcsstr(lpFileName, L"cache")) {
		MessageBox(NULL, L"\"mamiyaotaru\" and \"cache\" found\n", L"VoxelMapRedir", MB_OK);

		//file
		if (wcscmp(lpFileName + len - wcslen(L".zip"), L".zip") == 0) {
			MessageBox(NULL, L"ends with \".zip\"\n", L"VoxelMapRedir", MB_OK);
			int slashes = 0;
			int endfilename = len - 1;

			for (int i = len - 1; i >= 0; i--) {
				if (lpFileName[i] == L'\\' || lpFileName[i] == L'/')
					slashes++;
				if (slashes >= 2) {
					endfilename = i;
					break;
				}
			}

			wcscat(newFileName, &lpFileName[endfilename + 1]);
			lpFileName = newFileName;
			wcstombs(buffer, lpFileName, 1023);
			MessageBox(NULL, lpFileName, L"VoxelMapRedir", MB_OK);
		}
		//directory
		else {
			MessageBox(NULL, L"doesn't end with \".zip\"\n", L"VoxelMapRedir", MB_OK);
			int slashes = 0;
			int endfilename = len - 1;

			//if string ends with \ then account for it
			if (lpFileName[endfilename] == L'\\' || lpFileName[endfilename] == L'/') {
				slashes--;
			}

			for (int i = len - 1; i >= 0; i--) {
				if (lpFileName[i] == L'\\' || lpFileName[i] == L'/')
					slashes++;
				if (slashes >= 1) {
					endfilename = i;
					break;
				}
			}

			wcscat(newFileName, &lpFileName[endfilename + 1]);
			lpFileName = newFileName;
			wcstombs(buffer, lpFileName, 1023);
			MessageBox(NULL, lpFileName, L"VoxelMapRedir", MB_OK);
		}
	};

	return pCreateFileW_Trampoline(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


struct {
	LPVOID pTarget;
	LPVOID pDetour;
	LPVOID* ppOriginal;

	char* dll;
	char* func;
} hooks[] = {
	//{ pNtCreateFile_orig, &Detour_NtCreateFile, (LPVOID*)(&pNtCreateFile_Trampoline), "ntdll.dll", "NtCreateFile" },
	//{ pNtOpenFile_orig, &Detour_NtOpenFile, (LPVOID*)(&pNtOpenFile_Trampoline), "ntdll.dll", "NtOpenFile" },
	{ NULL, &Detour_CreateFileW, (LPVOID*)(&pCreateFileW_Trampoline), "kernel32.dll", "CreateFileW" },
	{ NULL, &Detour_GetFileAttributesExW, (LPVOID*)(&pGetFileAttributesExW_Trampoline), "kernelbase.dll", "GetFileAttributesExW" },
};
const int numhooks = (sizeof(hooks) / sizeof(*hooks));

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
	//find original function pointers
	for (int i = 0; i < numhooks; i++) {
		HMODULE dll = LoadLibraryA(hooks[i].dll);
		if (!dll) {
			MessageBoxA(NULL, hooks[i].dll, "VoxelMapRedir: could not load dll", MB_OK);
			return 0;
		}
		hooks[i].pTarget = (LPVOID)GetProcAddress(dll, hooks[i].func);
		if (!hooks[i].pTarget) {
			MessageBoxA(NULL, hooks[i].func, "VoxelMapRedir: could not find func", MB_OK);
			return 0;
		}
	}

	if (MH_Initialize() != MH_OK) {
		MessageBoxA(NULL, "MH_Initialize() failed\n", "VoxelMapRedir", MB_OK);
		return FALSE;
	}

	for (int i = 0; i < numhooks; i++) {
		if (MH_CreateHook(hooks[i].pTarget, hooks[i].pDetour, hooks[i].ppOriginal) != MH_OK) {
			MessageBoxA(NULL, hooks[i].func, "VoxelMapRedir: could not create hook for func", MB_OK);
			return FALSE;
		}

		if (MH_EnableHook(hooks[i].pTarget) != MH_OK) {
			MessageBoxA(NULL, hooks[i].func, "VoxelMapRedir: could not enable hook for func", MB_OK);
			return FALSE;
		}
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	DWORD tid;
	HANDLE hthread;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hthread = CreateThread(NULL, 0, ThreadFunc, NULL, 0, &tid);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		for (int i = 0; i < numhooks; i++) {
			MH_DisableHook(hooks[i].pTarget);
		}

		MH_Uninitialize();

		break;
	}
	return TRUE;
}
