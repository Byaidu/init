#include <windows.h>
#include <cstdio>
#include <io.h>
#include <iostream>
using namespace std;
typedef void(*pcall)(wchar_t*, wchar_t*);
pcall list[100];
int sz = 0;
char path[MAX_PATH];
char finddll[] = "\\*.dll";

#define SetEnvW ((PFNSETENVIRONMENTVARIABLE)bakSetEnv)

typedef bool  (WINAPI *PFNSETENVIRONMENTVARIABLE)(wchar_t *, wchar_t *);

bool *bakSetEnv = (bool  *)SetEnvironmentVariableW;

extern "C" __declspec(dllexport) int Init(void)
{
	return 0;
}

void HookAPI(void *OldFunc, void *NewFunc)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeaders;
	PIMAGE_OPTIONAL_HEADER    pOptHeader;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDescriptor;
	PIMAGE_THUNK_DATA         pThunkData;
	//PIMAGE_IMPORT_BY_NAME     pImportByName;
	HMODULE hMod;
	//------------hook api----------------
	hMod = GetModuleHandle(NULL);
	pDosHeader = (PIMAGE_DOS_HEADER)hMod;
	pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hMod + pDosHeader->e_lfanew);
	pOptHeader = (PIMAGE_OPTIONAL_HEADER)&(pNTHeaders->OptionalHeader);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hMod + pOptHeader->DataDirectory[1].VirtualAddress);
	while (pImportDescriptor->FirstThunk)
	{
		//char * dllname = (char *)((BYTE *)hMod + pImportDescriptor->Name);
		pThunkData = (PIMAGE_THUNK_DATA)((BYTE *)hMod + pImportDescriptor->OriginalFirstThunk);
		int no = 1;
		while (pThunkData->u1.Function)
		{
			//char * funname = (char *)((BYTE *)hMod + (DWORD)pThunkData->u1.AddressOfData + 2);
			PDWORD lpAddr = (DWORD *)((BYTE *)hMod + (DWORD)pImportDescriptor->FirstThunk) + (no - 1);
			//修改内存的部分
			if ((*lpAddr) == (unsigned int)OldFunc)
			{
				//修改内存页的属性
				DWORD dwOLD;
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQuery(lpAddr, &mbi, sizeof(mbi));
				VirtualProtect(lpAddr, sizeof(DWORD), PAGE_READWRITE, &dwOLD);
				WriteProcessMemory(GetCurrentProcess(), lpAddr, &NewFunc, sizeof(DWORD), NULL);
				//恢复内存页的属性
				VirtualProtect(lpAddr, sizeof(DWORD), dwOLD, 0);
			}
			//---------
			no++;
			pThunkData++;
		}
		pImportDescriptor++;
	}
	//-------------------HOOK END-----------------
}

BOOL WINAPI calllist(wchar_t *varName, wchar_t *varValue)
{
	SetEnvW(varName, varValue);
	if (varName[0] >= 'a'&&varName[0] <= 'z')
	{
		for (int i = 0; i < sz; i++)
			(*list[i])(varName, varValue);
	}
	return 1;
}

void loaddll()
{
	GetModuleFileNameA(NULL, path, sizeof(path));
	char *p = strrchr(path, '\\');
	*p = 0x00;
	memcpy(path + strlen(path), finddll, sizeof(finddll));
	//printf("Find:%s\n", path);

	HANDLE hFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAA mFileData;
	hFile = FindFirstFileA(path, &mFileData);
	if (hFile == INVALID_HANDLE_VALUE) return;
	do
	{
			//printf("Load:%s\n", mFileData.cFileName);
			HMODULE hDllLib = LoadLibraryA(mFileData.cFileName);
			FARPROC fpFun = GetProcAddress(hDllLib, "call");
			if (fpFun != NULL) list[sz++] = (pcall)fpFun;
	} while (FindNextFileA(hFile, &mFileData));
}

bool WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		loaddll();
		HookAPI(SetEnvironmentVariableW, calllist);
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return true;
}