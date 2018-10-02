// #include <stdio.h>
#include <string.h>
#include <windows.h>
#include "APIHOOK.H"

#if defined(_MSC_VER)
#pragma comment(linker, "/nodefaultlib:libcmt.lib")
#pragma comment(lib, "msvcrt.lib")
#pragma comment(lib, "kernel32.lib")
#endif
#define MAX_DLL 128

HMODULE		hDllMod = NULL;

const char	DLLPath[] = "\\*.dll";

typedef void (*PCALL) (wchar_t *, wchar_t *);

struct DLLcall
{
	HMODULE hModule;
	PCALL	pCall;
} List[MAX_DLL];

int	LCount;

APIBAK	bak;

BOOL WINAPI CallList(wchar_t *varName, wchar_t *varValue)
{
	BOOL	ret;
	int	i;

	APIFREE(&bak);
	ret = SetEnvironmentVariableW(varName, varValue);
	APIHOOK("KernelBASE.dll", "SetEnvironmentVariableW", (void *) &CallList, &bak);

	// printf("Call Event:\n");
	for(i = 0; i < LCount; i++) (*List[i].pCall) (varName, varValue);

	return ret;
}

void LoadDLL()
{
	char			ThisPath[MAX_PATH], FindPath[MAX_PATH], DLLPathName[MAX_PATH];
	HANDLE			hFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAA	mFileData;

	GetModuleFileNameA(hDllMod, ThisPath, sizeof(ThisPath));

	strrchr(ThisPath, '\\')[1] = '\0';

	strcpy(FindPath, ThisPath);
	strcat(FindPath, DLLPath);

	// printf("Path: '%s'\n", FindPath);
	LCount = 0;
	hFile = FindFirstFileA(FindPath, &mFileData);
	if(hFile == INVALID_HANDLE_VALUE) return;
	do
	{
		HMODULE hModule;
		FARPROC pCall;

		//注意坑人的地方
		strcpy(DLLPathName, ThisPath);
		strcat(DLLPathName, mFileData.cFileName);

		hModule = LoadLibraryA(DLLPathName);
		pCall = GetProcAddress(hModule, "call");

		if(pCall != NULL)
		{
			// printf("Load: '%s' (%08X,%08X)\n", mFileData.cFileName, hModule, pCall);
			List[LCount].hModule = hModule;
			List[LCount].pCall = (PCALL) pCall;
			LCount++;
		}
		else if(hModule != NULL)
		{
			// printf("None: '%s'\n", mFileData.cFileName);
			FreeLibrary(hModule);
		}
		else
		{
			// printf("Fail: '%s'\n", mFileData.cFileName);
		}
	} while(FindNextFileA(hFile, &mFileData));
	FindClose(hFile);
}

void FreeDLL()
{
	int	i;
	for(i = 0; i < LCount; i++) FreeLibrary(List[LCount].hModule);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	switch(dwReason)
	{
	case DLL_PROCESS_ATTACH:
		hDllMod = hModule;
		DisableThreadLibraryCalls(hModule);
		LoadDLL();
		APIHOOK("KernelBASE.dll", "SetEnvironmentVariableW", (void *) &CallList, &bak);
		break;

	case DLL_PROCESS_DETACH:
		FreeDLL();
		APIFREE(&bak);
		break;
	}

	return TRUE;
}
