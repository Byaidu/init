//#include <stdio.h>
#include <windows.h>

#if defined(_MSC_VER)
#pragma comment(lib,"kernel32.lib")
#pragma comment(linker,"/entry:DllMain")
#endif

#define MAX_DLL 100
#define SetEnvW (*bakSetEnv)

const char	DLLPath[] = "\\*.dll";

typedef BOOL (WINAPI *PSetEnv) (wchar_t *, wchar_t *);
typedef void (*PCALL) (wchar_t *, wchar_t *);

struct DLLcall
{
	HMODULE hModule;
	PCALL	pCall;
} List[MAX_DLL];

int	LCount;

PSetEnv bakSetEnv = (PSetEnv) SetEnvironmentVariableW;

__declspec(dllexport)
int Init(void)
{
	return 0;
}

void HookAPI(void *OldFunc, void *NewFunc)
{
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNTHeaders;
	PIMAGE_OPTIONAL_HEADER		pOptHeader;
	PIMAGE_IMPORT_DESCRIPTOR	pImportDescriptor;
	PIMAGE_THUNK_DATA		pThunkData;

	//PIMAGE_IMPORT_BY_NAME     pImportByName;
	HMODULE				hMod;

	int				no = 1;

	//------------hook api----------------
	hMod = GetModuleHandle(NULL);
	pDosHeader = (PIMAGE_DOS_HEADER) hMod;
	pNTHeaders = (PIMAGE_NT_HEADERS) ((BYTE *) hMod + pDosHeader->e_lfanew);
	pOptHeader = (PIMAGE_OPTIONAL_HEADER) & (pNTHeaders->OptionalHeader);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) ((BYTE *) hMod + pOptHeader->DataDirectory[1].VirtualAddress);
	while(pImportDescriptor->FirstThunk)
	{
		//char * dllname = (char *)((BYTE *)hMod + pImportDescriptor->Name);
		pThunkData = (PIMAGE_THUNK_DATA) ((BYTE *) hMod + pImportDescriptor->OriginalFirstThunk);

		while(pThunkData->u1.Function)
		{
			//char * funname = (char *)((BYTE *)hMod + (DWORD)pThunkData->u1.AddressOfData + 2);
			PDWORD	lpAddr = (DWORD *) ((BYTE *) hMod + (DWORD) pImportDescriptor->FirstThunk) + (no - 1);

			//修改内存的部分
			if((*lpAddr) == (unsigned int) OldFunc)
			{
				DWORD				dwOLD;
				MEMORY_BASIC_INFORMATION	mbi;
				//printf("Change: %08X(%08X -> %08X)\n", lpAddr, *lpAddr, NewFunc);

				//修改内存页的属性
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

BOOL WINAPI CallList(wchar_t *varName, wchar_t *varValue)
{
	BOOL	ret = SetEnvW(varName, varValue);
	int	i;
	//printf("Call Event:\n");
	for(i = 0; i < LCount; i++) (*List[i].pCall) (varName, varValue);

	return ret;
}

void LoadDLL()
{
	char			Path[MAX_PATH], *cp;
	HANDLE			hFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAA	mFileData;

	GetModuleFileNameA(NULL, Path, sizeof(Path));

	cp = strrchr(Path, '\\');
	*cp = '\0';
	strcat(Path, DLLPath);

	//printf("Path: '%s'\n", Path);
	LCount = 0;
	hFile = FindFirstFileA(Path, &mFileData);
	if(hFile == INVALID_HANDLE_VALUE) return;
	do
	{
		HMODULE hModule = LoadLibraryA(mFileData.cFileName);
		FARPROC pCall = GetProcAddress(hModule, "call");
		if(pCall != NULL)
		{
			//printf("Load: '%s' (%08X,%08X)\n", mFileData.cFileName, hModule, pCall);
			List[LCount].hModule = hModule;
			List[LCount].pCall = (PCALL) pCall;
			LCount++;
		}
		else if(hModule != NULL)
		{
			//printf("Fail: '%s'\n", mFileData.cFileName);
			FreeLibrary(hModule);
		}
	} while(FindNextFileA(hFile, &mFileData));
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
		DisableThreadLibraryCalls(hModule);
		LoadDLL();
		HookAPI(SetEnvironmentVariableW, CallList);
		break;

	case DLL_PROCESS_DETACH:
		FreeDLL();
		HookAPI(CallList, bakSetEnv);
		break;
	}

	return TRUE;
}
