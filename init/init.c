#include <windows.h>

#define MAX_DLL 100
#define SetEnvW (*bakSetEnv)

const char	DLLPath[] = "\\*.dll";

typedef BOOL WINAPI (*PSetEnv) (wchar_t *, wchar_t *);
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

		int	no = 1;
		while(pThunkData->u1.Function)
		{
			//char * funname = (char *)((BYTE *)hMod + (DWORD)pThunkData->u1.AddressOfData + 2);
			PDWORD	lpAddr = (DWORD *) ((BYTE *) hMod + (DWORD) pImportDescriptor->FirstThunk) + (no - 1);

			//�޸��ڴ�Ĳ���
			if((*lpAddr) == (unsigned int) OldFunc)
			{
				//�޸��ڴ�ҳ������
				DWORD				dwOLD;
				MEMORY_BASIC_INFORMATION	mbi;
				VirtualQuery(lpAddr, &mbi, sizeof(mbi));
				VirtualProtect(lpAddr, sizeof(DWORD), PAGE_READWRITE, &dwOLD);
				WriteProcessMemory(GetCurrentProcess(), lpAddr, &NewFunc, sizeof(DWORD), NULL);

				//�ָ��ڴ�ҳ������
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
	for(int i = 0; i < LCount; i++) (*List[i].pCall) (varName, varValue);

	return ret;
}

void LoadDLL()
{
	char			Path[MAX_PATH];
	HANDLE			hFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAA	mFileData;

	GetModuleFileNameA(NULL, Path, sizeof(Path));

	char	*cp = strrchr(Path, '\\');
	*cp = '\0';
	strcat(Path, DLLPath);

	//printf("Find: '%s'\n", Path);
	LCount = 0;
	hFile = FindFirstFileA(Path, &mFileData);
	if(hFile == INVALID_HANDLE_VALUE) return;
	do
	{
		//printf("Load: '%s'\n", mFileData.cFileName);
		HMODULE hModule = LoadLibraryA(mFileData.cFileName);
		FARPROC pCall = GetProcAddress(hModule, "call");
		if(pCall != NULL)
		{
			List[LCount].hModule = hModule;
			List[LCount].pCall = (PCALL) pCall;
			LCount++;
		}
		else if(hModule != NULL)
			FreeLibrary(hModule);
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
		break;
	}

	return TRUE;
}
