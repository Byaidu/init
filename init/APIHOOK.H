#include <windows.h>
typedef struct _APIBAK
{
	HMODULE hDLL;
	void	*func;
	char	bak[5];
} APIBAK;

BOOL APIHOOK(const char *pcsDllName, const char *pcsFuncName, void *pfnNewFunc, APIBAK *backup)
{
	char		JMP[5] = { 0xE9 };
	DWORD		oldAttr;
	unsigned int	jmpDist;

	backup->hDLL = LoadLibraryA(pcsDllName);
	backup->func = (void *) GetProcAddress(backup->hDLL, pcsFuncName);

	if(!VirtualProtect(backup->func, 5, PAGE_READWRITE, &oldAttr)) return FALSE;

	jmpDist = (int) pfnNewFunc - (int) backup->func - 5;
	memcpy(&JMP[1], &jmpDist, sizeof(unsigned int));

	memcpy(backup->bak, backup->func, sizeof(backup->bak));
	memcpy(backup->func, JMP, sizeof(JMP));

	VirtualProtect(backup->func, 5, oldAttr, &oldAttr);
	return TRUE;
}

BOOL APIFREE(const APIBAK *backup)
{
	DWORD	oldAttr;

	if(!VirtualProtect(backup->func, 5, PAGE_READWRITE, &oldAttr)) return FALSE;

	memcpy(backup->func, backup->bak, sizeof(backup->bak));

	VirtualProtect(backup->func, 5, oldAttr, &oldAttr);
	FreeLibrary(backup->hDLL);
	return TRUE;
}
