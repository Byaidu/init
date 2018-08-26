#define _CRT_SECURE_NO_WARNINGS

#include "CPWDLLA.H"

//#include <shlwapi.h>
#include <direct.h>
#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <windows.h>

BOOL WINAPI	PathFileExistsA(const char *);

int main(int argc, char *argv[])
{
	char			strDll[MAX_PATH];

	STARTUPINFO		si = { sizeof(si), 0 };
	PROCESS_INFORMATION	pi = { 0 };

	GetModuleFileNameA(NULL, strDll, MAX_PATH);
	strrchr(strDll, '\\')[1] = '\0';
	strcat(strDll, "init.dll");

	puts(strDll);

	if(!PathFileExistsA(strDll)) * (void **) 0 = 0;

	CreateProcessWithDllA
	(
		NULL,
		"C:\\WINDOWS\\system32\\cmd.exe",
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi,
		strDll,
		NULL
	);

	WaitForSingleObject(pi.hProcess, INFINITE);

	puts(strDll);

	return 0;
}
