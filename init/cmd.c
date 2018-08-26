#define _CRT_SECURE_NO_WARNINGS

#include "CPWDLLA.H"

//#include <shlwapi.h>
#include <direct.h>
#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <windows.h>

BOOL WINAPI	PathFileExistsA(const char *);
LPTSTR WINAPI	GetCommandLineA(void);
PTSTR WINAPI	PathGetArgsA(PTSTR pszPath);

int main(int argc, char *argv[])
{
	int			n;
	char			strDll[MAX_PATH];
	char			cmdLine[8192] = "";

	STARTUPINFO		si = { sizeof(si), 0 };
	PROCESS_INFORMATION	pi = { 0 };

	GetModuleFileNameA(NULL, strDll, MAX_PATH);
	strrchr(strDll, '\\')[1] = '\0';
	strcat(strDll, "init.dll");

	puts(strDll);

	if(!PathFileExistsA(strDll)) * (void **) 0 = 0;

	strcpy(cmdLine, getenv("ComSpec"));
	strcat(cmdLine, " ");
	strcat(cmdLine, PathGetArgsA(GetCommandLineA()));

	puts(cmdLine);

	CreateProcessWithDllA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi, strDll, NULL);

	WaitForSingleObject(pi.hProcess, INFINITE);

	return 0;
}
