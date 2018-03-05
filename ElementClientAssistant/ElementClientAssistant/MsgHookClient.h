#pragma once
#include <windows.h>
#include <Tlhelp32.h>


typedef LONG(WINAPI *TNtReadVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, UINT64 NumberOfBytesToRead, PUINT64 NumberOfBytesReaded);

class MsgHookClient
{
public:
	MsgHookClient();
	BOOL SetWinHKInject(WCHAR *pszDllPath, WCHAR *pszProcess);
private:
	DWORD GetTargetProcessIdFromProcName(WCHAR *procName);
	DWORD GetTargetThreadIdFromProcId(DWORD procId);
};