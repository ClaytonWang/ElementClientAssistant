#include "stdafx.h"
#include "MsgHookClient.h"

MsgHookClient::MsgHookClient()
{
}

DWORD MsgHookClient::GetTargetProcessIdFromProcName(WCHAR *procName)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapshot, hProcess;
	BOOL retval, ProcFound = false;
	unsigned long pTID, threadID;

	thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (thSnapshot == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, L"Error: unable to create toolhelp snapshot", L"Loader", NULL);
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32First(thSnapshot, &pe);

	while (retval)
	{
		if (_wcsicmp(pe.szExeFile, procName) == 0)
		{
			ProcFound = true;
			break;
		}

		retval = Process32Next(thSnapshot, &pe);
		pe.dwSize = sizeof(PROCESSENTRY32);
	}

	CloseHandle(thSnapshot);
	if (ProcFound)
		return pe.th32ProcessID;
	else
		return NULL;
}

DWORD MsgHookClient::GetTargetThreadIdFromProcId(DWORD procId)
{
	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	BOOL retval, ThreadFound = false;

	retval = Thread32First(hSnapshot, &te);
	while (retval)
	{
		if (procId == te.th32OwnerProcessID)
		{
			ThreadFound = true;
			break;
		}
		retval = Thread32Next(hSnapshot, &te);
		te.dwSize = sizeof(THREADENTRY32);
	}

	CloseHandle(hSnapshot);
	if (ThreadFound)
		return te.th32ThreadID;
	else
		return NULL;

	//_asm {
	//	mov eax, dword ptr fs:[0x18]
	//	add eax, 36
	//	mov [pTID], eax
	//}

	//hProcess = OpenProcess(PROCESS_VM_READ, false, pe.th32ProcessID);
	////BOOL isReadSucc = ReadProcessMemory(hProcess, (const void *)pTID, &threadID, 4, NULL);

	//TNtReadVirtualMemory64  pfnNtReadVirtualMemory = (TNtReadVirtualMemory64)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtWow64ReadVirtualMemory64");
	//LONG a = pfnNtReadVirtualMemory(hProcess, (PVOID64*)pTID, &threadID, 4, NULL);
	//DWORD d =GetLastError();
	//CloseHandle(hProcess);

	//return a;
}

//
//利用Windows API SetWindowsHookEx实现注入DLL
//
BOOL MsgHookClient::SetWinHKInject(WCHAR *pszDllPath, WCHAR *pszProcess)
{
	HMODULE hMod = NULL;
	bool    bSuccess = false;
	DWORD  lpFunc = NULL;
	DWORD  dwThreadId;
	DWORD  dwProcID;
	PVOID  pShareM = NULL;

	OutputDebugString(L"[+] SetWinHKInject Enter!\n");


	hMod = LoadLibrary(pszDllPath);
	if (!hMod)
	{
		OutputDebugString(L"[+] LoadLibrary error!\n");
		goto Exit;
	}


	lpFunc = (DWORD)GetProcAddress(hMod, "MyMessageProc");
	if (!lpFunc)
	{
		OutputDebugString(L"[+] GetProcAddress error!\n");
		goto Exit;
	}

	dwProcID = GetTargetProcessIdFromProcName(pszProcess);
	if (!dwProcID) 
	{
		OutputDebugString(L"[+] GetProcessId error!\n");
		goto Exit;
	}
	dwThreadId = GetTargetThreadIdFromProcId(dwProcID);
	if (!dwThreadId)
	{
		OutputDebugString(L"[+] GetThreadId error!\n");
		goto Exit;
	}

	g_hhook = SetWindowsHookEx(
		WH_KEYBOARD,//WH_KEYBOARD,//WH_CALLWNDPROC,
		(HOOKPROC)lpFunc,
		hMod,
		dwThreadId//0 为系统级钩子
	);

	if (!g_hhook)
	{
		OutputDebugString(L"[-] SetWindowsHookEx error !\n");
		goto Exit;
	}

	OutputDebugString(L"[!] SetWinHKInject Exit!\n");
	bSuccess = true;
Exit:
	if (hMod)
		FreeLibrary(hMod);
	return bSuccess;

}

BOOL MsgHookClient::UnhookWinHKInject()
{
	return UnhookWindowsHookEx(g_hhook);
}
