// MsgHook.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#pragma data_seg(SHARD_SEG_NAME)
static HHOOK g_hhook;
#pragma data_seg()
const char *t = "clay123";
__declspec(dllexport) LRESULT CALLBACK MyMessageProc(int code, WPARAM wParam, LPARAM lParam)
{
	//
	//你自己对消息的处理
	//
	
	if (wParam == VK_F1 && ((lParam&(1 << 31)) == 0)) {
		MessageBoxW(NULL, L"F1键在游戏窗口被按下了！", L"dll inject", MB_OK);
		return 1;
	}
	HMODULE hDll = LoadLibraryEx(L"ElHook.dll", NULL, LOAD_WITH_ALTERED_SEARCH_PATH);


	HANDLE hthSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	MODULEENTRY32W me = { sizeof(me) };

	BOOL bFound = FALSE;
	BOOL bMoreMods = Module32FirstW(hthSnapshot, &me);
	for (; bMoreMods; bMoreMods = Module32NextW(hthSnapshot, &me))
	{
		bFound = (_wcsicmp(me.szModule, L"ElHook.dll") == 0) || (_wcsicmp(me.szExePath, L"MsgHook.dll") == 0);
		if (bFound) break;
	}

	return CallNextHookEx(g_hhook, code, wParam, lParam);
}
