// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
BOOL isLoad = false;
const char *t1 = "clay";

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		{
			//
			//加入你想在目标进程空间HOOK的代码
			//
			
			isLoad = TRUE;
			MessageBoxW(NULL, L"SetWindowsHookEx inject success", L"dll inject", MB_OK);
		}
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

