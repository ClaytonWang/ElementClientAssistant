// MsgHook.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#pragma data_seg(SHARD_SEG_NAME)
static HHOOK g_hhook;
#pragma data_seg()

__declspec(dllexport) LRESULT CALLBACK MyMessageProc(int code, WPARAM wParam, LPARAM lParam)
{
	//
	//你自己对消息的处理
	//
	if (wParam == VK_F1 && ((lParam&(1 << 31)) == 0)) {
		MessageBoxW(NULL, L"F1键在游戏窗口被按下了！", L"dll inject", MB_OK);
		return 1;
	}
	return CallNextHookEx(g_hhook, code, wParam, lParam);
}
