// ElHook.h: ElHook DLL 的主标头文件
//

#pragma once

#ifndef __AFXWIN_H__
	#error "在包含此文件之前包含“stdafx.h”以生成 PCH 文件"
#endif

#include "resource.h"		// 主符号


// CElHookApp
// 有关此类实现的信息，请参阅 ElHook.cpp
//

class _declspec(dllexport) CElHookApp : public CWinApp
{
public:
	CElHookApp();

// 重写
public:
	virtual BOOL InitInstance();

	void SetHook(CString prc_name);
	CString ReadProcessMemory(DWORD dwRdAddr);

	DECLARE_MESSAGE_MAP()
private:
	HANDLE hProc;
	int __asmTest();
};
