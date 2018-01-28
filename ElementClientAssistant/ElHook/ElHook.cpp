// ElHook.cpp: 定义 DLL 的初始化例程。
//

#include "stdafx.h"
#include "ElHook.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//
//TODO:  如果此 DLL 相对于 MFC DLL 是动态链接的，
//		则从此 DLL 导出的任何调入
//		MFC 的函数必须将 AFX_MANAGE_STATE 宏添加到
//		该函数的最前面。
//
//		例如: 
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// 此处为普通函数体
//		}
//
//		此宏先于任何 MFC 调用
//		出现在每个函数中十分重要。  这意味着
//		它必须作为以下项中的第一个语句:
//		出现，甚至先于所有对象变量声明，
//		这是因为它们的构造函数可能生成 MFC
//		DLL 调用。
//
//		有关其他详细信息，
//		请参阅 MFC 技术说明 33 和 58。
//

// CElHookApp

BEGIN_MESSAGE_MAP(CElHookApp, CWinApp)
END_MESSAGE_MAP()


// CElHookApp 构造

CElHookApp::CElHookApp()
{
	// TODO:  在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}


// 唯一的 CElHookApp 对象

CElHookApp theHookDll;


// CElHookApp 初始化

BOOL CElHookApp::InitInstance()
{
	CWinApp::InitInstance();

	return TRUE;
}

///钩子回调函数
LRESULT CALLBACK KeyboardProc(int code,       // hook code
	WPARAM wParam,  // virtual-key code
	LPARAM lParam   // keystroke-message information
) {
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	if (wParam == VK_F1 && ((lParam&(1 << 31)) == 0)) {
		AfxMessageBox(L"F1键在游戏窗口被按下了！");
	}
	return CallNextHookEx(0, code, wParam, lParam);

}

void CElHookApp::SetHook(LPWSTR prc_name) {
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	HWND hd = FindWindow(NULL, prc_name);
	if (hd == NULL)
	{
		AfxMessageBox(L"请打开输入的程序进程");
		return;
	}
	DWORD dwid = GetWindowThreadProcessId(hd, NULL);
	//
	HINSTANCE hdll = ::GetModuleHandleW(L"ElHook.dll");

	SetWindowsHookEx(WH_KEYBOARD, &KeyboardProc, hdll, dwid);
}
