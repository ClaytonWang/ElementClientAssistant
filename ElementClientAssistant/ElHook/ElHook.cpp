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
const char *t = "clay111";
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
		//AfxMessageBox(L"F1键在游戏窗口被按下了！");
		CString str;
		str.Format(_T("%d"), wParam);
		AfxMessageBox(str);
		return 1;
	}
	return CallNextHookEx(0, code, wParam, lParam);
}

void CElHookApp::SetHook(CString prc_name) {
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	HWND hd = FindWindow(NULL, prc_name);
	if (hd == NULL)
	{
		AfxMessageBox(L"请打开输入的程序进程");
		return;
	}

	DWORD procId;
	DWORD dwid = GetWindowThreadProcessId(hd, &procId);
	HINSTANCE hdll = GetModuleHandleW(L"ElHook.dll");

	//SetWindowsHookEx(WH_KEYBOARD, &KeyboardProc, hdll, dwid);

	this->hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procId);
	DWORD dwRdAddr = 0x76ED7254;
	CString str = this->ReadProcessMemory(dwRdAddr);
	int a = this->__asmTest();
	CloseHandle(this->hProc);

	
}

CString CElHookApp::ReadProcessMemory(DWORD dwRdAddr)
{
	char buffer[1024] = { '\0' };
	SIZE_T dwNumberOfBytesRead;
	BOOL bRead = ::ReadProcessMemory(this->hProc, LPVOID(dwRdAddr), LPVOID(buffer), sizeof(buffer), &dwNumberOfBytesRead);
	if (bRead) {
		return CString(buffer);
	}
	else
	{
		return CString("");
	}
}

int CElHookApp::__asmTest() {
	/*unsigned int a = 1, b = 2;
	__asm {
		MOV EAX, a;
		MOV EBX, b;
		ADD EAX, EBX;
		MOV a, EAX;
	}
	return a;*/

	//g_val1 = 100;
	/*int a = (int)Int_3(1,2,3,4,5);

	int b = Int_4();
	return a;*/
	return 0;
}