
// ElementClientAssistantDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "ElementClientAssistant.h"
#include "ElementClientAssistantDlg.h"
#include "afxdialogex.h"
#include "./../ElHook/ElHook.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CElementClientAssistantDlg 对话框



CElementClientAssistantDlg::CElementClientAssistantDlg(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_ELEMENTCLIENTASSISTANT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CElementClientAssistantDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CElementClientAssistantDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTONChange, &CElementClientAssistantDlg::OnBnClickedButtonchange)
	ON_BN_CLICKED(IDC_BUTTON1, &CElementClientAssistantDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CElementClientAssistantDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CElementClientAssistantDlg 消息处理程序

BOOL CElementClientAssistantDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CElementClientAssistantDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CElementClientAssistantDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CElementClientAssistantDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CElementClientAssistantDlg::OnBnClickedButtonchange()
{
	//CString  str = _T("OllyDbg - [CPU]");
	//CString  str = _T("无标题 - 记事本");
	//CWnd *pWnd = FindWindow(NULL, str);
	//if (pWnd->m_hWnd != NULL)
	//{
	//	pWnd->SetWindowText(_T("1"));  //句柄得到了，可以干你想干的事情了。
	//	//pWnd->ShowWindow(SW_HIDE);
	//	pWnd->ShowWindow(SW_SHOW);
	//}

	CEdit* pBoxOne;
	pBoxOne = (CEdit*)GetDlgItem(IDC_EDITName);
	CString str;
	pBoxOne->GetWindowText(str);
}


void CElementClientAssistantDlg::OnBnClickedButton1()
{

	/*CString  str = _T("无标题 - 记事本");
	HWND pWnd = ::FindWindow(NULL, str);*/

	/*CEdit* pBoxOne;
	pBoxOne = (CEdit*)GetDlgItem(IDC_EDITName);
	CString str;
	pBoxOne->GetWindowText(str);

	if (str.IsEmpty()) {
		str = L"1.txt - Notepad";
	}

	CElHookApp theHookDllApp;
	theHookDllApp.SetHook(str);*/
	client.UnhookWinHKInject();
}


void CElementClientAssistantDlg::OnBnClickedButton2()
{
	// TODO: Add your control notification handler code here
	CEdit* pBoxOne;
	pBoxOne = (CEdit*)GetDlgItem(IDC_EDITName);
	CString procName;
	pBoxOne->GetWindowText(procName);

	

	if (procName.IsEmpty()) {
		procName = L"notepad.exe";
	}

	CString dllName = L"MsgHook.dll";
	client.SetWinHKInject((WCHAR*)(LPCTSTR)dllName, (WCHAR*)(LPCTSTR)procName);
}
