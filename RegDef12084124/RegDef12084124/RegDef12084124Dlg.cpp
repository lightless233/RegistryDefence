
// RegDef12084124Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "RegDef12084124.h"
#include "RegDef12084124Dlg.h"
#include "afxdialogex.h"

#include <winsvc.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif




// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CRegDef12084124Dlg 对话框




CRegDef12084124Dlg::CRegDef12084124Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CRegDef12084124Dlg::IDD, pParent)
	, m_returnBytes(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_bNotLeave = TRUE;
	//ZeroMemory(m_OutBuffer, 512);
}

void CRegDef12084124Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CRegDef12084124Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START, &CRegDef12084124Dlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_STOP, &CRegDef12084124Dlg::OnBnClickedStop)
	ON_BN_CLICKED(IDC_BUTTON1, &CRegDef12084124Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_SAVELOG, &CRegDef12084124Dlg::OnBnClickedSavelog)
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CRegDef12084124Dlg 消息处理程序

BOOL CRegDef12084124Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	CTime t = CTime::GetCurrentTime();
	CEdit *editLog = (CEdit*)GetDlgItem(IDC_LOG);
	char tmp[512];
	ZeroMemory(tmp, 512);
	sprintf(tmp, "[%d-%d-%d %d:%d:%d] Load main module...success.\r\n", t.GetYear(),
		t.GetMonth(), t.GetDay(), t.GetHour(), t.GetMinute(), t.GetSecond());

	editLog->SetWindowText(tmp);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CRegDef12084124Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CRegDef12084124Dlg::OnPaint()
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
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CRegDef12084124Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

char *DriverName = "RegDef";
char *DriverPath = "C:\\Windows\\System32\\";

void CRegDef12084124Dlg::OnBnClickedStart()
{
	// 驱动加载
	//AfxBeginThread(ThreadProc, this);
	char szCurrentPath[256];
	GetCurrentDirectory(256, szCurrentPath);

	char szDriverImagePath[256];
	GetFullPathName(szCurrentPath, 256, szDriverImagePath, NULL);

	strcat(szDriverImagePath, "\\SSDT_Hook_DriverReg.sys");

	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;

	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		// 打开失败
		AfxMessageBox("OpenSCManager failure");
		return ;
	}
	else
	{
		AfxMessageBox("OpenSCM success.");
	}

	//MessageBox(szDriverImagePath);

	// 创建驱动所对应的服务
	hServiceDDK = CreateService( hServiceMgr, 
		DriverName,
		DriverName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		szDriverImagePath,
		NULL,NULL,NULL,NULL,NULL);
	AfxMessageBox(szDriverImagePath);
	DWORD dwRtn;
	if (hServiceDDK == NULL)
	{
		dwRtn = GetLastError();
		if ( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
		{
			// 由于其他原因创建服务失败
			AfxMessageBox("Create Service Failed.");
			goto BeforeLeave;
		}
		else
		{
			// 服务创建失败，因为已经创立过
			AfxMessageBox("Create Service Failed. Service already exists.");
		}

		// 驱动已经创建过了，只需要打开即可
		hServiceDDK = OpenService(hServiceMgr, DriverName, SERVICE_ALL_ACCESS);

		if (hServiceDDK == NULL)
		{
			// 打开服务失败
			dwRtn = GetLastError();
			AfxMessageBox("OpenService failure.");
			goto BeforeLeave;
		}
		else
		{
			AfxMessageBox("OpenService success.");
		}

	}
	else
	{
		AfxMessageBox("CreateService success.");
	}

	//开启此项服务
	bRet = StartService( hServiceDDK, NULL, NULL);
	if (!bRet)
	{
		DWORD dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
		{
			char buffer[512];
			sprintf(buffer, "StartService failure. %u", dwRtn);
			AfxMessageBox(buffer);
			goto BeforeLeave;
		}
		else
		{
			if (dwRtn == ERROR_IO_PENDING)
			{
				// 设备被挂住
				AfxMessageBox( "StartService failure. ERROR_IO_PENDING");
				goto BeforeLeave;
			}
			else
			{
				AfxMessageBox("StartService failure. ERROR_SERVICE_ALREADY_RUNNING");
				goto BeforeLeave;
			}
		}
	}
	//////////////////////////////////////////////////////////////////////////
	// 驱动加载完成，继续进行通信初始化工作
	//////////////////////////////////////////////////////////////////////////
	// 打开驱动句柄
	AfxMessageBox("Load Driver Done.");
	m_hDevice = CreateFile("\\\\.\\RegDef", GENERIC_READ | GENERIC_WRITE, 
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
	if (m_hDevice == INVALID_HANDLE_VALUE)
	{
		CTime t = CTime::GetCurrentTime();
		char tmp[512];
		ZeroMemory(tmp, 512);
		sprintf(tmp, "[%d-%d-%d %d:%d:%d] [Error] open device failure!\r\n", t.GetYear(),
			t.GetMonth(), t.GetDay(), t.GetHour(), t.GetMinute(), t.GetSecond());
		CString strLog;
		CString strTemp;
		CEdit *editLog = (CEdit *)GetDlgItem(IDC_LOG);
		editLog->GetWindowText(strLog);
		strTemp.Format("%s", tmp);
		strLog += tmp;
		editLog->SetWindowText(strLog);
	}
	else
	{
		CTime t = CTime::GetCurrentTime();
		char tmp[512];
		ZeroMemory(tmp, 512);
		sprintf(tmp, "[%d-%d-%d %d:%d:%d] Open device success.\r\n", t.GetYear(),
			t.GetMonth(), t.GetDay(), t.GetHour(), t.GetMinute(), t.GetSecond());
		CString strlog, strTemp;
		CEdit *editLog = (CEdit *)GetDlgItem(IDC_LOG);
		editLog->GetWindowText(strlog);
		strTemp.Format("%s", tmp);
		strlog += strTemp;
		editLog->SetWindowText(strlog);
	}

	m_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	m_hWaitUserRequestEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	// 创建同步线程
	// 然后把同步事件作为参数传递给这个线程


	// 将事件句柄传递给内核驱动
	//内核将把用户句柄转换为内核对象指针
	DeviceIoControl(m_hDevice, IOCTL_SETEVENT, &m_hEvent, sizeof(HANDLE), 
		NULL, 0, &m_returnBytes, NULL);
	AfxMessageBox("IOCTL_SETEVENT send.");

	DeviceIoControl(m_hDevice, IOCTL_SETWAITEVENT, &m_hWaitUserRequestEvent, sizeof(HANDLE), 
		NULL, 0, &m_returnBytes, NULL);
	AfxMessageBox("IOCTL_SETWATIEVENT send.");

	AfxBeginThread(EventThread, this);

BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return ;

}


void CRegDef12084124Dlg::OnBnClickedStop()
{
	BOOL bRet = false;
	SC_HANDLE hManager = NULL;
	SC_HANDLE hService = NULL;
	SERVICE_STATUS SvrSta;

	//打开SCM管理器
	hManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if( hManager == NULL )
	{
		//打开服务管理器失败
		MessageBox( "OpenSCM error." );
		bRet = false;
		CloseServiceHandle( hManager );
		return ;
	}
	else
	{
		MessageBox( "OpenSCM success." );
	}
	//打开服务
	hService = OpenService( hManager, DriverName, SERVICE_ALL_ACCESS );
	if( hService == NULL )
	{
		//打开服务失败
		MessageBox( "OpenService Error." );
		bRet = false;
		CloseServiceHandle( hManager );
		CloseServiceHandle( hService );
		return ;
	}
	else
	{
		MessageBox( "OpenService Success." );
	}
	//停止驱动
	if( !ControlService( hService,SERVICE_CONTROL_STOP, &SvrSta) )
	{
		MessageBox( "ControlService Error." );
	}
	else
	{
		MessageBox( "ControlService Success." );
	}
	//卸载服务
	if( !DeleteService( hService ) )
	{
		MessageBox( "DeleteService error." );
	}
	else
	{
		MessageBox( "DeleteService Success." );
	}
	bRet = true;
	CloseServiceHandle( hManager );
	CloseServiceHandle( hService );
	CloseHandle(m_hDevice);
//////////////////////////////////////////////////////////////////////////
	//打开SCM管理器
	hManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if( hManager == NULL )
	{
		//打开服务管理器失败
		MessageBox( "OpenSCM error." );
		bRet = false;
		CloseServiceHandle( hManager );
		return ;
	}
	else
	{
		MessageBox( "OpenSCM success." );
	}
	//打开服务
	hService = OpenService( hManager, DriverName, SERVICE_ALL_ACCESS );
	if( hService == NULL )
	{
		//打开服务失败
		MessageBox( "OpenService Error." );
		bRet = false;
		CloseServiceHandle( hManager );
		CloseServiceHandle( hService );
		return ;
	}
	else
	{
		MessageBox( "OpenService Success." );
	}
	//停止驱动
	if( !ControlService( hService,SERVICE_CONTROL_STOP, &SvrSta) )
	{
		MessageBox( "ControlService Error." );
	}
	else
	{
		MessageBox( "ControlService Success." );
	}
	//卸载服务
	if( !DeleteService( hService ) )
	{
		MessageBox( "DeleteService error." );
	}
	else
	{
		MessageBox( "DeleteService Success." );
	}
	bRet = true;
	CloseServiceHandle( hManager );
	CloseServiceHandle( hService );
	CloseHandle(m_hDevice);
	CloseHandle(m_hWaitUserRequestEvent);

	return ;
}


// 关闭按钮
void CRegDef12084124Dlg::OnBnClickedButton1()
{
	int res = MessageBox("Really want to exit?", "Exit", MB_YESNO);
	if (res == IDYES)
	{
		ExitProcess(1);
		CloseHandle(m_hDevice);
		CloseHandle(m_hWaitUserRequestEvent);
	}
	else return;
}

void CRegDef12084124Dlg::OnClose()
{
	int res = MessageBox("Really want to exit?", "Exit", MB_YESNO);
	if (res == IDYES)
	{
		ExitProcess(1);
		CloseHandle(m_hDevice);
		CloseHandle(m_hWaitUserRequestEvent);
	}
	else return;
}

// 导出日志按钮
void CRegDef12084124Dlg::OnBnClickedSavelog()
{
	CEdit *editLog = (CEdit * )GetDlgItem(IDC_LOG);
	CString strLog;
	editLog->GetWindowText(strLog);

	char *p;
	p = (LPSTR)(LPCTSTR)strLog;
	char *szLog = (char *)malloc(sizeof(char) * strLog.GetLength() + 4);
	memcpy(szLog, p, strLog.GetLength());

	FILE *fileLog;
	fileLog = fopen("log.txt", "w+");
	fprintf(fileLog, "%s", szLog);

	CTime t = CTime::GetCurrentTime();
	char tmp[512];
	ZeroMemory(tmp, 512);
	sprintf(tmp, "[%d-%d-%d %d:%d:%d]Writing log file to ./log.txt ...success.\r\n", t.GetYear(),
		t.GetMonth(), t.GetDay(), t.GetHour(), t.GetMinute(), t.GetSecond());
	CString strTemp;
	strTemp.Format("%s", tmp);
	strLog += strTemp;

	editLog->SetWindowText(strLog);

	free(szLog);
	fclose(fileLog);
	return ;
}



// 新线程 用于加载驱动
UINT CRegDef12084124Dlg::ThreadProc(LPVOID pParam)
{
	CRegDef12084124Dlg *pThis = (CRegDef12084124Dlg *)pParam;

	char szCurrentPath[256];
	GetCurrentDirectory(256, szCurrentPath);

	char szDriverImagePath[256];
	GetFullPathName(szCurrentPath, 256, szDriverImagePath, NULL);

	strcat(szDriverImagePath, "\\SSDT_Hook_DriverReg.sys");

	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;

	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		// 打开失败
		AfxMessageBox("OpenSCManager failure");
		return -1;
	}
	else
	{
		AfxMessageBox("OpenSCM success.");
	}

	//MessageBox(szDriverImagePath);

	// 创建驱动所对应的服务
	hServiceDDK = CreateService( hServiceMgr, 
		DriverName,
		DriverName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		szDriverImagePath,
		NULL,NULL,NULL,NULL,NULL);
	AfxMessageBox(szDriverImagePath);
	DWORD dwRtn;
	if (hServiceDDK == NULL)
	{
		dwRtn = GetLastError();
		if ( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
		{
			// 由于其他原因创建服务失败
			AfxMessageBox("Create Service Failed.");
			goto BeforeLeave;
		}
		else
		{
			// 服务创建失败，因为已经创立过
			AfxMessageBox("Create Service Failed. Service already exists.");
		}

		// 驱动已经创建过了，只需要打开即可
		hServiceDDK = OpenService(hServiceMgr, DriverName, SERVICE_ALL_ACCESS);

		if (hServiceDDK == NULL)
		{
			// 打开服务失败
			dwRtn = GetLastError();
			AfxMessageBox("OpenService failure.");
			goto BeforeLeave;
		}
		else
		{
			AfxMessageBox("OpenService success.");
		}

	}
	else
	{
		AfxMessageBox("CreateService success.");
	}

	//开启此项服务
	bRet = StartService( hServiceDDK, NULL, NULL);
	if (!bRet)
	{
		DWORD dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
		{
			char buffer[512];
			sprintf(buffer, "StartService failure. %u", dwRtn);
			AfxMessageBox(buffer);
			goto BeforeLeave;
		}
		else
		{
			if (dwRtn == ERROR_IO_PENDING)
			{
				// 设备被挂住
				AfxMessageBox( "StartService failure. ERROR_IO_PENDING");
				goto BeforeLeave;
			}
			else
			{
				AfxMessageBox("StartService failure. ERROR_SERVICE_ALREADY_RUNNING");
				goto BeforeLeave;
			}
		}
	}
//////////////////////////////////////////////////////////////////////////
	// 驱动加载完成，继续进行通信初始化工作
//////////////////////////////////////////////////////////////////////////
	// 打开驱动句柄
	pThis->m_hDevice = CreateFile("\\\\.\\RegDef", GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pThis->m_hDevice == INVALID_HANDLE_VALUE)
	{
		char buf[24];
		DWORD x = GetLastError();
		sprintf(buf, "[Error] open device failed.! - %u", x);
		AfxMessageBox(buf);
	}
	else AfxMessageBox("[Info] open device success.!");

BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}



	return 1;
}


UINT CRegDef12084124Dlg::EventThread(LPVOID pParam)
{
	CRegDef12084124Dlg *pThis = (CRegDef12084124Dlg *)pParam;
	DWORD dwReturned = 0;
	int i = 0; 
	char szBuf[512];
	char szName[128];
	char szKey[128];
	char szSubKey[128];
	CString strTemp;
	while (true)
	{
		WaitForSingleObject(pThis->m_hEvent, INFINITE);
		DeviceIoControl(pThis->m_hDevice, IOCTL_GETINFO, NULL, 0, &pThis->m_OutBuffer, 1024, &dwReturned, NULL);
		//AfxMessageBox(pThis->m_OutBuffer);
		strTemp.Empty();
		strTemp.Format("%s", pThis->m_OutBuffer);
		AfxMessageBox(strTemp);
		ZeroMemory(szBuf, 512);ZeroMemory(szName, 128);ZeroMemory(szKey, 128);ZeroMemory(szSubKey, 128);
//		sscanf(pThis->m_OutBuffer, "%[]", szName, szKey, szSubKey);

		int i = 0;
		int j = 0;
		while (pThis->m_OutBuffer[i] != '|')
		{
			szName[j] = pThis->m_OutBuffer[i];
			i++;j++;
		}
		i += 1;j = 0;
		while (pThis->m_OutBuffer[i] != '|')
		{
			szKey[j] = pThis->m_OutBuffer[i];
			i++;j++;
		}
		i += 1;j = 0;
		while (pThis->m_OutBuffer[i] != '|')
		{
			szSubKey[j] = pThis->m_OutBuffer[i];
			i++;j++;
		}

		sprintf(szBuf, "Process Name: %s\r\nRegistry key: %s\r\nSubkey: %s\r\nWould you want this process to change the registyr?", szName, szKey, szSubKey);
		int t = pThis->MessageBox(szBuf,"Warning!", MB_YESNO);
		if (t == IDYES)
		{
			// 1表示允许修改;
			pThis->UserRes = 1;
			DeviceIoControl(pThis->m_hDevice, IOCTL_PASSUSERRES, &pThis->UserRes, 1, NULL, 0, &dwReturned, NULL);
		}
		else
		{
			// 0表示不允许修改
			pThis->UserRes = 0;
			DeviceIoControl(pThis->m_hDevice, IOCTL_PASSUSERRES, &pThis->UserRes, 1, NULL, 0, &dwReturned, NULL);
		}
		
		SetEvent(pThis->m_hWaitUserRequestEvent);
		ResetEvent(pThis->m_hEvent);
	}

	return 0;
}