
// RegDef12084124Dlg.h : 头文件
//

#pragma once

#define DEVICE_NAME "\\Device\\SSDTHOOKRegDevice"	// Driver Name
#define Win32LinkName "\\\\.\\SSDTHookReg"



//////////////////////////////////////////////////////////////////////////
//  定义IOCTL控制码
//////////////////////////////////////////////////////////////////////////
// 设置事件
#define IOCTL_SETEVENT \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 向ring0 请求数据
#define IOCTL_GETINFO \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 设置等待用户判断的事件
#define IOCTL_SETWAITEVENT \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 传递用户的判断结果
#define IOCTL_PASSUSERRES \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x834, METHOD_BUFFERED, FILE_ANY_ACCESS)


// CRegDef12084124Dlg 对话框
class CRegDef12084124Dlg : public CDialogEx
{
// 构造
public:
	CRegDef12084124Dlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_REGDEF12084124_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedStart();
	afx_msg void OnBnClickedStop();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedSavelog();
	afx_msg void OnClose();

	static UINT __cdecl ThreadProc(LPVOID pParam);
	static UINT __cdecl EventThread(LPVOID pParam);

	BOOL m_bNotLeave;
	char m_OutBuffer[1024];

	HANDLE m_hDevice;
	HANDLE m_hEvent;
	DWORD m_returnBytes;
	HANDLE m_hWaitUserRequestEvent;
	
	// 1表示允许修改 0表示不允许修改
	char UserRes;
};

