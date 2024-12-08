
// ETWMonitorDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "ETWMonitor.h"
#include "ETWMonitorDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


#define FILE_DEVICE_UNKNOWN 0x00000022  // 或者其他适合你的设备类型的值
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#define IOCTL_CUSTOM_FUNC1 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CUSTOM_FUNC2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

HANDLE hDevice = NULL;

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


// CETWMonitorDlg 对话框



CETWMonitorDlg::CETWMonitorDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ETWMONITOR_DIALOG, pParent)
	, ProcessName(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CETWMonitorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT2, ProcessName);
}

BEGIN_MESSAGE_MAP(CETWMonitorDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(BUTTON_ADD_, &CETWMonitorDlg::OnBnClickedAdd)
	ON_BN_CLICKED(BUTTON_DELETE_, &CETWMonitorDlg::OnBnClickedDelete)
END_MESSAGE_MAP()


// CETWMonitorDlg 消息处理程序

BOOL CETWMonitorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
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
	hDevice = CreateFile(
		L"\\\\.\\MyDevice_Link",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		::MessageBox(0, TEXT("无法打开驱动设备！"), 0, 0);
		return 1;
	}



	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CETWMonitorDlg::OnSysCommand(UINT nID, LPARAM lParam)
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
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CETWMonitorDlg::OnPaint()
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
HCURSOR CETWMonitorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CETWMonitorDlg::OnBnClickedAdd()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	char outBuffer[1024];  // 根据需要分配足够的大小
	// 向驱动写数据
	DWORD bytesReturned;
	BOOL success = DeviceIoControl(
		hDevice,
		IOCTL_CUSTOM_FUNC1,
		ProcessName.GetBuffer(),
		ProcessName.GetLength()*2 + 1,
		outBuffer,
		sizeof(outBuffer),
		&bytesReturned,
		NULL
	);
	//CString str;
	//str.Format(_T("%d"), success);  // %d 是格式说明符，用于打印十进制整数

	//AfxMessageBox(str.GetBuffer());
	//::MessageBoxA(0, outBuffer, 0, 0);
	if (success)  //注意，SUCCESS是0
	{
		AfxMessageBox(L"添加监控成功！\n");
	}
	else
	{
		AfxMessageBox(L"添加监控失败！已经添加过了\n");
	}

}


void CETWMonitorDlg::OnBnClickedDelete()
{
	// TODO: 在此添加控件通知处理程序代码
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	char outBuffer[1024];  // 根据需要分配足够的大小
	// 向驱动写数据
	DWORD bytesReturned;
	BOOL success = DeviceIoControl(
		hDevice,
		IOCTL_CUSTOM_FUNC2,
		ProcessName.GetBuffer(),
		ProcessName.GetLength()*2 + 1,
		outBuffer,
		sizeof(outBuffer),
		&bytesReturned,
		NULL
	);


	//CString str;
	//str.Format(_T("%d"), success);  // %d 是格式说明符，用于打印十进制整数

	//::MessageBoxA(0,outBuffer,0,0);
	if (success)
	{
		AfxMessageBox(L"删除监控成功！\n");
	}
	else
	{
		AfxMessageBox(L"删除监控失败！没有这个进程名\n");
	}
}
