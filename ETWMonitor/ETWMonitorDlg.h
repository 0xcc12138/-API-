
// ETWMonitorDlg.h: 头文件
//

#pragma once


// CETWMonitorDlg 对话框
class CETWMonitorDlg : public CDialogEx
{
// 构造
public:
	CETWMonitorDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ETWMONITOR_DIALOG };
#endif

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
	// 获取需要监控的进程名
	CString ProcessName;
	afx_msg void OnBnClickedAdd();
	afx_msg void OnBnClickedDelete();
};
