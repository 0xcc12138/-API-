//#define INITGUID  // Include this #define to use SystemTraceControlGuid in Evntrace.h.
//
//#include <windows.h>
//#include <stdio.h>
//#include <conio.h>
//#include <strsafe.h>
//#include <wmistr.h>
//#include <evntrace.h>
//#include <evntcons.h>
//#include <iostream>
//using namespace std;
//#define LOGFILE_PATH L"C:\\Users\\nzt\\Desktop\\etw.etl"
//
//
//GUID ProviderGuid = {
//  0xa4b4ba50, 0xa667, 0x43f5, { 0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5 }
//};
//
//
//VOID WINAPI ProcessTraceCallback(PEVENT_RECORD pEventRecord)
//{
//    //// This callback will be invoked for each event that is captured.
//    //if (pEventRecord->EventHeader.EventDescriptor.Id == 10) // Event ID for process start
//    //{
//    //    // 直接从 EventHeader 中提取进程 ID
//    //    ULONG processId = pEventRecord->EventHeader.ProcessId;
//    //    wprintf(L"Process started with PID: %lu\n", processId);
//    //}
//
//    cout << pEventRecord->EventHeader.ProcessId << endl;
//
//    return;
//}
//
//
//#define SESSION_NAME_FILE  L"myETWsession"  // 确保会话名称是有效的
//void wmain(void)
//{
//    ULONG status = ERROR_SUCCESS;
//    TRACEHANDLE SessionHandle = 0;
//    EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
//    ULONG BufferSize = 0;
//    // Set up the callback for processing the trace events
//    EVENT_TRACE_LOGFILE logFile = { 0 };
//    TRACEHANDLE traceHandle;
//    TRACEHANDLE m_hTraceHandle_econt[2];
//    EVENT_TRACE_LOGFILEW m_Logfile = { 0 };
//    ULONG rc;
//    // Allocate memory for the session properties. The memory must
//    // be large enough to include the log file name and session name,
//    // which get appended to the end of the session properties structure.
//
//    BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGFILE_PATH) + sizeof(KERNEL_LOGGER_NAME);
//    pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
//    if (NULL == pSessionProperties)
//    {
//        wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
//        goto cleanup;
//    }
//
//    // Set the session properties. You only append the log file name
//    // to the properties structure; the StartTrace function appends
//    // the session name for you.
//
//    ZeroMemory(pSessionProperties, BufferSize);
//    pSessionProperties->Wnode.BufferSize = BufferSize;
//    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
//    pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
//    //pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
//    pSessionProperties->LogFileMode = PROCESS_TRACE_MODE_REAL_TIME;//****这里原来是 EVENT_TRACE_FILE_MODE_CIRCULAR;
//    pSessionProperties->MaximumFileSize = 5;  // 5 MB
//    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
//    pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
//    StringCbCopy((LPWSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), sizeof(LOGFILE_PATH), LOGFILE_PATH);
//
//    //// Add Kernel Process Provider GUID to the session's enabled events
//    //status = EnableTrace(TRUE, 0, 0, &KernelProcessProviderGuid);
//
//    if (status != ERROR_SUCCESS)
//    {
//        wprintf(L"EnableTrace failed with %lu\n", status);
//        goto cleanup;
//    }
//
//    // Create the trace session.
//
//    status = StartTrace(&SessionHandle, SESSION_NAME_FILE, pSessionProperties);
//
//    if (ERROR_SUCCESS != status)
//    {
//        if (ERROR_ALREADY_EXISTS == status)
//        {
//            wprintf(L"The NT Kernel Logger session is already in use.\n");
//        }
//        else
//        {
//            wprintf(L"EnableTrace() failed with %lu\n", status);
//        }
//
//        goto cleanup;
//    }
//
//    // Enable the trace for Kernel Process events
//    status = EnableTrace(TRUE, 0, 0, &ProviderGuid, SessionHandle);
//
//    if (ERROR_SUCCESS != status)
//    {
//        wprintf(L"ProcessTrace() failed with %lu\n", status);
//        goto cleanup;
//    }
//
//
//
//
//
//
//    
//    ZeroMemory(&m_Logfile, sizeof(m_Logfile));
//
//    // 设置会话名称
//    m_Logfile.LoggerName = (LPWSTR)SESSION_NAME_FILE;
//
//    m_Logfile.LogFileName = (LPWSTR)LOGFILE_PATH;
//    // 设置其他必要字段
//    m_Logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME; 
//
//    // 设置回调函数
//    m_Logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)ProcessTraceCallback;
//    //m_Logfile.Context = (PVOID)0x114514;  // 随便输入一个数，这里是模拟上下文数据
//
//    // 打开 Trace 会话
//    SetLastError(0);
//    traceHandle = OpenTraceW(&m_Logfile);  // 使用 OpenTraceW（假设SESSION_NAME_FILE是Unicode字符串）
//
//    if (traceHandle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
//    {
//        wprintf(L"OpenTraceW failed with error %lu\n", GetLastError());
//        system("pause");
//        return;
//    }
//
//  
//
//    // 设置 TRACEHANDLE 数组（你可能会有多个 trace handle）
//    m_hTraceHandle_econt[0] = { traceHandle };
//
//    // 开始处理事件
//    rc = ProcessTrace(m_hTraceHandle_econt, 1, 0, 0);
//    if (rc != ERROR_SUCCESS)
//    {
//        wprintf(L"ProcessTrace failed with error %lu\n", rc);
//        return;
//    }
//    cout << "开始监视！" << endl;
//
//    
//    getchar();
//
//cleanup:
//
//    if (SessionHandle)
//    {
//        status = ControlTrace(SessionHandle, KERNEL_LOGGER_NAME, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
//
//        if (ERROR_SUCCESS != status)
//        {
//            wprintf(L"ControlTrace(stop) failed with %lu\n", status);
//        }
//    }
//
//    if (pSessionProperties)
//        free(pSessionProperties);
//
//    system("pause");
//}
